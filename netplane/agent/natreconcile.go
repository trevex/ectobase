package agent

import (
	"context"
	"fmt"
	"log"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// nat64WellKnownPrefix is the RFC 6052 well-known NAT64 prefix.
const nat64WellKnownPrefix = "64:ff9b::/96"

// NatSource is a LOCAL egress SNAT the agent programs via AddNatSource: overlay
// SourceIP (in Vni) is SNATed onto NatIP:[PortMin,PortMax).
type NatSource struct {
	Vni      uint32
	SourceIP string
	NatIP    string
	PortMin  uint32
	PortMax  uint32
}

// NatBlock is a NAT block this node ANNOUNCES on the routebus (so every other
// node can return-route to us). It carries this node's underlay as the owner.
type NatBlock struct {
	Vni           uint32
	SourceIP      string
	NatIP         string
	PortMin       uint32
	PortMax       uint32
	OwnerUnderlay string
}

// localSource is a NetworkInterface IP scheduled to this node, with its VNI.
type localSource struct {
	vni uint32
}

// ExternalRoute is an external (egress-SNAT) route this node ANNOUNCES on the
// routebus. The WAN edge originates a default (0.0.0.0/0, and 64:ff9b::/96 for
// NAT64) into each VPC's VNI so source hypervisors SNAT + encap egress toward
// the edge's underlay.
type ExternalRoute struct {
	Vni      uint32
	Prefix   string // CIDR, e.g. "0.0.0.0/0" or nat64WellKnownPrefix
	Nexthop  string // the edge underlay /128
	External bool   // always true for these
}

// DesiredExternalRoutes returns the external default routes THIS node should
// announce. A node only originates them when it IS a WAN edge, i.e. it was started
// with --edge-loopback (edgeLoopback != ""); non-edge nodes originate nothing. The
// edge role is NO LONGER tied to any per-NATGateway field: the edge fleet self-
// advertises via its own underlay. For EVERY NATGateway it resolves the VPC's VNI
// from Spec.VPCRef and returns an external 0.0.0.0/0 route plus a NAT64
// nat64WellKnownPrefix route, both nexthop'd at this edge's own underlay (anycast).
// VNIs are deduped so multiple gateways sharing a VNI originate one pair of routes.
func DesiredExternalRoutes(ctx context.Context, c client.Client, underlay, edgeLoopback string) ([]ExternalRoute, error) {
	if edgeLoopback == "" {
		return nil, nil // not a WAN edge: originate nothing
	}

	var gws netv1.NATGatewayList
	if err := c.List(ctx, &gws); err != nil {
		return nil, fmt.Errorf("list natgateways: %w", err)
	}

	var routes []ExternalRoute
	seen := map[uint32]struct{}{}
	for gi := range gws.Items {
		gw := &gws.Items[gi]
		vni, err := vpcVNIFor(ctx, c, gw.Namespace, gw.Spec.VPCRef.Name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				log.Printf("VPC %s/%s not found for gateway %s/%s, skipping", gw.Namespace, gw.Spec.VPCRef.Name, gw.Namespace, gw.Name)
				continue
			}
			return nil, err
		}
		if vni == 0 {
			continue // VPC not yet allocated a VNI; skip until it is
		}
		if _, ok := seen[vni]; ok {
			continue // another gateway already originated this VNI's default
		}
		seen[vni] = struct{}{}
		// The v6 NAT64 prefix rides the same generic (prefix, external) announce path:
		// the reflector RIB keys prefixes as opaque strings and AddRoute accepts v6 CIDRs.
		routes = append(routes,
			ExternalRoute{Vni: vni, Prefix: "0.0.0.0/0", Nexthop: underlay, External: true},
			ExternalRoute{Vni: vni, Prefix: nat64WellKnownPrefix, Nexthop: underlay, External: true},
		)
	}

	// LoadBalancer VNIs also need an external default so DSR replies can leave the fabric: the
	// backend answers FROM the public VIP (a public IP), so it needs no NATGateway/SNAT — the reply
	// misses the SNAT lookup and egresses un-SNAT'd via the edge. Originate 0.0.0.0/0 for each LB's
	// VPC VNI (deduped with the NATGateway VNIs above). No NAT64 prefix — DSR is same-family.
	var lbs netv1.LoadBalancerList
	if err := c.List(ctx, &lbs); err != nil {
		return nil, fmt.Errorf("list loadbalancers: %w", err)
	}
	for li := range lbs.Items {
		lb := &lbs.Items[li]
		vni, err := vpcVNIFor(ctx, c, lb.Namespace, lb.Spec.VPCRef.Name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				log.Printf("VPC %s/%s not found for loadbalancer %s/%s, skipping", lb.Namespace, lb.Spec.VPCRef.Name, lb.Namespace, lb.Name)
				continue
			}
			return nil, err
		}
		if vni == 0 {
			continue
		}
		if _, ok := seen[vni]; ok {
			continue
		}
		seen[vni] = struct{}{}
		routes = append(routes,
			ExternalRoute{Vni: vni, Prefix: "0.0.0.0/0", Nexthop: underlay, External: true},
		)
	}
	return routes, nil
}

// vpcVNIFor resolves a VPC's effective VNI from its status.vni.
func vpcVNIFor(ctx context.Context, c client.Client, namespace, name string) (uint32, error) {
	var vpc netv1.VPC
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &vpc); err != nil {
		return 0, fmt.Errorf("get vpc %s/%s: %w", namespace, name, err)
	}
	return uint32(vpc.Status.VNI), nil
}

// DesiredNat reads every NATGateway's Status.Allocations and, for allocations
// whose Source is an overlay IP of a NetworkInterface scheduled to THIS node,
// returns the local SNAT sources to program (via AddNatSource) and the matching
// NAT blocks to announce (owner = this node's underlay). Allocations for remote
// sources are ignored here: their owners announce them and this node learns them
// off the bus as neighbor-nat return routes.
func DesiredNat(ctx context.Context, c client.Client, nodeID, underlay string) ([]NatSource, []NatBlock, error) {
	local, err := localSources(ctx, c, nodeID)
	if err != nil {
		return nil, nil, err
	}

	var gws netv1.NATGatewayList
	if err := c.List(ctx, &gws); err != nil {
		return nil, nil, fmt.Errorf("list natgateways: %w", err)
	}

	var sources []NatSource
	var blocks []NatBlock
	for gi := range gws.Items {
		for _, a := range gws.Items[gi].Status.Allocations {
			ls, ok := local[a.Source]
			if !ok {
				continue // not a source scheduled to this node
			}
			sources = append(sources, NatSource{
				Vni: ls.vni, SourceIP: a.Source, NatIP: a.PublicIP,
				PortMin: uint32(a.PortMin), PortMax: uint32(a.PortMax),
			})
			blocks = append(blocks, NatBlock{
				Vni: ls.vni, SourceIP: a.Source, NatIP: a.PublicIP,
				PortMin: uint32(a.PortMin), PortMax: uint32(a.PortMax), OwnerUnderlay: underlay,
			})
		}
	}
	return sources, blocks, nil
}

// localSources indexes overlay IP -> {vni} for every NetworkInterface scheduled
// to nodeID. The VNI resolves from status.vni, else the referenced VPC's status.vni.
func localSources(ctx context.Context, c client.Client, nodeID string) (map[string]localSource, error) {
	var nics netv1.NetworkInterfaceList
	if err := c.List(ctx, &nics); err != nil {
		return nil, fmt.Errorf("list networkinterfaces: %w", err)
	}
	out := map[string]localSource{}
	vpcVNI := map[string]uint32{}
	for i := range nics.Items {
		nic := &nics.Items[i]
		if nic.Spec.NodeName == nil || *nic.Spec.NodeName != nodeID {
			continue
		}
		vni := uint32(nic.Status.VNI)
		if vni == 0 {
			key := nic.Namespace + "/" + nic.Spec.VPCRef.Name
			v, ok := vpcVNI[key]
			if !ok {
				var vpc netv1.VPC
				if err := c.Get(ctx, client.ObjectKey{Namespace: nic.Namespace, Name: nic.Spec.VPCRef.Name}, &vpc); err != nil {
					return nil, fmt.Errorf("get vpc %s: %w", key, err)
				}
				v = uint32(vpc.Status.VNI)
				vpcVNI[key] = v
			}
			vni = v
		}
		if vni == 0 {
			continue // VPC not yet allocated a VNI; skip until it is
		}
		for _, ip := range nic.Spec.IPs {
			out[ip] = localSource{vni: vni}
		}
	}
	return out, nil
}
