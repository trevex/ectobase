package agent

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	"github.com/trevex/xdp-dp/netplane/routebus"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// nat64WellKnownPrefix is the RFC 6052 well-known NAT64 prefix.
const nat64WellKnownPrefix = "64:ff9b::/96"

// PublicVNI is the reserved, control-plane-only aggregation VNI (dpservice ALL_VNI=0). The WAN edge
// originates the external default routes into it; egress-needing tenant nodes subscribe to it and
// import the defaults into their own tenant VNIs. It is NOT a wire/dataplane VNI.
const PublicVNI uint32 = 0

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
// It aliases the shared routebus.NatBlock so the agent and reflector use one
// canonical representation.
type NatBlock = routebus.NatBlock

// localSource is a NetworkInterface IP scheduled to this node, with its VNI.
type localSource struct {
	vni uint32
	// underlay is the source NIC's own underlay /128 (status.underlayRoute). It is the NAT-block
	// owner (NOT the node underlay): the WAN edge re-encaps a nat_ip return to this /128, and the
	// owner's uplink_rx resolves it via UNDERLAY[owner] -> {vni, tap} to reverse-NAT + deliver to
	// the guest. The node underlay is NOT in UNDERLAY, so using it would leave the return
	// unresolved (XDP_PASS -> kernel drop). Empty until the NIC is attached.
	underlay string
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
// edge is tenant-agnostic: it originates the external defaults ONCE into the public
// VNI (PublicVNI), nexthop = this edge's own anycast underlay. Egress-needing tenant
// nodes subscribe to the public VNI and import the defaults into their own VNIs.
func DesiredExternalRoutes(ctx context.Context, c client.Client, underlay, edgeLoopback string) ([]ExternalRoute, error) {
	if edgeLoopback == "" {
		return nil, nil // not a WAN edge: originate nothing
	}
	// The edge is tenant-agnostic: originate the external defaults ONCE into the public VNI,
	// nexthop = this edge's own anycast underlay. Egress-needing tenant nodes import them.
	return []ExternalRoute{
		{Vni: PublicVNI, Prefix: "0.0.0.0/0", Nexthop: underlay, External: true},
		{Vni: PublicVNI, Prefix: nat64WellKnownPrefix, Nexthop: underlay, External: true},
		{Vni: PublicVNI, Prefix: "::/0", Nexthop: underlay, External: true},
	}, nil
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
			// The NAT-block owner is the SOURCE NIC's own underlay /128 (uniquely resolves
			// {vni, tap} in the owner's UNDERLAY for reverse-NAT + delivery), NOT the node
			// underlay (which is not registered in UNDERLAY). Fall back to the node underlay
			// only if the NIC hasn't been attached yet (no status.underlayRoute).
			owner := ls.underlay
			if owner == "" {
				owner = underlay
			}
			blocks = append(blocks, NatBlock{
				Vni: ls.vni, SourceIP: a.Source, NatIP: a.PublicIP,
				PortMin: uint32(a.PortMin), PortMax: uint32(a.PortMax), OwnerUnderlay: owner,
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
			out[ip] = localSource{vni: vni, underlay: nic.Status.UnderlayRoute}
		}
	}
	return out, nil
}
