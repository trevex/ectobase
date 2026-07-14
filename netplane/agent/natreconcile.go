package agent

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

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
