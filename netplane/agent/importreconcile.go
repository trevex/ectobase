package agent

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

// desiredEgressVNIs returns the VNIs this node hosts that need internet egress: a VNI whose VPC has a
// NATGateway (and this node hosts a NIC in it), or a VNI of a local LB-backend NIC. These VNIs import
// the public VNI's default route (0.0.0.0/0, etc.) so their egress reaches the WAN edge.
func (r *Reconciler) desiredEgressVNIs(ctx context.Context) ([]uint32, error) {
	set := map[uint32]struct{}{}

	// (a) NATGateway VNIs, intersected with VNIs this node actually hosts.
	var gws netv1.NATGatewayList
	if err := r.client.List(ctx, &gws); err != nil {
		return nil, fmt.Errorf("list natgateways: %w", err)
	}
	natVNIs := map[uint32]struct{}{}
	for i := range gws.Items {
		vni, err := vpcVNIFor(ctx, r.client, gws.Items[i].Namespace, gws.Items[i].Spec.VPCRef.Name)
		if err != nil {
			continue // VPC not resolvable yet; skip
		}
		if vni != 0 {
			natVNIs[vni] = struct{}{}
		}
	}
	if len(natVNIs) > 0 {
		var nics netv1.NetworkInterfaceList
		if err := r.client.List(ctx, &nics); err != nil {
			return nil, fmt.Errorf("list networkinterfaces: %w", err)
		}
		for i := range nics.Items {
			n := &nics.Items[i]
			if n.Spec.NodeName == nil || *n.Spec.NodeName != r.nodeID {
				continue
			}
			vni := uint32(n.Status.VNI)
			if _, ok := natVNIs[vni]; ok && vni != 0 {
				set[vni] = struct{}{}
			}
		}
	}

	// (b) LB-backend VNIs on this node (CompiledNIC.LB non-empty).
	var cnics netv1.CompiledNICList
	if err := r.client.List(ctx, &cnics); err != nil {
		return nil, fmt.Errorf("list compilednics: %w", err)
	}
	for i := range cnics.Items {
		c := &cnics.Items[i]
		if c.Spec.NodeName == r.nodeID && len(c.Spec.LB) > 0 && c.Spec.VNI != 0 {
			set[uint32(c.Spec.VNI)] = struct{}{}
		}
	}

	out := make([]uint32, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	return out, nil
}
