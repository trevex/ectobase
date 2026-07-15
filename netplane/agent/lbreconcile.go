package agent

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
)

// lbBacking is one (VIP, backend NIC) pairing this node hosts: the join of a CompiledNIC.LB entry
// with the NIC's own node-local underlay /128 (from NetworkInterface.Status.UnderlayRoute).
type lbBacking struct {
	VIP         string   // v4 or v6
	Vni         uint32   // the backend NIC's VPC VNI (for the E/W anycast route)
	NicUnderlay string   // the backend NIC's /128 (E/W route nexthop + LB_VIP owner_underlay)
	Ports       []LbPort // service tuples (proto as IP protocol number)
}

// desiredLB lists the CompiledNICs scheduled to this node and joins each CompiledNIC.LB entry with
// its NIC's node-local underlay /128 (from NetworkInterface.Status). A NIC without an allocated
// underlay yet is skipped (nothing to announce until it is attached).
func (r *Reconciler) desiredLB(ctx context.Context) ([]lbBacking, error) {
	var cnics netv1.CompiledNICList
	if err := r.client.List(ctx, &cnics); err != nil {
		return nil, fmt.Errorf("list compilednics: %w", err)
	}
	var nics netv1.NetworkInterfaceList
	if err := r.client.List(ctx, &nics); err != nil {
		return nil, fmt.Errorf("list networkinterfaces: %w", err)
	}
	underlayByNIC := map[string]string{} // namespace/name -> underlay /128
	for i := range nics.Items {
		n := &nics.Items[i]
		underlayByNIC[n.Namespace+"/"+n.Name] = n.Status.UnderlayRoute
	}

	var out []lbBacking
	for i := range cnics.Items {
		c := &cnics.Items[i]
		if c.Spec.NodeName != r.nodeID || len(c.Spec.LB) == 0 {
			continue
		}
		ul := underlayByNIC[c.Namespace+"/"+c.Spec.NICRef.Name]
		if ul == "" {
			continue // NIC not attached yet
		}
		for _, lb := range c.Spec.LB {
			ports := make([]LbPort, 0, len(lb.Ports))
			for _, p := range lb.Ports {
				ports = append(ports, LbPort{Port: uint32(p.Port), Proto: protoNum(p.Proto)})
			}
			out = append(out, lbBacking{VIP: lb.VIP, Vni: uint32(c.Spec.VNI), NicUnderlay: ul, Ports: ports})
		}
	}
	return out, nil
}
