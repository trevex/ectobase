package agent

import (
	"context"
	"errors"
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

// ReconcileLB is the EDGE-only LB VIP reconcile: it lists LoadBalancers and diffs AddLbVip/DelLbVip
// against appliedLbVips. Backends are added separately by the bus's applyPublic (LB_VIP records).
// Non-edge nodes are a no-op (they reach VIPs via the E/W anycast route, not maglev).
func (r *Reconciler) ReconcileLB(ctx context.Context) error {
	if r.dp == nil || r.edgeLoopback == "" {
		return nil
	}
	var lbs netv1.LoadBalancerList
	if err := r.client.List(ctx, &lbs); err != nil {
		return fmt.Errorf("list loadbalancers: %w", err)
	}
	desired := map[string][]LbPort{} // vip -> ports
	for i := range lbs.Items {
		lb := &lbs.Items[i]
		ports := make([]LbPort, 0, len(lb.Spec.Ports))
		for _, p := range lb.Spec.Ports {
			ports = append(ports, LbPort{Port: uint32(p.Port), Proto: protoNum(p.Proto)})
		}
		desired[lb.Spec.VIP] = ports
	}
	if r.appliedLbVips == nil {
		r.appliedLbVips = map[string][]LbPort{}
	}
	var errs []error
	// Delete VIPs no longer desired (or whose ports changed → delete then re-add below).
	for vip, prevPorts := range r.appliedLbVips {
		if want, ok := desired[vip]; ok && lbPortsEqual(want, prevPorts) {
			continue
		}
		if err := r.dp.DelLbVip(ctx, vip); err != nil {
			errs = append(errs, fmt.Errorf("DelLbVip %s: %w", vip, err))
			continue
		}
		delete(r.appliedLbVips, vip)
	}
	// Add VIPs newly desired (or just-deleted because ports changed). lbUnderlay = the edge's own
	// anycast underlay; vni=0 (WAN). create_lb skips the UNDERLAY write for vni==0 (see Task 2).
	for vip, ports := range desired {
		if cur, ok := r.appliedLbVips[vip]; ok && lbPortsEqual(cur, ports) {
			continue
		}
		if err := r.dp.AddLbVip(ctx, vip, 0, vip, r.underlay, ports); err != nil {
			errs = append(errs, fmt.Errorf("AddLbVip %s: %w", vip, err))
			continue
		}
		r.appliedLbVips[vip] = ports
	}
	return errors.Join(errs...)
}

func lbPortsEqual(a, b []LbPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
