package agent

import (
	"context"
	"errors"
	"fmt"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
)

// lbBacking is one (VIP, backend NIC) pairing this node hosts: a CompiledNIC.LB entry together with
// the backend NIC's own node-local underlay /128 (resolved from the local dataplane).
type lbBacking struct {
	VIP         string   // v4 or v6
	Vni         uint32   // the backend NIC's VPC VNI (for the E/W anycast route)
	NicUnderlay string   // the backend NIC's /128 (E/W route nexthop + LB_VIP owner_underlay)
	Ports       []LbPort // service tuples (proto as IP protocol number)
}

// desiredLB lists the CompiledNICs locally attached on this node and, for each CompiledNIC.LB entry,
// emits an lbBacking keyed on the backend NIC's node-local underlay /128 — resolved by joining the
// NIC's (VNI, overlayIP) to ulByKey (from the local dataplane's attached interfaces). A NIC is
// "local" iff its (VNI, overlayIP) appears in localSet; its underlay is the matching ulByKey entry.
// A NIC whose overlay IP isn't attached locally yet is skipped (nothing to announce until it is).
// Both maps are keyed by (VNI, overlayIP) so the function is safe under overlapping VPC subnets.
func (r *Reconciler) desiredLB(ctx context.Context, ulByKey map[ipKey]string, localSet map[ipKey]struct{}) ([]lbBacking, error) {
	cnics, err := r.listCNICs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list compilednics: %w", err)
	}

	var out []lbBacking
	for i := range cnics.Items {
		c := &cnics.Items[i]
		if !localNIC(c, localSet) || len(c.Spec.LB) == 0 {
			continue
		}
		ul := ""
		for _, ip := range c.Spec.OverlayIPs {
			if u, ok := ulByKey[ipKey{uint32(c.Spec.VNI), ip}]; ok {
				ul = u
				break
			}
		}
		if ul == "" {
			continue // backend NIC not attached locally yet
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
	// anycast underlay; vni=0 (WAN). create_lb skips the UNDERLAY write for vni==0.
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
