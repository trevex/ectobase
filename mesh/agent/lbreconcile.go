package agent

import (
	"context"
	"fmt"
)

// lbBacking is one (LB address, backend NIC) pairing this node hosts: a CompiledNIC.LB entry
// together with this node's VTEP (resolved from the local dataplane).
type lbBacking struct {
	IP          string   // the load balancer's address, v4 or v6
	Vni         uint32   // the backend NIC's VPC VNI (for the E/W anycast route)
	NicUnderlay string   // this node's VTEP (E/W route nexthop + LB_IP owner_underlay)
	OverlayIP   string   // the backend NIC's overlay IP (for AddLbBackend's Geneve encap)
	Ports       []LbPort // service tuples (proto as IP protocol number)
}

// desiredLB lists the CompiledNICs locally attached on this node and, for each CompiledNIC.LB entry,
// emits an lbBacking carrying this node's VTEP — resolved by joining the NIC's (VNI, overlayIP) to
// ulByKey (from the local dataplane's attached interfaces). A NIC is "local" iff its
// (VNI, overlayIP) appears in localSet. The VTEP does not identify the backend on its own — two
// backends on this node share it — which is why OverlayIP is carried alongside.
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
		ul, overlayIP := "", ""
		for _, ip := range c.Spec.OverlayIPs {
			if u, ok := ulByKey[ipKey{uint32(c.Spec.VNI), ip}]; ok {
				ul = u
				overlayIP = ip
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
			out = append(out, lbBacking{IP: lb.IP, Vni: uint32(c.Spec.VNI), NicUnderlay: ul, OverlayIP: overlayIP, Ports: ports})
		}
	}
	return out, nil
}

// The edge does NOT reconcile LoadBalancers from an API server. It has none — it is a router, not a
// Kubernetes node — and even a pool-resident edge could not: the broker syncs only the compiled.*
// kinds downstream, so a raw LoadBalancer never reaches a pool API server and listing them there
// always returned zero items. The edge instead learns each LB address from the LB_IP records its BACKENDS
// announce, which carry the service ports alongside the backend identity (see DesiredPublic) — so
// Bus.applyPublic does the AddLoadBalancer + AddLbBackend pair. The consequence is deliberate: an LB address with
// no backends is never programmed at the edge, which is correct (an edge that Maglev-hashes to an
// empty backend set can only blackhole) but does mean an LB address is not reserved until something backs it.
//
// Announced LB addresses are always the centrally-ALLOCATED ones: the compiler only writes a CompiledNIC.LB
// entry for a LoadBalancer whose status is Allocated with a non-empty allocatedIP (see
// controllers/compilednic.go), so an auto-allocated LB's empty spec.lbIP can never reach the edge.
