package agent

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
)

// ReconcileFirewall installs the firewall rules of every CompiledNIC scheduled to this node onto
// the dataplane. Idempotent: rule ids are deterministic; rules that disappear since the last
// reconcile are deleted before the new set is applied.
func (r *Reconciler) ReconcileFirewall(ctx context.Context) error {
	if r.dp == nil {
		return nil
	}
	var list netv1.CompiledNICList
	if err := r.client.List(ctx, &list); err != nil {
		return fmt.Errorf("list compilednics: %w", err)
	}
	desired := map[string]map[string]FwRule{} // interfaceID -> ruleID -> rule
	for i := range list.Items {
		c := &list.Items[i]
		if c.Spec.NodeName != r.nodeID {
			continue
		}
		iface := c.Spec.NICRef.Name
		rules := desired[iface]
		if rules == nil {
			rules = map[string]FwRule{}
			desired[iface] = rules
		}
		for idx, cr := range c.Spec.Firewall.Ingress {
			rules[fmt.Sprintf("fw-in-%d", idx)] = compiledToFw(cr, false)
		}
		for idx, cr := range c.Spec.Firewall.Egress {
			rules[fmt.Sprintf("fw-eg-%d", idx)] = compiledToFw(cr, true)
		}
	}
	// Delete rules that vanished since last reconcile.
	for iface, prev := range r.appliedFw {
		for ruleID := range prev {
			if _, ok := desired[iface][ruleID]; !ok {
				if err := r.dp.DelFwRule(ctx, iface, ruleID); err != nil {
					return fmt.Errorf("DelFwRule %s/%s: %w", iface, ruleID, err)
				}
			}
		}
	}
	// Apply desired.
	for iface, rules := range desired {
		for ruleID, fr := range rules {
			if err := r.dp.AddFwRule(ctx, iface, ruleID, fr); err != nil {
				return fmt.Errorf("AddFwRule %s/%s: %w", iface, ruleID, err)
			}
		}
	}
	r.appliedFw = desired
	return nil
}

func compiledToFw(cr netv1.CompiledFwRule, egress bool) FwRule {
	return FwRule{
		SrcCIDR: "0.0.0.0/0", DstCIDR: cr.CIDR, Proto: protoNum(cr.Proto),
		DstPortMin: uint32(cr.Port), DstPortMax: uint32(cr.Port),
		Allow: cr.Action == "Allow", Egress: egress,
	}
}

func protoNum(s string) uint32 {
	switch s {
	case "TCP", "tcp":
		return 6
	case "UDP", "udp":
		return 17
	case "ICMP", "icmp":
		return 1
	default:
		return 0
	}
}
