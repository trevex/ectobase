package agent

import (
	"context"
	"errors"
	"fmt"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
)

// ReconcileFirewall installs the firewall rules of every CompiledNIC scheduled to this node onto
// the dataplane. It DIFFS against the last-applied set (`r.appliedFw`): unchanged rules are left
// alone (the dataplane rejects duplicate rule ids, so re-adding would error every reconcile), rules
// that vanished or changed are deleted, and new/changed rules are (re-)added. `appliedFw` is updated
// per successful op and failures are collected (not fatal) so the level-triggered loop retries only
// the ops that didn't land.
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
	if r.appliedFw == nil {
		r.appliedFw = map[string]map[string]FwRule{}
	}
	var errs []error
	// Delete rules that are applied but no longer desired, OR whose contents changed (a changed rule
	// is deleted here and re-added in the next loop; the dataplane keys by rule id).
	for iface, prev := range r.appliedFw {
		for ruleID, prevRule := range prev {
			if want, ok := desired[iface][ruleID]; ok && want == prevRule {
				continue // unchanged: leave it installed
			}
			if err := r.dp.DelFwRule(ctx, iface, ruleID); err != nil {
				errs = append(errs, fmt.Errorf("DelFwRule %s/%s: %w", iface, ruleID, err))
				continue
			}
			delete(prev, ruleID)
		}
		if len(prev) == 0 {
			delete(r.appliedFw, iface)
		}
	}
	// Add rules that are desired but not currently applied (new, or just-deleted because changed).
	for iface, rules := range desired {
		for ruleID, fr := range rules {
			if cur, ok := r.appliedFw[iface][ruleID]; ok && cur == fr {
				continue // already installed, unchanged
			}
			if err := r.dp.AddFwRule(ctx, iface, ruleID, fr); err != nil {
				errs = append(errs, fmt.Errorf("AddFwRule %s/%s: %w", iface, ruleID, err))
				continue
			}
			if r.appliedFw[iface] == nil {
				r.appliedFw[iface] = map[string]FwRule{}
			}
			r.appliedFw[iface][ruleID] = fr
		}
	}
	return errors.Join(errs...)
}

// compiledToFw lowers a CompiledFwRule to the dataplane FwRule. k8s NetworkPolicy semantics: an
// INGRESS rule's peer CIDR is the SOURCE (who may reach us) and an EGRESS rule's is the DESTINATION;
// the port is always the destination port. (An allow-all `0.0.0.0/0` is symmetric either way.)
func compiledToFw(cr netv1.CompiledFwRule, egress bool) FwRule {
	fw := FwRule{
		Proto:      protoNum(cr.Proto),
		DstPortMin: uint32(cr.Port),
		DstPortMax: uint32(cr.Port),
		Allow:      cr.Action == "Allow",
		Egress:     egress,
	}
	if egress {
		fw.SrcCIDR, fw.DstCIDR = "0.0.0.0/0", cr.CIDR
	} else {
		fw.SrcCIDR, fw.DstCIDR = cr.CIDR, "0.0.0.0/0"
	}
	return fw
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
