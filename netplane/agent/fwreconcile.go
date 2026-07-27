package agent

import (
	"context"
	"errors"
	"fmt"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

// ReconcileFirewall programs the firewall rules of every CompiledNIC scheduled to this node onto
// the dataplane. It is DECLARATIVE and restart-safe: for each locally-attached interface it computes
// the complete desired rule set (ingress rules first, then egress, in the CompiledNIC's Ingress/
// Egress slice order) and calls ReplaceInterfaceFirewall, which sets the interface's whole rule set
// at once. There is no in-memory diff to lose on restart, so an in-place policy change (or an agent
// restart mid-swap) always converges — no stale rule can survive to shadow the intended one.
//
// This reconciler only programs interfaces that are currently attached locally AND whose CompiledNIC
// is scheduled here; it never issues a delete. Cleanup of an interface's rules is owned by the
// dataplane's DetachInterface (see remove_fw_rules). So a NIC that is de-scheduled from this node
// while its interface is still attached keeps its last-programmed rules until the detach that a
// de-schedule drives actually fires — a narrow teardown window, bounded by deny-by-default.
func (r *Reconciler) ReconcileFirewall(ctx context.Context) error {
	if r.dp == nil {
		return nil
	}
	// The dataplane is the source of truth for which interface a NIC's overlay IP is attached to.
	ifaceByIP, err := r.interfaceIDByOverlayIP(ctx)
	if err != nil {
		return err
	}
	var list netv1.CompiledNICList
	if err := r.client.List(ctx, &list); err != nil {
		return fmt.Errorf("list compilednics: %w", err)
	}
	// interfaceID -> ordered desired rules (ingress first, then egress; index = slot within family).
	desired := map[string][]FwRuleWithID{}
	for i := range list.Items {
		c := &list.Items[i]
		if c.Spec.NodeName != r.nodeID {
			continue
		}
		iface := ""
		for _, ip := range c.Spec.OverlayIPs {
			if id, ok := ifaceByIP[ip]; ok {
				iface = id
				break
			}
		}
		if iface == "" {
			continue // NIC not attached locally yet; nothing to program until it is
		}
		rules := desired[iface]
		for idx, cr := range c.Spec.Firewall.Ingress {
			rules = append(rules, FwRuleWithID{ID: fmt.Sprintf("fw-in-%d", idx), Rule: compiledToFw(cr, false)})
		}
		for idx, cr := range c.Spec.Firewall.Egress {
			rules = append(rules, FwRuleWithID{ID: fmt.Sprintf("fw-eg-%d", idx), Rule: compiledToFw(cr, true)})
		}
		desired[iface] = rules
	}
	var errs []error
	for iface, rules := range desired {
		if err := r.dp.ReplaceInterfaceFirewall(ctx, iface, rules); err != nil {
			errs = append(errs, fmt.Errorf("ReplaceInterfaceFirewall %s: %w", iface, err))
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
