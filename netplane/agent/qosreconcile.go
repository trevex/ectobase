package agent

import (
	"context"
	"errors"
	"fmt"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
)

// compiledQoSCaps holds the three scalar Mbit/s caps the dataplane takes.
// 0 in any field means unlimited.
type compiledQoSCaps struct {
	EgressMbps  uint32
	PublicMbps  uint32
	IngressMbps uint32
}

// qosCapsFromCompiled extracts the three caps from a *CompiledQoS (nil → all zeros/unlimited).
func qosCapsFromCompiled(q *compiledv1.CompiledQoS) compiledQoSCaps {
	if q == nil {
		return compiledQoSCaps{}
	}
	return compiledQoSCaps{
		EgressMbps:  q.EgressMbps,
		PublicMbps:  q.PublicMbps,
		IngressMbps: q.IngressMbps,
	}
}

// ReconcileQoS programs the QoS lanes (ConfigureQoS) for every CompiledNIC that is locally
// attached (its (VNI, overlayIP) appears in the dataplane's ListInterfaces) and whose spec.qos is
// set. Diffs against r.appliedQoS: unchanged NICs are skipped, cleared/removed NICs are set back
// to unlimited (0/0/0), new/changed caps are pushed.
//
// The interface_id is resolved from the local dataplane (interfaceIDByKey), consistent with
// fwreconcile. Locality is determined by (VNI, overlayIP) — not nodeName — so QoS follows the
// interface wherever the CNI attaches it. The QoS caps come directly from CompiledNIC.spec.qos,
// which the compiler folds from NetworkInterface.spec.qos, so the agent never reads raw
// NetworkInterfaces or VPCs.
func (r *Reconciler) ReconcileQoS(ctx context.Context) error {
	if r.dp == nil {
		return nil
	}
	// ifaceByKey: (VNI, overlayIP) -> real interface_id the CNI attached with.
	// localSet: set of all (VNI, overlayIP) pairs attached on this node.
	ifaceByKey, localSet, err := r.interfaceIDByKey(ctx)
	if err != nil {
		return fmt.Errorf("list local interfaces: %w", err)
	}
	var cnics compiledv1.CompiledNICList
	if err := r.client.List(ctx, &cnics); err != nil {
		return fmt.Errorf("list compilednics: %w", err)
	}
	// desired: interfaceID -> caps to program (only locally-attached NICs with QoS set).
	desired := map[string]compiledQoSCaps{}
	for i := range cnics.Items {
		c := &cnics.Items[i]
		if c.Spec.QoS == nil {
			continue
		}
		if !localNIC(c, localSet) {
			continue
		}
		// Resolve the dataplane interface_id from the (VNI, overlayIP) key — same as fwreconcile.
		iface := ""
		for _, ip := range c.Spec.OverlayIPs {
			if id, ok := ifaceByKey[ipKey{uint32(c.Spec.VNI), ip}]; ok {
				iface = id
				break
			}
		}
		if iface == "" {
			continue // not attached locally yet
		}
		desired[iface] = qosCapsFromCompiled(c.Spec.QoS)
	}
	if r.appliedQoS == nil {
		r.appliedQoS = map[string]compiledQoSCaps{}
	}
	var errs []error
	// Clear QoS for interfaces that were previously programmed but are no longer desired.
	for iface := range r.appliedQoS {
		if _, ok := desired[iface]; ok {
			continue
		}
		if err := r.dp.ConfigureQoS(ctx, iface, 0, 0, 0); err != nil {
			errs = append(errs, fmt.Errorf("ConfigureQoS clear %s: %w", iface, err))
			continue
		}
		delete(r.appliedQoS, iface)
	}
	// Push new or changed caps.
	for iface, caps := range desired {
		if cur, ok := r.appliedQoS[iface]; ok && cur == caps {
			continue // identical: skip (struct comparison on three uint32s is exact)
		}
		if err := r.dp.ConfigureQoS(ctx, iface, caps.EgressMbps, caps.PublicMbps, caps.IngressMbps); err != nil {
			errs = append(errs, fmt.Errorf("ConfigureQoS %s: %w", iface, err))
			continue
		}
		r.appliedQoS[iface] = caps
	}
	return errors.Join(errs...)
}
