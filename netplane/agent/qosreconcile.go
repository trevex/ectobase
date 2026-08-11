package agent

import (
	"context"
	"errors"
	"fmt"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
)

// lanes flattens an InterfaceQoS into the three scalar Mbit/s caps the dataplane takes.
func lanes(q netv1.InterfaceQoS) (egress, public, ingress uint32) {
	if q.Egress != nil {
		egress = q.Egress.RateMbps
		public = q.Egress.PublicMbps
	}
	if q.Ingress != nil {
		ingress = q.Ingress.RateMbps
	}
	return
}

// qosEqual compares two InterfaceQoS by VALUE on the lanes we program (InterfaceQoS has pointer
// fields, so `==` would compare pointers and defeat the idempotent-skip).
// BurstKB is intentionally excluded: the adapter does not forward it and the dataplane ignores it
// in v1; revisit when burst activation is implemented.
func qosEqual(a, b netv1.InterfaceQoS) bool {
	ae, ap, ai := lanes(a)
	be, bp, bi := lanes(b)
	return ae == be && ap == bp && ai == bi
}

// ReconcileQoS programs the QoS lanes (ConfigureQoS) for every NetworkInterface that is locally
// attached (its (VNI, overlayIP) appears in the dataplane's ListInterfaces) and whose spec.qos is
// set. Diffs against r.appliedQoS: unchanged NICs are skipped, cleared/removed NICs are set back
// to unlimited (0/0/0), new/changed caps are pushed. interface_id = NIC name.
// Locality is determined by (VNI, overlayIP) — not nodeName — so QoS follows the interface wherever
// the CNI attaches it, consistent with the rest of the agent's self-locating policy.
func (r *Reconciler) ReconcileQoS(ctx context.Context) error {
	if r.dp == nil {
		return nil
	}
	// Build the (VNI, IP) set of locally-attached interfaces to decide which NICs to program.
	_, localSet, err := r.underlayByKey(ctx)
	if err != nil {
		return fmt.Errorf("list local interfaces: %w", err)
	}
	var nics netv1.NetworkInterfaceList
	if err := r.client.List(ctx, &nics); err != nil {
		return fmt.Errorf("list networkinterfaces: %w", err)
	}
	desired := map[string]netv1.InterfaceQoS{}
	for i := range nics.Items {
		nic := &nics.Items[i]
		if nic.Spec.QoS == nil {
			continue
		}
		// A NIC is local iff any of its overlay IPs is attached here under its effective VNI.
		// nic.Status.VNI is the effective VNI (same value the compiler stamps into CompiledNIC.VNI).
		vni := uint32(nic.Status.VNI)
		local := false
		for _, ip := range nic.Spec.IPs {
			if _, ok := localSet[ipKey{vni, ip}]; ok {
				local = true
				break
			}
		}
		if !local {
			continue
		}
		desired[nic.Name] = *nic.Spec.QoS
	}
	if r.appliedQoS == nil {
		r.appliedQoS = map[string]netv1.InterfaceQoS{}
	}
	var errs []error
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
	for iface, q := range desired {
		if cur, ok := r.appliedQoS[iface]; ok && qosEqual(cur, q) {
			continue
		}
		eg, pub, ing := lanes(q)
		if err := r.dp.ConfigureQoS(ctx, iface, eg, pub, ing); err != nil {
			errs = append(errs, fmt.Errorf("ConfigureQoS %s: %w", iface, err))
			continue
		}
		r.appliedQoS[iface] = q
	}
	return errors.Join(errs...)
}
