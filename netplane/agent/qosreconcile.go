package agent

import (
	"context"
	"errors"
	"fmt"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
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

// ReconcileQoS programs the QoS lanes (ConfigureQoS) for every NetworkInterface scheduled to this
// node whose spec.qos is set. Diffs against r.appliedQoS: unchanged NICs are skipped, cleared/removed
// NICs are set back to unlimited (0/0/0), new/changed caps are pushed. interface_id = NIC name.
func (r *Reconciler) ReconcileQoS(ctx context.Context) error {
	if r.dp == nil {
		return nil
	}
	var nics netv1.NetworkInterfaceList
	if err := r.client.List(ctx, &nics); err != nil {
		return fmt.Errorf("list networkinterfaces: %w", err)
	}
	desired := map[string]netv1.InterfaceQoS{}
	for i := range nics.Items {
		nic := &nics.Items[i]
		if nic.Spec.NodeName == nil || *nic.Spec.NodeName != r.nodeID {
			continue
		}
		if nic.Spec.QoS == nil {
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
