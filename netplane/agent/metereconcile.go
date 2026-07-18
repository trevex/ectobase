package agent

import (
	"context"
	"errors"
	"fmt"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

// ReconcileMeter programs the egress bandwidth cap (METER token-bucket) for every NetworkInterface
// scheduled to this node whose spec.bandwidth is set. It DIFFS against the last-applied caps
// (`r.appliedMeter`): a NIC whose caps are unchanged is skipped (ConfigureMeter is idempotent but
// re-calling every loop is wasteful), a NIC whose bandwidth was cleared or removed is set back to
// unlimited (0/0), and new/changed caps are pushed. The interface_id is the NIC name, matching the
// firewall reconcile's NICRef.Name convention (the dataplane resolves it to the attached ifindex).
func (r *Reconciler) ReconcileMeter(ctx context.Context) error {
	if r.dp == nil {
		return nil
	}
	var nics netv1.NetworkInterfaceList
	if err := r.client.List(ctx, &nics); err != nil {
		return fmt.Errorf("list networkinterfaces: %w", err)
	}
	// desired: interfaceID -> caps for the NICs scheduled here that request a bandwidth cap.
	desired := map[string]netv1.InterfaceBandwidth{}
	for i := range nics.Items {
		nic := &nics.Items[i]
		if nic.Spec.NodeName == nil || *nic.Spec.NodeName != r.nodeID {
			continue // only meter interfaces attached to THIS node
		}
		if nic.Spec.Bandwidth == nil {
			continue // no cap requested → unlimited (handled by the clear pass below)
		}
		desired[nic.Name] = *nic.Spec.Bandwidth
	}
	if r.appliedMeter == nil {
		r.appliedMeter = map[string]netv1.InterfaceBandwidth{}
	}
	var errs []error
	// Clear caps for interfaces that were metered but are no longer desired (spec removed or NIC
	// gone): set them back to unlimited (0/0). ConfigureMeter with 0/0 removes the METER entry.
	for iface := range r.appliedMeter {
		if _, ok := desired[iface]; ok {
			continue
		}
		if err := r.dp.ConfigureMeter(ctx, iface, 0, 0); err != nil {
			errs = append(errs, fmt.Errorf("ConfigureMeter clear %s: %w", iface, err))
			continue
		}
		delete(r.appliedMeter, iface)
	}
	// Push new/changed caps.
	for iface, bw := range desired {
		if cur, ok := r.appliedMeter[iface]; ok && cur == bw {
			continue // unchanged
		}
		if err := r.dp.ConfigureMeter(ctx, iface, bw.TotalMbps, bw.PublicMbps); err != nil {
			errs = append(errs, fmt.Errorf("ConfigureMeter %s: %w", iface, err))
			continue
		}
		r.appliedMeter[iface] = bw
	}
	return errors.Join(errs...)
}
