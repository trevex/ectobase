// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package clusterpool

import (
	"time"

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

const (
	// PhaseReady indicates the pool's broker lease is fresh (renewed within healthStale).
	PhaseReady = "Ready"
	// PhaseUnknown indicates the pool's broker lease has expired (stale RenewTime).
	PhaseUnknown = "Unknown"
)

// phaseFromLease derives the pool phase from lease freshness: no lease/renew =>
// Pending (never reported); renewed within-or-at healthStale => Ready; older =>
// Unknown. The boundary is inclusive (age == healthStale is still Ready) to avoid
// flicker exactly at the threshold.
func phaseFromLease(now time.Time, lease *platformv1.ClusterPoolLease, healthStale time.Duration) string {
	if lease == nil || lease.RenewTime == nil {
		return PhasePending
	}
	if now.Sub(lease.RenewTime.Time) <= healthStale {
		return PhaseReady
	}
	return PhaseUnknown
}
