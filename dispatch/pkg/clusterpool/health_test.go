// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package clusterpool

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

func TestPhaseFromLease(t *testing.T) {
	now := time.Unix(1000, 0)
	stale := 30 * time.Second
	mt := func(sec int64) *metav1.MicroTime { m := metav1.NewMicroTime(time.Unix(sec, 0)); return &m }
	cases := []struct {
		name  string
		lease *platformv1.ClusterPoolLease
		want  string
	}{
		{"never", nil, PhasePending},
		{"fresh", &platformv1.ClusterPoolLease{RenewTime: mt(990)}, PhaseReady},    // 10s old < 30s
		{"stale", &platformv1.ClusterPoolLease{RenewTime: mt(900)}, PhaseUnknown},  // 100s old > 30s
		{"boundary", &platformv1.ClusterPoolLease{RenewTime: mt(970)}, PhaseReady}, // exactly 30s old (== stale) is still Ready
		{"nil-renew", &platformv1.ClusterPoolLease{}, PhasePending},
	}
	for _, tc := range cases {
		if got := phaseFromLease(now, tc.lease, stale); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

// Reachable needs the phase AND the lease: the phase lags a broker that has just gone silent.
func TestReachable(t *testing.T) {
	now := time.Unix(1000, 0)
	stale := 30 * time.Second
	mt := func(sec int64) *metav1.MicroTime { m := metav1.NewMicroTime(time.Unix(sec, 0)); return &m }
	pool := func(phase string, renew *metav1.MicroTime) *platformv1.ClusterPool {
		p := &platformv1.ClusterPool{Status: platformv1.ClusterPoolStatus{Phase: phase}}
		if renew != nil {
			p.Status.Lease = &platformv1.ClusterPoolLease{RenewTime: renew}
		}
		return p
	}
	for name, tc := range map[string]struct {
		pool *platformv1.ClusterPool
		want bool
	}{
		"ready and fresh":          {pool(PhaseReady, mt(990)), true},
		"ready on a stale lease":   {pool(PhaseReady, mt(900)), false},
		"unknown on a fresh lease": {pool(PhaseUnknown, mt(990)), false},
		"ready without a lease":    {pool(PhaseReady, nil), false},
	} {
		if got := Reachable(tc.pool, now, stale); got != tc.want {
			t.Errorf("%s: got %v want %v", name, got, tc.want)
		}
	}
}
