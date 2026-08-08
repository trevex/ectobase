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
		{"fresh", &platformv1.ClusterPoolLease{RenewTime: mt(990)}, PhaseReady},   // 10s old < 30s
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
