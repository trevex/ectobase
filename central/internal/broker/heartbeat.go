// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// CapacityReporter yields the schedulable capacity to advertise for this cluster.
type CapacityReporter interface{ Report(ctx context.Context) (corev1.ResourceList, error) }

// Heartbeater renews the broker's ClusterPool lease + reports capacity upward.
type Heartbeater struct {
	Central        client.Client
	PoolName       string
	HolderIdentity string
	Reporter       CapacityReporter
	Interval       time.Duration
}

// heartbeatOnce renews the lease RenewTime + Allocatable on the broker's own ClusterPool.
func (h *Heartbeater) heartbeatOnce(ctx context.Context) error {
	pool := &platformv1.ClusterPool{}
	if err := h.Central.Get(ctx, client.ObjectKey{Name: h.PoolName}, pool); err != nil {
		return fmt.Errorf("get clusterpool %s: %w", h.PoolName, err)
	}
	rl, err := h.Reporter.Report(ctx)
	if err != nil {
		return fmt.Errorf("report capacity: %w", err)
	}
	now := metav1.NewMicroTime(time.Now())
	pool.Status.Lease = &platformv1.ClusterPoolLease{HolderIdentity: h.HolderIdentity, RenewTime: &now}
	pool.Status.Allocatable = rl
	// No retry loop: a 409 conflict (e.g. the pool-health controller concurrently
	// writing Status.Phase) just means we miss one beat. The pool-health staleness
	// threshold is >> Interval, so the next tick recovers well before the pool is
	// judged stale — the broker is the sole writer of its own lease.
	if err := h.Central.Status().Update(ctx, pool); err != nil {
		return fmt.Errorf("update clusterpool status: %w", err)
	}
	return nil
}

// Start runs heartbeatOnce every Interval until ctx is done (controller-runtime manager.Runnable).
func (h *Heartbeater) Start(ctx context.Context) error {
	t := time.NewTicker(h.Interval)
	defer t.Stop()
	_ = h.heartbeatOnce(ctx) // best-effort immediate beat; retried next tick on error
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := h.heartbeatOnce(ctx); err != nil {
				ctrllog.FromContext(ctx).Error(err, "heartbeat")
			}
		}
	}
}
