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

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// CapacityReporter yields the schedulable capacity to advertise for this cluster.
type CapacityReporter interface{ Report(ctx context.Context) (corev1.ResourceList, error) }

// Heartbeater renews the broker's ClusterPool lease + reports capacity upward.
type Heartbeater struct {
	Hub        client.Client
	PoolName       string
	HolderIdentity string
	Reporter       CapacityReporter
	Interval       time.Duration
}

// heartbeatOnce renews the lease RenewTime + Allocatable on the broker's own ClusterPool.
func (h *Heartbeater) heartbeatOnce(ctx context.Context) error {
	pool := &platformv1.ClusterPool{}
	if err := h.Hub.Get(ctx, client.ObjectKey{Name: h.PoolName}, pool); err != nil {
		return fmt.Errorf("get clusterpool %s: %w", h.PoolName, err)
	}
	rl, err := h.Reporter.Report(ctx)
	if err != nil {
		return fmt.Errorf("report capacity: %w", err)
	}
	now := metav1.NewMicroTime(time.Now())
	orig := pool.DeepCopy()
	pool.Status.Lease = &platformv1.ClusterPoolLease{HolderIdentity: h.HolderIdentity, RenewTime: &now}
	pool.Status.Allocatable = rl
	// A merge Patch (not Update) of ONLY the lease+allocatable fields: the statusReporter
	// concurrently patches NodePrefixes/NodeDrain and the pool-health controller writes Phase
	// on the SAME status subresource. A full Status().Update from a cached (stale) Get both
	// 409-conflicts against those writers AND clobbers their fields back to the cached value
	// (this is why NodePrefixes never stuck). MergeFrom sends only this beat's diff with no
	// resourceVersion precondition — no conflict, no clobber.
	if err := h.Hub.Status().Patch(ctx, pool, client.MergeFrom(orig)); err != nil {
		return fmt.Errorf("patch clusterpool status: %w", err)
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
