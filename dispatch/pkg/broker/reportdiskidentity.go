// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"fmt"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ReportDiskIdentities carries each provisioned disk's CSI identity from the pool that provisioned
// it up onto the dispatch, so it can outlive the attachment that happens to reference it.
//
// It is the same shape as the per-VM placement half of ReportStatus, and for the same reason: the
// identity belongs conceptually on the Volume, but the Volume lives in a tenant namespace shared
// with every other pool's workloads, so a pool writing it would need a grant no per-pool RBAC can
// scope. Writing this pool's own attachment is scopeable, and a mesh controller on the dispatch does
// the cross-namespace hop onto the Volume.
//
// It differs from placement in one way that matters: failures are RETURNED, not swallowed. A dropped
// placement is a stale field the next tick corrects. A dropped identity is the only record of which
// image holds a disk's data, and until it reaches the dispatch a rebind of that workload provisions
// a blank disk instead — so the tick must know it failed.
func (b *Broker) ReportDiskIdentities(ctx context.Context) error {
	have := &compiledv1.CompiledVolumeAttachmentList{}
	if err := b.Downstream.List(ctx, have); err != nil {
		return fmt.Errorf("list downstream attachments: %w", err)
	}

	// Keep going after a per-attachment failure so one unwritable disk cannot hide the identities of
	// all the others, but still surface every failure so the tick retries.
	var errs []error
	for i := range have.Items {
		cur := &have.Items[i]
		id := cur.Status.DiskIdentity
		if id == nil {
			continue // not provisioned yet, or not CSI-backed
		}
		var up compiledv1.CompiledVolumeAttachment
		if err := b.Dispatch.Get(ctx, client.ObjectKey{Namespace: b.poolNamespace(), Name: cur.Name}, &up); err != nil {
			// Not one of ours: the downstream list is a superset, and an attachment with no dispatch
			// counterpart is either mid-GC or was never compiled centrally. Not an error, and not
			// something to create — a pool does not get to invent attachments.
			continue
		}
		if equality.Semantic.DeepEqual(up.Status.DiskIdentity, id) {
			continue // converged: no write, no resourceVersion churn on every tick
		}
		orig := up.DeepCopy()
		up.Status.DiskIdentity = id.DeepCopy()
		// Merge patch, not Update: the compiler owns this object's spec and other writers touch
		// other status fields, so a full Update from a cached read would clobber them.
		if err := b.Dispatch.Status().Patch(ctx, &up, client.MergeFrom(orig)); err != nil {
			errs = append(errs, fmt.Errorf("report disk identity for %s: %w", keyAtt(cur), err))
		}
	}
	return errors.Join(errs...)
}
