// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/dispatch/pkg/broker"
)

// resyncPeriod bounds how long the downstream can disagree with the dispatch without any event to
// say so: a delete that happened while the broker was down, a watch event lost to a reconnect, or a
// twin removed or edited downstream by hand.
const resyncPeriod = time.Minute

// syncRequest is the one work item every trigger enqueues. The sync ignores its request and
// reconciles every type at once, so one shared key both coalesces a burst of events into a single
// pass and keeps passes from running concurrently against each other.
var syncRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "pool-sync"}}

// setupSync registers the controller that drives r. Three things enqueue a sync:
//
//   - any CompiledNIC, CompiledVM, CompiledVolumeAttachment or CompiledContainer event in the
//     pool namespace;
//   - the controller starting, which is what reaps twins stranded while the broker was down. An
//     empty pool namespace yields no events at all — its initial list is empty — so without this
//     a pool whose last workload moved away while its broker was down keeps that workload forever;
//   - every resyncPeriod after a successful pass.
//
// Pruning on an empty desired set is safe because empty here is authoritative: the dispatch reads
// go through the manager's cache, which serves nothing until it has synced, and a failed list fails
// the pass before anything is deleted. So "the dispatch says nothing is wanted" and "the dispatch
// could not be read" never look alike to the sync.
func setupSync(mgr ctrl.Manager, r *brokerReconciler) error {
	enqueue := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{syncRequest}
	})
	// Workers start only after every watched cache has synced, so this first pass reads a complete
	// desired set, never a partially filled one.
	atStart := source.Func(func(_ context.Context, q workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
		q.Add(syncRequest)
		return nil
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("broker").
		Watches(&compiledv1.CompiledNIC{}, enqueue).
		Watches(&compiledv1.CompiledVM{}, enqueue).
		Watches(&compiledv1.CompiledVolumeAttachment{}, enqueue).
		Watches(&compiledv1.CompiledContainer{}, enqueue).
		WatchesRawSource(atStart).
		Complete(r)
}

// brokerReconciler wraps the broker engine so it satisfies reconcile.Reconciler.
// It holds no per-object state: every pass is a full SyncOnce + SyncCompiledVMs +
// SyncCompiledVolumeAttachments + SyncCompiledContainers (declarative set-reconcile;
// idempotent and restart-safe).
type brokerReconciler struct {
	dispatch    client.Client
	downstream  client.Client
	clusterName string
}

func (r *brokerReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	b := &broker.Broker{
		Dispatch:    r.dispatch,
		Downstream:  r.downstream,
		ClusterName: r.clusterName,
	}
	if err := b.SyncOnce(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := b.SyncCompiledVMs(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := b.SyncCompiledVolumeAttachments(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := b.SyncCompiledContainers(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: resyncPeriod}, nil
}
