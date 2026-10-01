// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/dispatch/pkg/broker"
)

// resyncPeriod bounds how long the downstream can disagree with the dispatch without any event to
// say so: a delete that happened while the broker was down, a watch event lost to a reconnect, or a
// twin removed or edited downstream by hand.
const resyncPeriod = time.Minute

// releasePollInterval is how soon a pass looks again while a retired twin is still held. The
// downstream teardown it waits for (VM -> VMI -> virt-launcher -> claim) raises no dispatch event,
// and a move is stalled until it finishes, so the minute-long resync would be the move's latency.
const releasePollInterval = 5 * time.Second

// syncRequest and releaseRequest are the two work items every trigger enqueues. Neither carries an
// object: the sync reconciles every type at once and the release check looks at every retired twin,
// so one key per pass both coalesces a burst of events into a single pass and keeps a pass from
// running concurrently with itself.
//
// They are separate items, not one pass, because the queue retries a failed item with an
// exponential backoff kept per item. A release check that shared its item with the syncs would
// share that backoff too: a sync failing for reasons unrelated to any VM (one bad container twin,
// say) would stretch the release poll from releasePollInterval to the backoff ceiling, and every
// move off this pool would wait it out.
var (
	syncRequest    = reconcile.Request{NamespacedName: types.NamespacedName{Name: "pool-sync"}}
	releaseRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "pool-release"}}
)

// setupSync registers the controller that drives r. Three things enqueue both the sync and the
// release check:
//
//   - any CompiledNIC, CompiledVM, CompiledVolumeAttachment or CompiledContainer event in the
//     pool namespace;
//   - the controller starting, which is what reaps twins stranded while the broker was down. An
//     empty pool namespace yields no events at all — its initial list is empty — so without this
//     a pool whose last workload moved away while its broker was down keeps that workload forever;
//   - every resyncPeriod after a successful pass (releasePollInterval for the release check while
//     a release is pending).
//
// The sync is enqueued first, so a twin's retirement is acted on (its VM stopped) before the
// release check first looks at it.
//
// Pruning on an empty desired set is safe because empty here is authoritative: the dispatch reads
// go through the manager's cache, which serves nothing until it has synced, and a failed list fails
// the pass before anything is deleted. So "the dispatch says nothing is wanted" and "the dispatch
// could not be read" never look alike to the sync.
func setupSync(mgr ctrl.Manager, r *brokerReconciler) error {
	enqueue := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{syncRequest, releaseRequest}
	})
	// Workers start only after every watched cache has synced, so this first pass reads a complete
	// desired set, never a partially filled one.
	atStart := source.Func(func(_ context.Context, q workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
		q.Add(syncRequest)
		q.Add(releaseRequest)
		return nil
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("broker").
		// A failed pass is retried with a backoff that doubles from 5ms, as by default, but stops at
		// resyncPeriod rather than the default 1000s. resyncPeriod is the promised bound on downstream
		// drift, and a pass that keeps failing should not be retried less often than a healthy one runs.
		WithOptions(controller.Options{
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
				5*time.Millisecond, resyncPeriod),
		}).
		Watches(&compiledv1.CompiledNIC{}, enqueue).
		Watches(&compiledv1.CompiledVM{}, enqueue).
		Watches(&compiledv1.CompiledVolumeAttachment{}, enqueue).
		Watches(&compiledv1.CompiledContainer{}, enqueue).
		WatchesRawSource(atStart).
		Complete(r)
}

// brokerReconciler wraps the broker engine so it satisfies reconcile.Reconciler.
// It holds no per-object state: a syncRequest pass is a full SyncOnce + SyncCompiledVMs +
// SyncCompiledVolumeAttachments + SyncCompiledContainers (declarative set-reconcile;
// idempotent and restart-safe), a releaseRequest pass is a ReportReleases.
type brokerReconciler struct {
	dispatch    client.Client
	downstream  client.Client
	clusterName string
}

func (r *brokerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	b := &broker.Broker{
		Dispatch:    r.dispatch,
		Downstream:  r.downstream,
		ClusterName: r.clusterName,
	}
	if req == releaseRequest {
		return reportReleases(ctx, b)
	}
	// Every sync runs even when an earlier one fails: a failing NIC or container sync must not
	// stop a retired twin's VM, which SyncCompiledVMs does and a move is stalled on. The errors are
	// returned together, so a failed pass still requeues with backoff.
	if err := errors.Join(
		b.SyncOnce(ctx),
		b.SyncCompiledVMs(ctx),
		b.SyncCompiledVolumeAttachments(ctx),
		b.SyncCompiledContainers(ctx),
	); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: resyncPeriod}, nil
}

// reportReleases is a releaseRequest pass. While a release is pending it looks again every
// releasePollInterval, even when checking a twin failed. ReportReleases has already checked every
// other twin by then, and handing the error back to the queue would put the release check under the
// failure backoff, so one bad retired twin would slow the release of every other one. The error is
// logged instead, and the poll is its retry.
//
// A failure that leaves nothing known to be pending — the twins could not be listed at all — is
// returned, and retried with backoff like any other failed pass.
func reportReleases(ctx context.Context, b *broker.Broker) (ctrl.Result, error) {
	pending, err := b.ReportReleases(ctx)
	switch {
	case pending:
		if err != nil {
			ctrllog.FromContext(ctx).Error(err, "release check failed; checking again at the release poll",
				"after", releasePollInterval)
		}
		return ctrl.Result{RequeueAfter: releasePollInterval}, nil
	case err != nil:
		return ctrl.Result{}, err
	default:
		return ctrl.Result{RequeueAfter: resyncPeriod}, nil
	}
}
