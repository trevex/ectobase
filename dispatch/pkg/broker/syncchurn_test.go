// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
)

// writeCounter records the mutating calls a sync makes downstream. Counting them is the only way
// to see this class of bug: a delete-then-recreate leaves the same SET of objects behind, so any
// assertion that only counts items passes while the twins churn on every cycle.
type writeCounter struct{ creates, deletes int }

func (w *writeCounter) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			w.creates++
			return c.Create(ctx, obj, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			w.deletes++
			return c.Delete(ctx, obj, opts...)
		},
	}
}

// TestSyncOnce_ConvergedStateIsAWriteFreeNoOp pins the property the whole set-reconcile rests on:
// once downstream matches the dispatch, a sync writes nothing.
//
// The desired set is keyed from DISPATCH objects, which live in the pool namespace, while the
// current set is keyed from DOWNSTREAM objects, which the broker deliberately mirrors into their
// SOURCE namespace. If both sides key on "namespace/name" those two key spaces can never intersect,
// so every twin looks simultaneously absent (create it) and unwanted (GC it) — a delete/recreate
// storm that cascades into the materialized Pod and VMI on every single sync tick.
func TestSyncOnce_ConvergedStateIsAWriteFreeNoOp(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	nic := func(ns, name string) *compiledv1.CompiledNIC {
		return &compiledv1.CompiledNIC{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       compiledv1.CompiledNICSpec{ClusterName: "c1"},
		}
	}

	vm := func(ns, name string) *compiledv1.CompiledVM {
		return &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	}
	att := func(ns, name string) *compiledv1.CompiledVolumeAttachment {
		return &compiledv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	}
	ctr := func(ns, name string) *compiledv1.CompiledContainer {
		return &compiledv1.CompiledContainer{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	}

	// All four kinds share the keying, so all four have to be pinned — a fix applied to one
	// sync loop and missed on another leaves that kind churning silently.
	for _, tc := range []struct {
		kind string
		// onDispatch relocates the fixture to the pool namespace and stamps its source;
		// downstream holds the already-converged twin, in that source namespace.
		dispatchObj, downstreamObj client.Object
		sync                       func(*Broker, context.Context) error
	}{
		{"CompiledNIC", onDispatch(nic("ns1", "a"), "c1"), nic("ns1", "a"),
			func(b *Broker, ctx context.Context) error { return b.SyncOnce(ctx) }},
		{"CompiledVM", onDispatch(vm("ns1", "a"), "c1"), vm("ns1", "a"),
			func(b *Broker, ctx context.Context) error { return b.SyncCompiledVMs(ctx) }},
		{"CompiledVolumeAttachment", onDispatch(att("ns1", "a"), "c1"), att("ns1", "a"),
			func(b *Broker, ctx context.Context) error { return b.SyncCompiledVolumeAttachments(ctx) }},
		{"CompiledContainer", onDispatch(ctr("ns1", "a"), "c1"), ctr("ns1", "a"),
			func(b *Broker, ctx context.Context) error { return b.SyncCompiledContainers(ctx) }},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(tc.dispatchObj).Build()
			var w writeCounter
			downstream := fake.NewClientBuilder().WithScheme(s).
				WithObjects(tc.downstreamObj).
				WithInterceptorFuncs(w.funcs()).Build()

			b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
			if err := tc.sync(b, context.Background()); err != nil {
				t.Fatal(err)
			}
			if w.deletes != 0 || w.creates != 0 {
				t.Fatalf("converged sync churned the downstream twin: %d deletes, %d creates (want 0, 0)",
					w.deletes, w.creates)
			}
		})
	}
}
