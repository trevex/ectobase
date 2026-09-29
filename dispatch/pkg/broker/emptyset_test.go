// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"testing"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
)

// strandedTwins is what a failover leaves on the source pool: one twin of every kind the broker
// mirrors, none of which the dispatch still wants.
func strandedTwins() []client.Object {
	meta := metav1.ObjectMeta{Namespace: "tenant", Name: "moved"}
	return []client.Object{
		&compiledv1.CompiledNIC{ObjectMeta: meta},
		&compiledv1.CompiledVM{ObjectMeta: meta},
		&compiledv1.CompiledVolumeAttachment{ObjectMeta: meta},
		&compiledv1.CompiledContainer{ObjectMeta: meta},
	}
}

func syncAll(ctx context.Context, b *Broker) error {
	for _, sync := range []func(context.Context) error{
		b.SyncOnce, b.SyncCompiledVMs, b.SyncCompiledVolumeAttachments, b.SyncCompiledContainers,
	} {
		if err := sync(ctx); err != nil {
			return err
		}
	}
	return nil
}

func downstreamCount(t *testing.T, c client.Client) int {
	t.Helper()
	ctx := context.Background()
	n := 0
	for _, l := range []client.ObjectList{
		&compiledv1.CompiledNICList{}, &compiledv1.CompiledVMList{},
		&compiledv1.CompiledVolumeAttachmentList{}, &compiledv1.CompiledContainerList{},
	} {
		if err := c.List(ctx, l); err != nil {
			t.Fatal(err)
		}
		n += apimeta.LenList(l)
	}
	return n
}

// An empty pool namespace on the dispatch is an authoritative answer — nothing is wanted here — so
// every twin downstream goes. This is the state a source pool is in after its only VM failed over
// elsewhere, and the one the broker used to never act on.
func TestSync_EmptyDesiredSetPrunesEverything(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	dispatch := fake.NewClientBuilder().WithScheme(s).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(strandedTwins()...).Build()

	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
	if err := syncAll(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if n := downstreamCount(t, downstream); n != 0 {
		t.Fatalf("an empty desired set left %d twins downstream, want 0", n)
	}
}

// A desired set that could not be read is NOT an empty one: pruning on it would wipe a live pool on
// a transient dispatch error. Every sync must fail before it deletes anything.
func TestSync_UnreadableDesiredSetPrunesNothing(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	dispatch := fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errors.New("dispatch unreachable")
		},
	}).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(strandedTwins()...).Build()

	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
	for _, sync := range []func(context.Context) error{
		b.SyncOnce, b.SyncCompiledVMs, b.SyncCompiledVolumeAttachments, b.SyncCompiledContainers,
	} {
		if err := sync(context.Background()); err == nil {
			t.Fatal("a sync over an unreadable desired set reported success")
		}
	}
	if n := downstreamCount(t, downstream); n != 4 {
		t.Fatalf("an unreadable desired set left %d of 4 twins downstream, want all 4", n)
	}
}
