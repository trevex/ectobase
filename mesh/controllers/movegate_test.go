// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
)

func vmTwin(ns string, terminating bool) *compiledv1.CompiledVM {
	t := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default-vm"}}
	if terminating {
		now := metav1.Now()
		t.DeletionTimestamp = &now
		t.Finalizers = []string{finalizerSourceReleased}
	}
	return t
}

func TestAwaitingRelease(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pool  string
		twins []client.Object
		want  int
	}{
		{"first placement: no twins", "pool-b", nil, 0},
		{"steady state: only the twin in its own pool", "pool-a", []client.Object{vmTwin("pool-a", false)}, 0},
		{"move: a live twin in the old pool", "pool-b", []client.Object{vmTwin("pool-a", false)}, 1},
		{"move in progress: the old twin terminating", "pool-b", []client.Object{vmTwin("pool-a", true)}, 1},
		{"reversed mid-move: own pool's twin still terminating", "pool-b", []client.Object{vmTwin("pool-b", true)}, 1},
		{"chained: two earlier pools still holding", "pool-b", []client.Object{vmTwin("pool-a", true), vmTwin("pool-c", false)}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(awaitingRelease(tc.pool, tc.twins)); got != tc.want {
				t.Fatalf("awaitingRelease(%s) = %d twins, want %d", tc.pool, got, tc.want)
			}
		})
	}
}

// A twin compiled before the finalizer existed must get it BEFORE it is deleted: deleted bare, it
// would vanish at once and the gate would open with the source VM still running.
func TestRetireTwin_FinalizesBeforeDeleting(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	legacy := vmTwin("pool-a", false)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(legacy).Build()

	if err := retireTwin(context.Background(), c, legacy); err != nil {
		t.Fatal(err)
	}
	var got compiledv1.CompiledVM
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(legacy), &got); err != nil {
		t.Fatalf("a retired twin must stay visible until its pool releases it: %v", err)
	}
	if got.DeletionTimestamp.IsZero() || !controllerutil.ContainsFinalizer(&got, finalizerSourceReleased) {
		t.Fatalf("want Terminating with %s, got deletionTimestamp=%v finalizers=%v",
			finalizerSourceReleased, got.DeletionTimestamp, got.Finalizers)
	}
	// Idempotent on an already-terminating twin.
	if err := retireTwin(context.Background(), c, &got); err != nil {
		t.Fatalf("second retire: %v", err)
	}
}
