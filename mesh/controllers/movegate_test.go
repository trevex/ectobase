// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
)

// twinIn is the CompiledVM twin of default/vm compiled for the pool behind namespace ns.
func twinIn(ns string, terminating bool) *compiledv1.CompiledVM {
	cvm := &compiledv1.CompiledVM{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default-vm"},
		Spec:       compiledv1.CompiledVMSpec{ClusterName: strings.TrimPrefix(ns, "pool-")},
	}
	if terminating {
		now := metav1.Now()
		cvm.DeletionTimestamp = &now
		cvm.Finalizers = []string{finalizerSourceReleased}
	}
	return cvm
}

func TestAwaitingRelease(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pool  string
		twins []client.Object
		want  []string // namespaces of the held twins, in the order returned
	}{
		{"first placement: no twins", "pool-b", nil, nil},
		{"steady state: only the twin in its own pool", "pool-a", []client.Object{twinIn("pool-a", false)}, nil},
		{"move: a live twin in the old pool", "pool-b", []client.Object{twinIn("pool-a", false)}, []string{"pool-a"}},
		{"move in progress: the old twin terminating", "pool-b", []client.Object{twinIn("pool-a", true)}, []string{"pool-a"}},
		{"reversed mid-move: own pool's twin still terminating", "pool-b", []client.Object{twinIn("pool-b", true)}, []string{"pool-b"}},
		{"chained: two earlier pools still holding, sorted", "pool-b",
			[]client.Object{twinIn("pool-c", false), twinIn("pool-a", true)}, []string{"pool-a", "pool-c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, cvm := range awaitingRelease(tc.pool, tc.twins) {
				got = append(got, cvm.Namespace)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("awaitingRelease(%s) = %v, want %v", tc.pool, got, tc.want)
			}
		})
	}
}

// The gate reads twins by the workload label, but a label is only a VM name: it must keep only
// the twins stamped for this very source.
func TestGateTwins_OnlyThisSource(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	twin := func(ns, name, workload, srcNS, srcName string) *compiledv1.CompiledVM {
		cvm := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, Labels: map[string]string{"workload": workload},
		}}
		stampSource(cvm, srcNS, srcName)
		return cvm
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(
		twin("pool-a", "default-vm", "vm", "default", "vm"),
		twin("pool-b", "default-vm", "vm", "default", "vm"),
		twin("pool-a", "other-vm", "vm", "other", "vm"),        // same VM name, another tenant namespace
		twin("pool-a", "default-vm2", "vm2", "default", "vm2"), // another VM entirely
	).Build()

	got, err := gateTwins(context.Background(), c, "default", "vm")
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, o := range got {
		keys = append(keys, o.GetNamespace()+"/"+o.GetName())
	}
	slices.Sort(keys)
	if want := []string{"pool-a/default-vm", "pool-b/default-vm"}; !slices.Equal(keys, want) {
		t.Fatalf("gateTwins = %v, want %v", keys, want)
	}
	if _, err := gateTwins(context.Background(), nil, "default", "vm"); err == nil {
		t.Fatal("gateTwins with no reader must fail loudly, not open the gate")
	}
}

// A twin compiled before the finalizer existed must get it BEFORE it is deleted: deleted bare, it
// would vanish at once and the gate would open with the source VM still running.
func TestRetireTwin_FinalizesBeforeDeleting(t *testing.T) {
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	legacy := twinIn("pool-a", false)
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
