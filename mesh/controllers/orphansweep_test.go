// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"
	"time"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// twin builds a CompiledNIC, optionally stamped with a source and aged past MinAge.
func twin(name string, srcNamespace, srcName string, age time.Duration) *compiledv1.CompiledNIC {
	c := &compiledv1.CompiledNIC{ObjectMeta: metav1.ObjectMeta{
		Namespace:         "default",
		Name:              name,
		CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
	}}
	if srcName != "" {
		stampSource(c, srcNamespace, srcName)
	}
	return c
}

// TestOrphanSweepOnlyReclaimsProvenOrphans pins the sweeper's conservatism: it deletes a twin only
// when it carries a source back-reference, is older than MinAge, and its source is verifiably
// gone. Everything else is left alone — a false positive here would delete a live workload's
// compiled state.
func TestOrphanSweepOnlyReclaimsProvenOrphans(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		netv1.AddToScheme, compiledv1.AddToScheme, computev1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	// The one true orphan: stamped, old, source absent.
	orphan := twin("orphan", "default", "gone-nic", time.Hour)
	// Stamped + old, but the source still exists.
	live := twin("live", "default", "live-nic", time.Hour)
	liveSrc := &netv1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "live-nic"}}
	// Stamped, source absent, but too young to judge — it may have just been created.
	young := twin("young", "default", "gone-nic", time.Second)
	// Unstamped: provenance unknown, so never swept.
	unstamped := twin("unstamped", "", "", time.Hour)

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(orphan, live, young, unstamped, liveSrc).Build()

	s := &OrphanSweeper{Client: cl, APIReader: cl, MinAge: time.Minute}
	n, err := s.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("swept %d twins, want exactly 1 (the proven orphan)", n)
	}

	gone := func(name string) bool {
		err := cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: name}, &compiledv1.CompiledNIC{})
		return apierrors.IsNotFound(err)
	}
	if !gone("orphan") {
		t.Fatal("orphan (stamped, old, source gone) should have been swept")
	}
	for _, keep := range []string{"live", "young", "unstamped"} {
		if gone(keep) {
			t.Fatalf("%q was swept but must be kept", keep)
		}
	}
}

// TestOrphanSweepResolvesAttachmentsToTheirVM covers the 1:N kind, whose stamped source is the
// owning VirtualMachine rather than a same-named object.
func TestOrphanSweepResolvesAttachmentsToTheirVM(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		netv1.AddToScheme, compiledv1.AddToScheme, computev1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	att := &compiledv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{
		Namespace:         "default",
		Name:              "vm-gone-vol-a",
		CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
	}}
	stampSource(att, "default", "vm-gone")
	keep := &compiledv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{
		Namespace:         "default",
		Name:              "vm-live-vol-a",
		CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
	}}
	stampSource(keep, "default", "vm-live")
	vm := &computev1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm-live"}}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(att, keep, vm).Build()
	s := &OrphanSweeper{Client: cl, APIReader: cl, MinAge: time.Minute}
	if n, err := s.SweepOnce(context.Background()); err != nil || n != 1 {
		t.Fatalf("swept %d, err %v; want exactly 1", n, err)
	}
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "vm-live-vol-a"},
		&compiledv1.CompiledVolumeAttachment{}); err != nil {
		t.Fatalf("attachment of a live VM was swept: %v", err)
	}
}
