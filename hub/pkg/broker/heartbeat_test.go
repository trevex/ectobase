// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platforminstall "github.com/trevex/ectobase/api/platform/install"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

type staticReporter struct{ rl corev1.ResourceList }

func (s staticReporter) Report(context.Context) (corev1.ResourceList, error) { return s.rl, nil }

type errReporter struct{ err error }

func (e errReporter) Report(context.Context) (corev1.ResourceList, error) { return nil, e.err }

func TestHeartbeatOnce(t *testing.T) {
	s := runtime.NewScheme()
	if err := platforminstall.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	pool := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c1"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pool).WithStatusSubresource(pool).Build()

	rl := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("8")}
	h := &Heartbeater{Central: c, PoolName: "c1", HolderIdentity: "broker-1", Reporter: staticReporter{rl}}
	if err := h.heartbeatOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := &platformv1.ClusterPool{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "c1"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Lease == nil || got.Status.Lease.RenewTime == nil {
		t.Fatalf("lease not set: %+v", got.Status)
	}
	if got.Status.Lease.HolderIdentity != "broker-1" {
		t.Fatalf("holder: %q", got.Status.Lease.HolderIdentity)
	}
	if got.Status.Allocatable.Cpu().Cmp(resource.MustParse("8")) != 0 {
		t.Fatalf("cpu: %v", got.Status.Allocatable.Cpu())
	}
}

// A reporter error aborts the heartbeat before any status write, leaving the
// pool's lease untouched (so a bad capacity read can't clobber a good lease).
func TestHeartbeatOnce_ReporterError(t *testing.T) {
	s := runtime.NewScheme()
	if err := platforminstall.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	pool := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c1"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pool).WithStatusSubresource(pool).Build()

	h := &Heartbeater{Central: c, PoolName: "c1", HolderIdentity: "broker-1", Reporter: errReporter{errors.New("boom")}}
	if err := h.heartbeatOnce(context.Background()); err == nil {
		t.Fatal("expected error from reporter, got nil")
	}

	got := &platformv1.ClusterPool{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "c1"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Lease != nil {
		t.Fatalf("lease must remain untouched on reporter error, got %+v", got.Status.Lease)
	}
}

// A missing ClusterPool surfaces as an error (no silent no-op).
func TestHeartbeatOnce_PoolNotFound(t *testing.T) {
	s := runtime.NewScheme()
	if err := platforminstall.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(s).Build()
	h := &Heartbeater{Central: c, PoolName: "missing", HolderIdentity: "b", Reporter: staticReporter{}}
	if err := h.heartbeatOnce(context.Background()); err == nil {
		t.Fatal("expected error for missing pool, got nil")
	}
}
