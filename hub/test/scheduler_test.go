// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/hub/pkg/clusterpool"
	"github.com/trevex/ectobase/hub/pkg/scheduler"
)

// TestScheduler_BindsVM proves the Phase-3 scheduler binds an unbound VM to a
// Ready ClusterPool that fits its resource request, against the REAL kit
// aggregated apiserver (not a fake client): a Ready pool c1 (cpu:8) and an
// unbound vm1 (requests cpu:2) are created, the scheduler.Reconciler is driven
// directly via Reconcile, and vm1 must end up spec.clusterName=c1 with a
// Scheduled=True condition.
func TestScheduler_BindsVM(t *testing.T) {
	c, ctx := startNetEnv(t)
	const ns = "default"

	// Ready pool c1 with cpu:8 allocatable. Phase/Allocatable live on status, so
	// they are set via the status subresource (spec has no such fields).
	pool := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c1"}}
	if err := c.Create(ctx, pool); err != nil {
		t.Fatalf("create pool c1: %v", err)
	}
	cur := &platformv1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pool), cur); err != nil {
		t.Fatalf("get pool c1: %v", err)
	}
	cur.Status.Phase = clusterpool.PhaseReady
	cur.Status.Allocatable = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("8")}
	if err := c.Status().Update(ctx, cur); err != nil {
		t.Fatalf("status update pool c1: %v", err)
	}

	// Unbound vm1 requesting cpu:2.
	vm := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm1"},
		Spec: computev1.VirtualMachineSpec{
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
			},
		},
	}
	if err := c.Create(ctx, vm); err != nil {
		t.Fatalf("create vm1: %v", err)
	}

	r := &scheduler.Reconciler{Client: c}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "vm1"}}); err != nil {
		t.Fatalf("scheduler Reconcile: %v", err)
	}

	got := &computev1.VirtualMachine{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm1"}, got); err != nil {
		t.Fatalf("get vm1: %v", err)
	}
	if got.Spec.ClusterName != "c1" {
		t.Fatalf("expected vm1 bound to c1, got %q", got.Spec.ClusterName)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, "Scheduled")
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Scheduled=True condition, got %+v", cond)
	}
	t.Logf("scheduler: PASS (vm1 -> c1, Scheduled=True reason=%s)", cond.Reason)
}

// TestScheduler_BindsContainer proves the Container pool-scheduler binds an unbound
// Container to a Ready ClusterPool that fits its request, AND that VMs and
// Containers share pool capacity: a Ready pool cc (cpu:4) already has a bound VM
// occupying cpu:3, so a Container requesting cpu:2 does NOT fit and stays unbound;
// a Container requesting cpu:1 fits the remaining cpu:1 and is bound to cc.
func TestScheduler_BindsContainer(t *testing.T) {
	c, ctx := startNetEnv(t)
	const ns = "default"

	// Ready pool cc with cpu:4 allocatable.
	pool := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "cc"}}
	if err := c.Create(ctx, pool); err != nil {
		t.Fatalf("create pool cc: %v", err)
	}
	cur := &platformv1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pool), cur); err != nil {
		t.Fatalf("get pool cc: %v", err)
	}
	cur.Status.Phase = clusterpool.PhaseReady
	cur.Status.Allocatable = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4")}
	if err := c.Status().Update(ctx, cur); err != nil {
		t.Fatalf("status update pool cc: %v", err)
	}

	// A VM already bound to cc, occupying cpu:3 of its cpu:4.
	vm := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm-cc"},
		Spec: computev1.VirtualMachineSpec{
			ClusterName: "cc",
			Resources:   corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("3")}},
		},
	}
	if err := c.Create(ctx, vm); err != nil {
		t.Fatalf("create vm-cc: %v", err)
	}

	r := &scheduler.ContainerReconciler{Client: c}

	// A Container requesting cpu:2 must NOT fit (3+2 > 4) -> stays unbound.
	big := &computev1.Container{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ctr-big"},
		Spec:       computev1.ContainerSpec{Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")}}},
	}
	if err := c.Create(ctx, big); err != nil {
		t.Fatalf("create ctr-big: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "ctr-big"}}); err != nil {
		t.Fatalf("reconcile ctr-big: %v", err)
	}
	gotBig := &computev1.Container{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctr-big"}, gotBig); err != nil {
		t.Fatalf("get ctr-big: %v", err)
	}
	if gotBig.Spec.ClusterName != "" {
		t.Fatalf("expected ctr-big unbound (VM+Container share capacity), got clusterName=%q", gotBig.Spec.ClusterName)
	}

	// A Container requesting cpu:1 fits the remaining cpu:1 -> bound to cc.
	small := &computev1.Container{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ctr-small"},
		Spec:       computev1.ContainerSpec{Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")}}},
	}
	if err := c.Create(ctx, small); err != nil {
		t.Fatalf("create ctr-small: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: "ctr-small"}}); err != nil {
		t.Fatalf("reconcile ctr-small: %v", err)
	}
	gotSmall := &computev1.Container{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "ctr-small"}, gotSmall); err != nil {
		t.Fatalf("get ctr-small: %v", err)
	}
	if gotSmall.Spec.ClusterName != "cc" {
		t.Fatalf("expected ctr-small bound to cc, got %q", gotSmall.Spec.ClusterName)
	}
	t.Logf("container scheduler: PASS (ctr-big unscheduled, ctr-small -> cc; VM+Container share capacity)")
}
