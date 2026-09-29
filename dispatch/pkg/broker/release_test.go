// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
)

func releaseScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"VirtualMachine", "VirtualMachineInstance"} {
		gv := schema.GroupVersion{Group: "kubevirt.io", Version: "v1"}
		s.AddKnownTypeWithName(gv.WithKind(kind), &unstructured.Unstructured{})
		s.AddKnownTypeWithName(gv.WithKind(kind+"List"), &unstructured.UnstructuredList{})
	}
	return s
}

// retiredTwin is the dispatch-side twin of VM default/vm on pool c1, retired by a move.
func retiredTwin() *compiledv1.CompiledVM { return retiredTwinOf("vm") }

// retiredTwinOf is the retired dispatch-side twin of VM default/<vm> on pool c1.
func retiredTwinOf(vm string) *compiledv1.CompiledVM {
	now := metav1.Now()
	return &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{
		Namespace:         validate.PoolNamespace("c1"),
		Name:              "default-" + vm,
		Labels:            map[string]string{"workload": vm},
		Annotations:       map[string]string{compiledv1.SourceNamespaceAnnotation: "default", compiledv1.SourceNameAnnotation: vm},
		DeletionTimestamp: &now,
		Finalizers:        []string{"compiled.ectobase.dev/source-released"},
	}}
}

func kubevirt(kind string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: "kubevirt.io", Version: "v1", Kind: kind})
	u.SetNamespace("default")
	u.SetName("default-vm")
	return u
}

func released(t *testing.T, c client.Client) bool { t.Helper(); return releasedOf(t, c, "vm") }

func releasedOf(t *testing.T, c client.Client, vm string) bool {
	t.Helper()
	var got compiledv1.CompiledVM
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(retiredTwinOf(vm)), &got); err != nil {
		t.Fatal(err)
	}
	return got.Status.Released
}

// Each thing the source might still hold must, on its own, keep the twin unreleased.
func TestReportReleases_HeldWhileAnythingRemains(t *testing.T) {
	launcher := launcherOf("default-vm")
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-vm-disk",
		Labels: map[string]string{"workload": "vm"}}}
	local := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-vm"}}

	for name, leftover := range map[string]client.Object{
		"downstream CompiledVM": local,
		"KubeVirt VM":           kubevirt("VirtualMachine"),
		"VMI":                   kubevirt("VirtualMachineInstance"),
		"virt-launcher pod":     launcher,
		"disk claim":            claim,
	} {
		t.Run(name, func(t *testing.T) {
			s := releaseScheme(t)
			twin := retiredTwin()
			dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(twin).WithStatusSubresource(twin).Build()
			downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(leftover).Build()
			b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}

			pending, err := b.ReportReleases(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !pending || released(t, dispatch) {
				t.Fatalf("released while a %s remains (pending=%v)", name, pending)
			}
		})
	}
}

func TestReportReleases_ReleasedOnceNothingRemains(t *testing.T) {
	s := releaseScheme(t)
	twin := retiredTwin()
	// A claim of ANOTHER workload in the same namespace must not hold this one.
	other := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "other",
		Labels: map[string]string{"workload": "other-vm"}}}
	// Nor may the virt-launcher pod of ANOTHER VMI in the same namespace.
	otherLauncher := launcherOf("default-other-vm")
	dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(twin).WithStatusSubresource(twin).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(other, otherLauncher).Build()
	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}

	pending, err := b.ReportReleases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pending || !released(t, dispatch) {
		t.Fatalf("want released and nothing pending, got pending=%v released=%v", pending, released(t, dispatch))
	}
}

// A retired twin is not desired: the broker stops the VM it names.
func TestSyncCompiledVMs_RetiredTwinIsPruned(t *testing.T) {
	s := releaseScheme(t)
	dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(retiredTwin()).Build()
	local := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-vm"}}
	downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(local).Build()
	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}

	if err := b.SyncCompiledVMs(context.Background()); err != nil {
		t.Fatal(err)
	}
	var list compiledv1.CompiledVMList
	if err := downstream.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 0 {
		t.Fatalf("a retired twin kept its VM running downstream: %+v", list.Items)
	}
}

// launcherOf is a virt-launcher pod as KubeVirt creates it: the fixed launcher label, and owned by
// the VMI it runs.
func launcherOf(vmi string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default", Name: "virt-launcher-" + vmi + "-x",
		Labels: map[string]string{"kubevirt.io": "virt-launcher"},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "kubevirt.io/v1", Kind: "VirtualMachineInstance", Name: vmi, UID: types.UID("uid-" + vmi),
		}},
	}}
}

// The released patch is optimistic-locked, and a conflict (the twin changed under a stale read)
// leaves that twin pending for the next pass without stopping the others.
func TestReportReleases_ConflictIsPendingAndLocked(t *testing.T) {
	s := releaseScheme(t)
	a, b2 := retiredTwinOf("a"), retiredTwinOf("b")
	var patches []string
	dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(a, b2).WithStatusSubresource(a, b2).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				data, err := patch.Data(obj)
				if err != nil {
					return err
				}
				patches = append(patches, string(data))
				if obj.GetName() == a.Name {
					return apierrors.NewConflict(schema.GroupResource{Group: "compiled.ectobase.dev", Resource: "compiledvms"}, obj.GetName(), errors.New("changed"))
				}
				return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
			},
		}).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).Build()
	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}

	pending, err := b.ReportReleases(context.Background())
	if err != nil {
		t.Fatalf("a conflict must not fail the pass: %v", err)
	}
	if !pending {
		t.Fatal("a conflicted release must stay pending")
	}
	if releasedOf(t, dispatch, "a") || !releasedOf(t, dispatch, "b") {
		t.Fatalf("want a unreleased (conflict) and b released, got a=%v b=%v",
			releasedOf(t, dispatch, "a"), releasedOf(t, dispatch, "b"))
	}
	for _, p := range patches {
		if !strings.Contains(p, `"resourceVersion"`) {
			t.Fatalf("released patch is not optimistic-locked: %s", p)
		}
	}
}

// One twin that cannot be checked must not stall the release of every other twin on the pool.
func TestReportReleases_OneBadTwinDoesNotStarveOthers(t *testing.T) {
	s := releaseScheme(t)
	a, b2 := retiredTwinOf("a"), retiredTwinOf("b")
	dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(a, b2).WithStatusSubresource(a, b2).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if key.Name == a.Name {
				return errors.New("apiserver unavailable")
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}).Build()
	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}

	pending, err := b.ReportReleases(context.Background())
	if err == nil {
		t.Fatal("want the bad twin's error reported")
	}
	if !pending {
		t.Fatal("the bad twin must stay pending")
	}
	if releasedOf(t, dispatch, "a") || !releasedOf(t, dispatch, "b") {
		t.Fatalf("want a unreleased and b released, got a=%v b=%v",
			releasedOf(t, dispatch, "a"), releasedOf(t, dispatch, "b"))
	}
}
