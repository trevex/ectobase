// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"context"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
	"github.com/trevex/ectobase/mesh/controllers"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestVolumeMove_IdentityFollowsAClusterRebind_E2E is the control-plane proof of Phase 0, against
// the real aggregated apiserver rather than a fake client.
//
// It asserts the property the whole design exists for: when a VM's spec.clusterName changes, the
// attachment compiled into the NEW pool namespace carries the SAME disk identity the old one had. If
// it does not, the target cluster provisions a blank image and the data is gone — which is what
// happened before Phase 0, reproduced live on 2026-09-24 with the RBD image vanishing from Ceph.
//
// Note what this deliberately exercises about the compiler's ordering: the attachment reconciler
// DELETES the old twin before creating the new one, in a single pass. For a ReadWriteOnce block
// device that is the correct order — it is what stops two clusters attaching one image — so Phase 0
// does not reorder it. It makes the deletion non-destructive instead, and the identity that survives
// the delete comes from the Volume, which has no cluster.
func TestVolumeMove_IdentityFollowsAClusterRebind_E2E(t *testing.T) {
	c, ctx := startNetEnv(t)

	const ns = "default"
	mustHaveNamespaces(t, ctx, c, validate.PoolNamespace("c1"), validate.PoolNamespace("c2"))

	vol := &storagev1.Volume{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "disk"},
		Spec:       storagev1.VolumeSpec{Size: resource.MustParse("1Gi"), StorageClass: "ceph-rbd"},
	}
	if err := c.Create(ctx, vol); err != nil {
		t.Fatalf("create volume: %v", err)
	}
	vm := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm1"},
		Spec: computev1.VirtualMachineSpec{
			ClusterName: "c1",
			VolumeRefs:  []computev1.LocalObjectReference{{Name: "disk"}},
		},
	}
	if err := c.Create(ctx, vm); err != nil {
		t.Fatalf("create vm: %v", err)
	}

	att := &controllers.CompiledVolumeAttachmentReconciler{Client: c}
	vmKey := client.ObjectKey{Namespace: ns, Name: "vm1"}

	// 1. First compile: nothing has been provisioned, so there is nothing to adopt.
	if _, err := att.Reconcile(ctx, ctrl.Request{NamespacedName: vmKey}); err != nil {
		t.Fatalf("compile into c1: %v", err)
	}
	first := client.ObjectKey{Namespace: validate.PoolNamespace("c1"), Name: "default-vm1-disk"}
	var cva compiledv1.CompiledVolumeAttachment
	if err := c.Get(ctx, first, &cva); err != nil {
		t.Fatalf("attachment not compiled into c1: %v", err)
	}
	if cva.Spec.DiskIdentity != nil {
		t.Fatalf("claimed a disk before one existed: %+v", cva.Spec.DiskIdentity)
	}
	if cva.Spec.VolumeRef != "disk" {
		t.Fatalf("volumeRef = %q, want disk", cva.Spec.VolumeRef)
	}

	// 2. The pool provisions the disk and reports its identity. Downstream that is the
	//    DiskIdentityReconciler and the broker; here the reported result is written directly, since
	//    what is under test is what the DISPATCH does with it.
	const handle = "0001-0024-fsid-0000000000000002-aaaa"
	orig := cva.DeepCopy()
	cva.Status.DiskIdentity = &compiledv1.DiskIdentity{
		CSI: &corev1.CSIPersistentVolumeSource{
			Driver:           "rbd.csi.ceph.com",
			VolumeHandle:     handle,
			VolumeAttributes: map[string]string{"imageName": "csi-vol-aaaa", "pool": "replicapool"},
		},
		Capacity: resource.MustParse("1Gi"),
	}
	if err := c.Status().Patch(ctx, &cva, client.MergeFrom(orig)); err != nil {
		t.Fatalf("report identity: %v", err)
	}

	// 3. The mirror carries it onto the Volume — the only object in this story with no cluster, and
	//    therefore the only one that can outlive the move.
	mirror := &controllers.DiskIdentityMirrorReconciler{Client: c}
	if _, err := mirror.Reconcile(ctx, ctrl.Request{NamespacedName: first}); err != nil {
		t.Fatalf("mirror: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "disk"}, vol); err != nil {
		t.Fatalf("get volume: %v", err)
	}
	if vol.Status.DiskIdentity == nil || vol.Status.DiskIdentity.CSI.VolumeHandle != handle {
		t.Fatalf("identity did not reach the Volume: %+v", vol.Status.DiskIdentity)
	}

	// 4. THE MOVE. Exactly what Tier-2 failover does (failover.go) and what a planned drain does.
	if err := c.Get(ctx, vmKey, vm); err != nil {
		t.Fatalf("get vm: %v", err)
	}
	vm.Spec.ClusterName = "c2"
	if err := c.Update(ctx, vm); err != nil {
		t.Fatalf("rebind vm to c2: %v", err)
	}
	if _, err := att.Reconcile(ctx, ctrl.Request{NamespacedName: vmKey}); err != nil {
		t.Fatalf("compile into c2: %v", err)
	}

	// 5. THE POINT: the attachment in the new pool must name the same disk.
	second := client.ObjectKey{Namespace: validate.PoolNamespace("c2"), Name: "default-vm1-disk"}
	var moved compiledv1.CompiledVolumeAttachment
	if err := c.Get(ctx, second, &moved); err != nil {
		t.Fatalf("attachment not compiled into c2: %v", err)
	}
	if moved.Spec.DiskIdentity == nil || moved.Spec.DiskIdentity.CSI == nil {
		t.Fatalf("the moved attachment carries no disk, so c2 would provision a blank one: %+v", moved.Spec)
	}
	if got := moved.Spec.DiskIdentity.CSI.VolumeHandle; got != handle {
		t.Errorf("moved attachment names disk %q, want the original %q", got, handle)
	}
	if got := moved.Spec.DiskIdentity.CSI.VolumeAttributes["imageName"]; got != "csi-vol-aaaa" {
		t.Errorf("moved attachment names image %q, want csi-vol-aaaa", got)
	}

	// And the old pool's attachment is gone, so the source cluster releases the disk rather than
	// holding a ReadWriteOnce claim on an image c2 is adopting.
	if err := c.Get(ctx, first, &cva); !apierrors.IsNotFound(err) {
		t.Errorf("the c1 attachment outlived the move: %v", err)
	}
}

// mustHaveNamespaces creates the per-pool namespaces a compiler writes twins into. The dispatch
// apiserver enforces NamespaceLifecycle, so a twin cannot be created in a namespace that is absent.
func mustHaveNamespaces(t *testing.T, ctx context.Context, c client.Client, names ...string) {
	t.Helper()
	for _, n := range names {
		nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}
		if err := c.Create(ctx, nsObj); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("create namespace %s: %v", n, err)
		}
	}
}
