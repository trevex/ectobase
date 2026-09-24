// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// cephPV is a PersistentVolume shaped like one ceph-csi actually provisions, values taken from a
// live lab PV so the stripping rule is tested against the real thing rather than an invention.
func cephPV(name string, policy corev1.PersistentVolumeReclaimPolicy) *corev1.PersistentVolume {
	block := corev1.PersistentVolumeBlock
	return &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			AccessModes:                   []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Capacity:                      corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")},
			VolumeMode:                    &block,
			PersistentVolumeReclaimPolicy: policy,
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "rbd.csi.ceph.com",
					VolumeHandle: "0001-0024-06022bce-a323-4618-a1a3-7cbffc48b99f-0000000000000002-0760cb9a-69f0-45c1-891b-666b376c9646",
					VolumeAttributes: map[string]string{
						"clusterID":     "06022bce-a323-4618-a1a3-7cbffc48b99f",
						"imageName":     "csi-vol-0760cb9a-69f0-45c1-891b-666b376c9646",
						"imageFeatures": "layering",
						"journalPool":   "replicapool",
						"pool":          "replicapool",
						"mapOptions":    "ms_mode=prefer-crc",
						// Provisioner bookkeeping that must NOT be replayed.
						"storage.kubernetes.io/csiProvisionerIdentity": "1790275620928-2111-rbd.csi.ceph.com",
						"csi.storage.k8s.io/pv/name":                   "pvc-old",
						"csi.storage.k8s.io/pvc/name":                  "old-claim",
						"csi.storage.k8s.io/pvc/namespace":             "old-ns",
					},
					NodeStageSecretRef:        &corev1.SecretReference{Name: "csi-rbd-secret", Namespace: "ceph-csi"},
					ControllerExpandSecretRef: &corev1.SecretReference{Name: "csi-rbd-secret", Namespace: "ceph-csi"},
				},
			},
		},
	}
}

// TestDiskIdentityFromPV_KeepsTheDriversFactsAndDropsItsBookkeeping pins the one judgement call in
// capturing an identity: which volumeAttributes survive into a replayed PV.
//
// The driver's own facts (clusterID, pool, imageName, ...) are what make the image findable from
// another cluster and must be kept verbatim. The provisioner's bookkeeping names objects and a
// provisioner instance in the cluster the disk came FROM, so replaying it points ceph-csi at the
// wrong names.
func TestDiskIdentityFromPV_KeepsTheDriversFactsAndDropsItsBookkeeping(t *testing.T) {
	id := diskIdentityFromPV(cephPV("pvc-1", corev1.PersistentVolumeReclaimDelete))
	if id == nil || id.CSI == nil {
		t.Fatalf("no identity captured: %+v", id)
	}
	if id.CSI.Driver != "rbd.csi.ceph.com" {
		t.Fatalf("driver: %q", id.CSI.Driver)
	}
	if got, want := id.CSI.VolumeHandle, "0001-0024-06022bce-a323-4618-a1a3-7cbffc48b99f-0000000000000002-0760cb9a-69f0-45c1-891b-666b376c9646"; got != want {
		t.Fatalf("volumeHandle: %q", got)
	}
	// The facts that let another cluster find the image.
	for k, want := range map[string]string{
		"clusterID":     "06022bce-a323-4618-a1a3-7cbffc48b99f",
		"imageName":     "csi-vol-0760cb9a-69f0-45c1-891b-666b376c9646",
		"pool":          "replicapool",
		"journalPool":   "replicapool",
		"imageFeatures": "layering",
		"mapOptions":    "ms_mode=prefer-crc",
	} {
		if got := id.CSI.VolumeAttributes[k]; got != want {
			t.Errorf("volumeAttributes[%q] = %q, want %q (a driver fact must survive)", k, got, want)
		}
	}
	// The bookkeeping that must not be replayed.
	for _, k := range []string{
		"storage.kubernetes.io/csiProvisionerIdentity",
		"csi.storage.k8s.io/pv/name",
		"csi.storage.k8s.io/pvc/name",
		"csi.storage.k8s.io/pvc/namespace",
	} {
		if v, ok := id.CSI.VolumeAttributes[k]; ok {
			t.Errorf("volumeAttributes[%q] = %q, want it dropped: it names the source cluster", k, v)
		}
	}
	// Secret refs must survive: ceph-csi is deployed per cluster from one template, so the same
	// name/namespace resolves in the target, and a PV without them fails at NodeStage.
	if id.CSI.NodeStageSecretRef == nil || id.CSI.NodeStageSecretRef.Name != "csi-rbd-secret" {
		t.Errorf("nodeStageSecretRef: %+v", id.CSI.NodeStageSecretRef)
	}
	if id.Capacity.Cmp(resource.MustParse("1Gi")) != 0 {
		t.Errorf("capacity = %v, want the PV's actual 1Gi", id.Capacity)
	}
}

// TestDiskIdentityFromPV_DoesNotMutateThePV guards against capturing by reference: the attribute map
// is shared with the live object, so stripping in place would edit the PV we are reading.
func TestDiskIdentityFromPV_DoesNotMutateThePV(t *testing.T) {
	pv := cephPV("pvc-1", corev1.PersistentVolumeReclaimDelete)
	_ = diskIdentityFromPV(pv)
	if _, ok := pv.Spec.CSI.VolumeAttributes["csi.storage.k8s.io/pv/name"]; !ok {
		t.Fatal("capturing the identity stripped attributes from the PV itself")
	}
}

func startDiskIdentityEnv(t *testing.T) (client.Client, context.Context) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}
	scheme := runtime.NewScheme()
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "charts", "ectobase-pool", "crd-bases"),
			filepath.Join("..", "..", "test", "crds"),
		},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return c, context.Background()
}

// bindDisk creates the PV/PVC pair an attachment's disk would have, already Bound. envtest runs no
// PV controller, so the binding is written directly.
func bindDisk(t *testing.T, ctx context.Context, c client.Client, att, pvName string, phase corev1.PersistentVolumeClaimPhase, policy corev1.PersistentVolumeReclaimPolicy) {
	t.Helper()
	pv := cephPV(pvName, policy)
	if err := c.Create(ctx, pv); err != nil {
		t.Fatalf("create pv: %v", err)
	}
	block := corev1.PersistentVolumeBlock
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: att},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			VolumeMode:  &block,
			VolumeName:  pvName,
			Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}},
		},
	}
	if err := c.Create(ctx, pvc); err != nil {
		t.Fatalf("create pvc: %v", err)
	}
	pvc.Status.Phase = phase
	if err := c.Status().Update(ctx, pvc); err != nil {
		t.Fatalf("set pvc phase: %v", err)
	}
}

func newAttachment(t *testing.T, ctx context.Context, c client.Client, name string) {
	t.Helper()
	cva := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
		Spec: compiledv1.CompiledVolumeAttachmentSpec{
			ClusterName: "c1",
			Size:        resource.MustParse("1Gi"),
			VolumeRef:   "disk",
		},
	}
	if err := c.Create(ctx, cva); err != nil {
		t.Fatalf("create cva: %v", err)
	}
}

// TestDiskIdentity_RetainsThePVAndRecordsTheIdentity is the core of making a rebind survivable.
//
// A dynamically provisioned PV inherits the StorageClass's reclaimPolicy, which is Delete, so the
// RBD image dies with its PVC — including when a clusterName change prunes the attachment and
// cascades into the DataVolume that owns the PVC. Flipping the PV to Retain is what turns that
// deletion from destruction into a detach, and recording the identity is what lets the next cluster
// find the image again.
func TestDiskIdentity_RetainsThePVAndRecordsTheIdentity(t *testing.T) {
	c, ctx := startDiskIdentityEnv(t)
	newAttachment(t, ctx, c, "vm1-disk")
	bindDisk(t, ctx, c, "vm1-disk", "pvc-1", corev1.ClaimBound, corev1.PersistentVolumeReclaimDelete)

	r := &DiskIdentityReconciler{Client: c}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "vm1-disk"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var pv corev1.PersistentVolume
	if err := c.Get(ctx, client.ObjectKey{Name: "pvc-1"}, &pv); err != nil {
		t.Fatalf("get pv: %v", err)
	}
	if pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain {
		t.Errorf("reclaimPolicy = %q, want Retain — otherwise a rebind destroys the image",
			pv.Spec.PersistentVolumeReclaimPolicy)
	}

	var cva compiledv1.CompiledVolumeAttachment
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "vm1-disk"}, &cva); err != nil {
		t.Fatalf("get cva: %v", err)
	}
	id := cva.Status.DiskIdentity
	if id == nil || id.CSI == nil {
		t.Fatalf("status.diskIdentity not recorded: %+v", cva.Status)
	}
	if id.CSI.VolumeAttributes["imageName"] != "csi-vol-0760cb9a-69f0-45c1-891b-666b376c9646" {
		t.Errorf("recorded imageName: %q", id.CSI.VolumeAttributes["imageName"])
	}

	// Idempotent: nothing to change on a second pass.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "vm1-disk"}}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
}

// TestDiskIdentity_WaitsForTheDiskToBeBound is the readiness rule, and it is deliberately the
// attachment's OWN PVC rather than anything CDI-shaped.
//
// CDI populates a block DataVolume through a "prime" PVC and rebinds that PV onto the named target
// PVC once the import completes, so "the attachment's PVC is Bound" IS "the disk is fully written",
// without this controller knowing anything about importers. Capturing earlier would publish the
// identity of a half-imported disk, and a move in that window would adopt partial data.
func TestDiskIdentity_WaitsForTheDiskToBeBound(t *testing.T) {
	c, ctx := startDiskIdentityEnv(t)
	newAttachment(t, ctx, c, "vm2-disk")
	bindDisk(t, ctx, c, "vm2-disk", "pvc-2", corev1.ClaimPending, corev1.PersistentVolumeReclaimDelete)

	r := &DiskIdentityReconciler{Client: c}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "vm2-disk"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var cva compiledv1.CompiledVolumeAttachment
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "vm2-disk"}, &cva); err != nil {
		t.Fatalf("get cva: %v", err)
	}
	if cva.Status.DiskIdentity != nil {
		t.Errorf("recorded an identity for a disk that is not Bound yet: %+v", cva.Status.DiskIdentity)
	}
	var pv corev1.PersistentVolume
	if err := c.Get(ctx, client.ObjectKey{Name: "pvc-2"}, &pv); err != nil {
		t.Fatalf("get pv: %v", err)
	}
	if pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimDelete {
		t.Errorf("reclaimPolicy = %q on an unbound disk, want it left alone",
			pv.Spec.PersistentVolumeReclaimPolicy)
	}
}
