// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestBuildDataVolume_Boot(t *testing.T) {
	cva := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1-boot", Labels: map[string]string{"workload": "vm1"}},
		Spec:       compiledv1.CompiledVolumeAttachmentSpec{Size: resource.MustParse("10Gi"), StorageClass: "ceph-rbd", BootImage: "quay.io/containerdisks/fedora:41", Boot: true},
	}
	dv := buildDataVolume(cva)
	if dv.Name != "vm1-boot" || dv.Namespace != "ns" {
		t.Fatalf("meta: %s/%s", dv.Namespace, dv.Name)
	}
	if dv.Spec.Source == nil || dv.Spec.Source.Registry == nil || dv.Spec.Source.Registry.URL == nil || *dv.Spec.Source.Registry.URL != "docker://quay.io/containerdisks/fedora:41" {
		t.Fatalf("source: %+v", dv.Spec.Source)
	}
	if dv.Spec.Storage == nil || dv.Spec.Storage.StorageClassName == nil || *dv.Spec.Storage.StorageClassName != "ceph-rbd" {
		t.Fatalf("storageClass: %+v", dv.Spec.Storage)
	}
	if dv.Spec.Storage.Resources.Requests.Storage().Cmp(resource.MustParse("10Gi")) != 0 {
		t.Fatalf("size: %v", dv.Spec.Storage.Resources.Requests.Storage())
	}
	if len(dv.Spec.Storage.AccessModes) != 1 || dv.Spec.Storage.AccessModes[0] != corev1.ReadWriteOnce {
		t.Fatalf("access: %+v", dv.Spec.Storage.AccessModes)
	}
	// The workload label is the VM<->attachment join key the VMMaterializer uses.
	if dv.Labels["workload"] != "vm1" {
		t.Fatalf("workload label: %v", dv.Labels)
	}
}

func TestBuildDataVolume_Blank(t *testing.T) {
	cva := &compiledv1.CompiledVolumeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "vm1-data"}, Spec: compiledv1.CompiledVolumeAttachmentSpec{Size: resource.MustParse("5Gi")}}
	dv := buildDataVolume(cva)
	if dv.Spec.Source == nil || dv.Spec.Source.Blank == nil {
		t.Fatalf("expected blank source, got %+v", dv.Spec.Source)
	}
	if dv.Spec.Storage.StorageClassName != nil {
		t.Fatalf("expected default storageClass (nil), got %v", *dv.Spec.Storage.StorageClassName)
	}
}

// TestVolumeMaterializer_CreatesDataVolume runs the reconciler against a real downstream
// apiserver with the CompiledVolumeAttachment CRD and the CDI DataVolume CRD installed, and
// asserts the reconciler materializes a DataVolume with the right source/storageClass/size.
func TestVolumeMaterializer_CreatesDataVolume(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}

	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := cdiv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			kubeVirtCRDPath(),
		},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	defer func() { _ = env.Stop() }()

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx := context.Background()

	cva := &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm1-boot", Labels: map[string]string{"workload": "vm1"}},
		Spec: compiledv1.CompiledVolumeAttachmentSpec{
			ClusterName:  "cluster-a",
			Size:         resource.MustParse("10Gi"),
			StorageClass: "ceph-rbd",
			BootImage:    "quay.io/containerdisks/fedora:41",
			Boot:         true,
		},
	}
	if err := c.Create(ctx, cva); err != nil {
		t.Fatalf("create compiledvolumeattachment: %v", err)
	}

	r := &VolumeMaterializerReconciler{Client: c}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "vm1-boot"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var dv cdiv1.DataVolume
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "vm1-boot"}, &dv); err != nil {
		t.Fatalf("get materialized datavolume: %v", err)
	}
	if dv.Spec.Source == nil || dv.Spec.Source.Registry == nil || dv.Spec.Source.Registry.URL == nil || *dv.Spec.Source.Registry.URL != "docker://quay.io/containerdisks/fedora:41" {
		t.Fatalf("source: %+v", dv.Spec.Source)
	}
	if dv.Spec.Storage == nil || dv.Spec.Storage.StorageClassName == nil || *dv.Spec.Storage.StorageClassName != "ceph-rbd" {
		t.Fatalf("storageClass: %+v", dv.Spec.Storage)
	}
	if dv.Spec.Storage.Resources.Requests.Storage().Cmp(resource.MustParse("10Gi")) != 0 {
		t.Fatalf("size: %v", dv.Spec.Storage.Resources.Requests.Storage())
	}

	// Idempotent: a second reconcile must not error and must not duplicate.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "vm1-boot"}}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
}
