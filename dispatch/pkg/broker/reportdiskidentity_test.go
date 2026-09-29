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
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
)

func diskIdentityScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func identity(image string) *compiledv1.DiskIdentity {
	return &compiledv1.DiskIdentity{
		CSI: &corev1.CSIPersistentVolumeSource{
			Driver:           "rbd.csi.ceph.com",
			VolumeHandle:     "0001-0024-fsid-0000000000000002-" + image,
			VolumeAttributes: map[string]string{"imageName": "csi-vol-" + image, "pool": "replicapool"},
		},
		Capacity: resource.MustParse("1Gi"),
	}
}

// attachmentPair is the same attachment as it exists on both sides: downstream in the SOURCE
// namespace (where the broker mirrors twins) and on the dispatch in this pool's namespace.
func attachmentPair(name string, downstreamIdentity *compiledv1.DiskIdentity) (downstream, dispatch *compiledv1.CompiledVolumeAttachment) {
	downstream = &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "default",
			Name:        name,
			Annotations: map[string]string{compiledv1.SourceNamespaceAnnotation: "default"},
		},
		Status: compiledv1.CompiledVolumeAttachmentStatus{DiskIdentity: downstreamIdentity},
	}
	dispatch = &compiledv1.CompiledVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: validate.PoolNamespace("c1"), Name: name},
	}
	return downstream, dispatch
}

// TestReportDiskIdentities_CarriesTheIdentityUpward is the hop that gets a provisioned disk's
// identity out of the pool that provisioned it and onto the dispatch, where it can outlive the
// attachment and be stamped into the next one.
func TestReportDiskIdentities_CarriesTheIdentityUpward(t *testing.T) {
	s := diskIdentityScheme(t)
	down, disp := attachmentPair("default-vm1-disk", identity("aaaa"))

	downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(down).WithStatusSubresource(down).Build()
	dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(disp).WithStatusSubresource(disp).Build()

	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
	if err := b.ReportDiskIdentities(context.Background()); err != nil {
		t.Fatalf("report: %v", err)
	}

	var got compiledv1.CompiledVolumeAttachment
	if err := dispatch.Get(context.Background(),
		client.ObjectKey{Namespace: validate.PoolNamespace("c1"), Name: "default-vm1-disk"}, &got); err != nil {
		t.Fatalf("get dispatch attachment: %v", err)
	}
	if got.Status.DiskIdentity == nil || got.Status.DiskIdentity.CSI == nil {
		t.Fatalf("identity not reported upward: %+v", got.Status)
	}
	if want := "csi-vol-aaaa"; got.Status.DiskIdentity.CSI.VolumeAttributes["imageName"] != want {
		t.Errorf("imageName = %q, want %q", got.Status.DiskIdentity.CSI.VolumeAttributes["imageName"], want)
	}
}

// TestReportDiskIdentities_SkipsAttachmentsTheDispatchDoesNotOwn keeps a pool from inventing
// attachments: a downstream object with no dispatch counterpart is not ours to report on, and must
// not be an error either, since the downstream list is a superset.
func TestReportDiskIdentities_SkipsAttachmentsTheDispatchDoesNotOwn(t *testing.T) {
	s := diskIdentityScheme(t)
	orphan, _ := attachmentPair("stray-disk", identity("bbbb"))

	downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(orphan).WithStatusSubresource(orphan).Build()
	dispatch := fake.NewClientBuilder().WithScheme(s).Build()

	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
	if err := b.ReportDiskIdentities(context.Background()); err != nil {
		t.Fatalf("an unowned downstream attachment must be skipped, not fail: %v", err)
	}
}

// TestReportDiskIdentities_IsAWriteFreeNoOpWhenConverged matters because this runs on every tick:
// re-patching an unchanged identity would churn resourceVersion on every attachment forever and
// wake every watcher of it.
func TestReportDiskIdentities_IsAWriteFreeNoOpWhenConverged(t *testing.T) {
	s := diskIdentityScheme(t)
	down, disp := attachmentPair("default-vm1-disk", identity("aaaa"))
	disp.Status.DiskIdentity = identity("aaaa") // already carried up

	downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(down).WithStatusSubresource(down).Build()
	var patches int
	dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(disp).WithStatusSubresource(disp).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				patches++
				return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
			},
		}).Build()

	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
	if err := b.ReportDiskIdentities(context.Background()); err != nil {
		t.Fatalf("report: %v", err)
	}
	if patches != 0 {
		t.Errorf("patched %d times on a converged state, want 0", patches)
	}
}

// TestReportDiskIdentities_ReturnsWriteFailures is the one place this must differ from the placement
// report beside it, which deliberately swallows errors. A dropped placement is a stale field that
// the next tick fixes. A dropped identity is the only record of which image holds the data, and if
// it never reaches the dispatch a later rebind provisions a blank disk instead — so the tick has to
// know it failed and retry.
func TestReportDiskIdentities_ReturnsWriteFailures(t *testing.T) {
	s := diskIdentityScheme(t)
	down, disp := attachmentPair("default-vm1-disk", identity("aaaa"))

	downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(down).WithStatusSubresource(down).Build()
	dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(disp).WithStatusSubresource(disp).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				return errors.New("the dispatch said no")
			},
		}).Build()

	b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}
	if err := b.ReportDiskIdentities(context.Background()); err == nil {
		t.Fatal("a failed identity write must surface, or the disk's only record is lost silently")
	}
}
