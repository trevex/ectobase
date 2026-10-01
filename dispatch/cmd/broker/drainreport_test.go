// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	platforminstall "github.com/trevex/ectobase/api/platform/install"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// The drain report is what central releases a fence on, so not knowing where VMIs run must never
// read as "nothing runs here". Only KubeVirt being absent from the downstream is an empty set; any
// other failure to list VMIs leaves the stored report as it is.

var kubevirtV1 = schema.GroupVersion{Group: "kubevirt.io", Version: "v1"}

func TestKubevirtAbsent(t *testing.T) {
	notFound := apierrors.NewNotFound(schema.GroupResource{Group: "kubevirt.io"}, "v1")
	unavailable := apierrors.NewServiceUnavailable("discovery for kubevirt.io/v1 timed out")
	discovery := func(errs map[schema.GroupVersion]error) error {
		e := apiutil.ErrResourceDiscoveryFailed(errs)
		return &e
	}
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		// The lazy RESTMapper's answer when the kubevirt.io group does not exist at all.
		"no kind match": {&meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "kubevirt.io", Kind: "VirtualMachineInstance"}}, true},
		// Its answer when discovery of the group version 404s or comes back empty.
		"discovery not found": {discovery(map[schema.GroupVersion]error{kubevirtV1: notFound}), true},
		"discovery no resource match": {discovery(map[schema.GroupVersion]error{
			kubevirtV1: &meta.NoResourceMatchError{PartialResource: kubevirtV1.WithResource("")}}), true},
		"wrapped no kind match": {fmt.Errorf("list: %w", &meta.NoKindMatchError{}), true},
		// Discovery that failed for another reason says nothing about whether KubeVirt is there.
		"discovery unavailable": {discovery(map[schema.GroupVersion]error{kubevirtV1: unavailable}), false},
		"discovery partly unavailable": {discovery(map[schema.GroupVersion]error{
			kubevirtV1: notFound, {Group: "kubevirt.io", Version: "v1alpha3"}: unavailable}), false},
		"forbidden":     {apierrors.NewForbidden(schema.GroupResource{Group: "kubevirt.io", Resource: "virtualmachineinstances"}, "", errors.New("rbac")), false},
		"timeout":       {apierrors.NewTimeoutError("list", 1), false},
		"plain failure": {errors.New("connection refused"), false},
	} {
		if got := kubevirtAbsent(tc.err); got != tc.want {
			t.Errorf("%s: kubevirtAbsent = %v, want %v", name, got, tc.want)
		}
	}
}

const (
	drainPrefix1 = "2001:db8:0:1::/64"
	drainPrefix2 = "2001:db8:0:2::/64"
)

// drainReporter is a statusReporter over fake clients whose VMI list fails with listErr (nil:
// lists nothing). The pool has both /64s fenced, with prefix1 stored not drained and prefix2
// drained, and each /64 has one node.
func drainReporter(t *testing.T, listErr error) (*statusReporter, client.Client) {
	t.Helper()
	s := runtime.NewScheme()
	if err := platforminstall.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	pool := &platformv1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{Name: "c1"},
		Status: platformv1.ClusterPoolStatus{
			FencedPrefixes: []string{drainPrefix1, drainPrefix2},
			NodeDrain: []platformv1.NodeDrainStatus{
				{Prefix: drainPrefix1, Drained: false},
				{Prefix: drainPrefix2, Drained: true},
			},
		},
	}
	dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(pool).WithStatusSubresource(pool).Build()
	node := func(name, prefix string) *corev1.Node {
		return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name,
			Annotations: map[string]string{netv1.NodeUnderlayPrefixAnnotation: prefix}}}
	}
	downstream := fake.NewClientBuilder().WithScheme(s).
		WithObjects(node("n1", drainPrefix1), node("n2", drainPrefix2)).
		WithInterceptorFuncs(interceptor.Funcs{List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if u, ok := list.(*unstructured.UnstructuredList); ok && u.GroupVersionKind().Group == "kubevirt.io" {
				return listErr
			}
			return cl.List(ctx, list, opts...)
		}}).Build()
	return &statusReporter{dispatch: dispatch, pools: dispatch, downstream: downstream, clusterName: "c1"}, dispatch
}

func storedDrain(t *testing.T, c client.Client) map[string]bool {
	t.Helper()
	var pool platformv1.ClusterPool
	if err := c.Get(context.Background(), client.ObjectKey{Name: "c1"}, &pool); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, d := range pool.Status.NodeDrain {
		out[d.Prefix] = d.Drained
	}
	return out
}

// A failed VMI list leaves NodeDrain exactly as stored: the not-drained /64 must not flip to
// drained, and the drained one must not flip either. The rest of the report still goes out.
func TestReportOnce_VMIListFailureLeavesTheDrainReportAlone(t *testing.T) {
	for name, listErr := range map[string]error{
		"plain failure":         errors.New("connection refused"),
		"discovery unavailable": apierrors.NewServiceUnavailable("kubevirt.io/v1 discovery"),
	} {
		t.Run(name, func(t *testing.T) {
			s, dispatch := drainReporter(t, listErr)
			_ = s.reportOnce(context.Background())
			got := storedDrain(t, dispatch)
			if got[drainPrefix1] || !got[drainPrefix2] {
				t.Fatalf("a failed VMI list must leave NodeDrain as stored ({%s:false %s:true}), got %v",
					drainPrefix1, drainPrefix2, got)
			}
			var pool platformv1.ClusterPool
			_ = dispatch.Get(context.Background(), client.ObjectKey{Name: "c1"}, &pool)
			if len(pool.Status.NodePrefixes) != 2 {
				t.Fatalf("the rest of the report must still be written, NodePrefixes=%v", pool.Status.NodePrefixes)
			}
		})
	}
}

// No KubeVirt on the downstream is an empty set, not a failure: nothing can be running there, so
// every fenced /64 is drained.
func TestReportOnce_NoKubeVirtMeansNothingBusy(t *testing.T) {
	s, dispatch := drainReporter(t, &meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "kubevirt.io", Kind: "VirtualMachineInstance"}})
	if err := s.reportOnce(context.Background()); err != nil {
		t.Fatalf("reportOnce: %v", err)
	}
	if got := storedDrain(t, dispatch); !got[drainPrefix1] || !got[drainPrefix2] {
		t.Fatalf("with no KubeVirt every fenced /64 is drained, got %v", got)
	}
}

// The shape a real apiserver's client returns for a VMI list without the KubeVirt CRDs installed
// must read as "KubeVirt absent", or every pool without KubeVirt would stop reporting drain.
func TestGatherVMNodes_MissingCRDOnARealAPIServerIsKubeVirtAbsent(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}
	cfg := startCompiledAPIServer(t) // pool CRDs only: no kubevirt.io
	downstream, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	vmis := &unstructured.UnstructuredList{}
	vmis.SetGroupVersionKind(kubevirtV1.WithKind("VirtualMachineInstanceList"))
	listErr := downstream.List(context.Background(), vmis)
	t.Logf("VMI list without the CRD: %T: %v", listErr, listErr)
	if !kubevirtAbsent(listErr) {
		t.Fatalf("a missing KubeVirt CRD must read as absent; the client returned %T: %v", listErr, listErr)
	}
	got, err := (&statusReporter{downstream: downstream}).gatherVMNodes(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("no KubeVirt must gather an empty set without error, got %v, %v", got, err)
	}
}
