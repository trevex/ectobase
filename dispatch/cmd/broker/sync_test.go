// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
)

// startCompiledAPIServer starts an apiserver serving the compiled.ectobase.dev types. The broker
// reads them from the dispatch's aggregated apiserver and writes them to a pool's CRDs; to the
// broker both are just the same namespaced API, so the pool CRDs stand in for either side.
func startCompiledAPIServer(t *testing.T) *rest.Config {
	t.Helper()
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "charts", "ectobase-pool", "crd-bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	return cfg
}

// startBroker runs the broker's sync controller for pool clusterName against the dispatch at
// dispatchCfg, the way main wires it, until the test ends.
func startBroker(ctx context.Context, t *testing.T, scheme *runtime.Scheme, dispatchCfg *rest.Config,
	downstream client.Client, clusterName string,
) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	// Every test registers the same "broker" controller in this one process.
	skipNameValidation := true
	mgr, err := ctrl.NewManager(dispatchCfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{
			validate.PoolNamespace(clusterName): {},
		}},
		Controller: config.Controller{SkipNameValidation: &skipNameValidation},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := setupSync(mgr, &brokerReconciler{
		dispatch: mgr.GetClient(), downstream: downstream, clusterName: clusterName,
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
}

// A broker that was down when its pool's last twin was deleted upstream must still prune it when it
// comes back. Nothing in the dispatch pool namespace means no watch event ever fires, so only a sync
// the broker runs of its own accord can see the stranded twin — which is exactly the state a
// Tier-2 failover leaves the source pool in.
func TestSync_StartupPrunesTwinsStrandedWhileDown(t *testing.T) {
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
	dispatchCfg := startCompiledAPIServer(t)
	downstreamCfg := startCompiledAPIServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dispatch, err := client.New(dispatchCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	downstream, err := client.New(downstreamCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	// The pool namespace exists on the dispatch but is empty: its only VM has moved elsewhere.
	const clusterName = "c1"
	poolNS := validate.PoolNamespace(clusterName)
	if err := dispatch.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: poolNS}}); err != nil {
		t.Fatal(err)
	}
	// Downstream still holds the twin it mirrored before it went down.
	if err := downstream.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}}); err != nil {
		t.Fatal(err)
	}
	stranded := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "moved"}}
	if err := downstream.Create(ctx, stranded); err != nil {
		t.Fatal(err)
	}

	startBroker(ctx, t, scheme, dispatchCfg, downstream, clusterName)

	deadline := time.Now().Add(30 * time.Second)
	for {
		err := downstream.Get(ctx, client.ObjectKeyFromObject(stranded), &compiledv1.CompiledVM{})
		if apierrors.IsNotFound(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the stranded CompiledVM survived the broker coming up (last get err=%v)", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// One failing sync must not slow the release check. A move waits on the source pool reporting the
// release, and the downstream teardown it waits for raises no dispatch event, so only the broker's
// own poll notices it is done. Were that poll driven by the same work item as the syncs, a sync that
// keeps failing would put the release check under the item's exponential backoff, and a move would
// wait out minutes of it for a failure that has nothing to do with the VM being moved.
func TestSync_FailingSyncDoesNotSlowReleaseCheck(t *testing.T) {
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
	dispatchCfg := startCompiledAPIServer(t)
	downstreamCfg := startCompiledAPIServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dispatch, err := client.New(dispatchCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	direct, err := client.NewWithWatch(downstreamCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	// Every container the broker tries to mirror is refused: the container sync fails on every
	// pass, for as long as the test runs.
	var containerFailures atomic.Int32
	downstream := interceptor.NewClient(direct, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*compiledv1.CompiledContainer); ok {
				containerFailures.Add(1)
				return errors.New("downstream refuses containers")
			}
			return c.Create(ctx, obj, opts...)
		},
	})

	const clusterName = "c1"
	poolNS := validate.PoolNamespace(clusterName)
	if err := dispatch.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: poolNS}}); err != nil {
		t.Fatal(err)
	}
	ctr := &compiledv1.CompiledContainer{ObjectMeta: metav1.ObjectMeta{
		Namespace: poolNS, Name: "default-ctr", Annotations: map[string]string{
			compiledv1.SourceNamespaceAnnotation: "default",
			compiledv1.SourceNameAnnotation:      "ctr",
		},
	}}
	if err := dispatch.Create(ctx, ctr); err != nil {
		t.Fatal(err)
	}
	// A VM moved away from this pool: its twin is retired, held by the move's finalizer until the
	// pool reports the release.
	twin := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{
		Namespace: poolNS, Name: "default-vm",
		Annotations: map[string]string{
			compiledv1.SourceNamespaceAnnotation: "default",
			compiledv1.SourceNameAnnotation:      "vm",
		},
		Labels:     map[string]string{"workload": "vm"},
		Finalizers: []string{"compiled.ectobase.dev/source-released"},
	}}
	if err := dispatch.Create(ctx, twin); err != nil {
		t.Fatal(err)
	}
	if err := dispatch.Delete(ctx, twin); err != nil {
		t.Fatal(err)
	}
	// The VM's virt-launcher is still shutting down, so the release is pending.
	launcher := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "virt-launcher-default-vm",
			Labels: map[string]string{"kubevirt.io": "virt-launcher"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "kubevirt.io/v1", Kind: "VirtualMachineInstance", Name: "default-vm", UID: "vmi-uid",
			}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "compute", Image: "virt-launcher"}}},
	}
	if err := direct.Create(ctx, launcher); err != nil {
		t.Fatal(err)
	}

	startBroker(ctx, t, scheme, dispatchCfg, downstream, clusterName)

	// Let the container sync fail long enough that a backoff shared with it (5ms, doubling per
	// failure) would have grown well past the release poll: after 12 failures the next retry is
	// 10s away.
	const failures = 12
	deadline := time.Now().Add(30 * time.Second)
	for containerFailures.Load() < failures {
		if time.Now().After(deadline) {
			t.Fatalf("the container sync failed only %d times in 30s", containerFailures.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if isReleased(ctx, t, dispatch, twin) {
		t.Fatal("released while the virt-launcher remained")
	}

	// The teardown finishes. The next release check must see it on the release poll's cadence,
	// not the failing sync's. (An unscheduled pod leaves the API at once; no kubelet is needed.)
	if err := direct.Delete(ctx, launcher); err != nil {
		t.Fatal(err)
	}
	if err := direct.Get(ctx, client.ObjectKeyFromObject(launcher), &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Fatalf("the virt-launcher is still there after its delete (get err=%v)", err)
	}
	within := releasePollInterval + 3*time.Second
	deadline = time.Now().Add(within)
	for !isReleased(ctx, t, dispatch, twin) {
		if time.Now().After(deadline) {
			t.Fatalf("release not reported within %s of the teardown finishing (container sync failures so far: %d)",
				within, containerFailures.Load())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// The two passes fail apart. A failing sync is returned, so the queue retries it with backoff and
// counts it; a release check keeps its poll even when a twin cannot be checked, so one bad retired
// twin does not slow the release of the others.
func TestReconcile_SyncAndReleaseFailApart(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"VirtualMachine", "VirtualMachineInstance"} {
		gv := schema.GroupVersion{Group: "kubevirt.io", Version: "v1"}
		scheme.AddKnownTypeWithName(gv.WithKind(kind), &unstructured.Unstructured{})
		scheme.AddKnownTypeWithName(gv.WithKind(kind+"List"), &unstructured.UnstructuredList{})
	}
	poolNS := validate.PoolNamespace("c1")
	retired := func(vm string) *compiledv1.CompiledVM {
		now := metav1.Now()
		return &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{
			Namespace: poolNS, Name: "default-" + vm, DeletionTimestamp: &now,
			Annotations: map[string]string{
				compiledv1.SourceNamespaceAnnotation: "default",
				compiledv1.SourceNameAnnotation:      vm,
			},
			Finalizers: []string{"compiled.ectobase.dev/source-released"},
		}}
	}
	// "bad" cannot be checked; "free" holds nothing on this pool and can be released.
	bad, free := retired("bad"), retired("free")
	ctr := &compiledv1.CompiledContainer{ObjectMeta: metav1.ObjectMeta{Namespace: poolNS, Name: "default-ctr"}}
	dispatch := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(bad, free, ctr).WithStatusSubresource(bad, free).Build()
	downstream := interceptor.NewClient(fake.NewClientBuilder().WithScheme(scheme).Build(), interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*compiledv1.CompiledContainer); ok {
				return errors.New("downstream refuses containers")
			}
			return c.Create(ctx, obj, opts...)
		},
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if key.Name == bad.Name {
				return errors.New("downstream unreachable for this twin")
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	r := &brokerReconciler{dispatch: dispatch, downstream: downstream, clusterName: "c1"}
	ctx := context.Background()

	if _, err := r.Reconcile(ctx, syncRequest); err == nil || !strings.Contains(err.Error(), "container") {
		t.Fatalf("a failing container sync must fail the sync pass, got err=%v", err)
	}

	res, err := r.Reconcile(ctx, releaseRequest)
	if err != nil || res.RequeueAfter != releasePollInterval {
		t.Fatalf("with a release pending, the release check must poll again in %s whatever failed; got %+v, err=%v",
			releasePollInterval, res, err)
	}
	if !isReleased(ctx, t, dispatch, free) || isReleased(ctx, t, dispatch, bad) {
		t.Fatalf("want only the checkable twin released: free=%v bad=%v",
			isReleased(ctx, t, dispatch, free), isReleased(ctx, t, dispatch, bad))
	}
}

// The sync and the release check must never run at once: a release reported between a sync's read
// of a live twin and its create would let two pools run the VM. The controller states its single
// worker itself, so a manager-wide concurrency default cannot override it.
func TestBrokerController_OneWorker(t *testing.T) {
	if n := brokerControllerOptions().MaxConcurrentReconciles; n != 1 {
		t.Fatalf("MaxConcurrentReconciles = %d, want 1", n)
	}
}

func isReleased(ctx context.Context, t *testing.T, c client.Client, twin *compiledv1.CompiledVM) bool {
	t.Helper()
	var got compiledv1.CompiledVM
	if err := c.Get(ctx, client.ObjectKeyFromObject(twin), &got); err != nil {
		t.Fatal(err)
	}
	return got.Status.Released
}
