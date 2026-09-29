// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"os"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubevirtv1 "kubevirt.io/api/core/v1"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// TestSetupWithManager_VMMaterializerControllersCoexist registers every controller the
// vm-materializer binary runs into ONE manager, exactly as main() does.
//
// It exists because two real bugs shipped through a gap these tests had: the disk-identity
// controller collided with the volume-materializer's default controller name ("controller with name
// compiledvolumeattachment already exists"), which crash-looped the whole binary so no disk was ever
// materialized; and corev1 was missing from the binary's scheme, so every PersistentVolume call
// would have failed at runtime with "no kind is registered".
//
// Neither was visible to a test that calls Reconcile directly, because neither is about reconcile
// logic — they are about WIRING. Controller names and scheme registration are only checked when
// something actually builds a manager, so this test builds one.
//
// There is deliberately only ONE test of this shape in this package, and a second one must not be
// added. controller-runtime keeps its used-name set in a package-level global (pkg/controller/name.go
// `usedNames`), so names are unique per PROCESS rather than per manager: a second test registering
// another binary's controllers would collide with the names this one claimed and fail for a reason
// that has nothing to do with the code. It also means a test registering every binary's controllers
// together would be wrong — the dispatch controller legitimately uses the name
// "compiledvolumeattachment" that the volume-materializer defaults to, and they never share a
// process. The dispatch binary's own controllers are each given an explicit distinct Named().
func TestSetupWithManager_VMMaterializerControllersCoexist(t *testing.T) {
	mgr := newManagerLikeVMMaterializer(t)

	// Same order and same set as mesh/cmd/vm-materializer/main.go.
	if err := (&VMMaterializerReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("vm-materializer: %v", err)
	}
	if err := (&VolumeMaterializerReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("volume-materializer: %v", err)
	}
	if err := (&DiskIdentityReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("disk-identity: %v — two controllers in one manager may not share a name, and the "+
			"default name is derived from the watched kind", err)
	}
}

// newManagerLikeVMMaterializer builds a manager whose scheme is the union of what the binaries
// register. A type missing here is a type that would fail at runtime with "no kind is registered".
func newManagerLikeVMMaterializer(t *testing.T) ctrl.Manager {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		compiledv1.AddToScheme, computev1.AddToScheme, netv1.AddToScheme,
		storagev1.AddToScheme, corev1.AddToScheme, kubevirtv1.AddToScheme, cdiv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	// A manager needs a rest.Config. envtest supplies a real one; ctrl.GetConfig() would reach for
	// the developer's own kubeconfig, which is not what this asserts against.
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}
	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return mgr
}
