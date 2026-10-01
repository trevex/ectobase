// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package failover

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/dispatch/pkg/clusterpool"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := computev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := platformv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// readyPoolObj is a reachable pool: Ready, with a lease its broker just renewed.
func readyPoolObj(name string) *platformv1.ClusterPool {
	now := metav1.NewMicroTime(time.Now())
	return &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: platformv1.ClusterPoolStatus{
		Phase: clusterpool.PhaseReady,
		Lease: &platformv1.ClusterPoolLease{RenewTime: &now},
	}}
}

func req(name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}
}
func key(name string) client.ObjectKey { return types.NamespacedName{Name: name} }
