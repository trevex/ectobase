// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	netinstall "github.com/trevex/ectobase/central/apis/net/install"
	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
)

// TestVPC_CRUD proves the net.ectobase.dev group is served end-to-end by the
// aggregated apiserver: a namespaced VPC (whose versioned struct lives in the
// external api module and is converted to the internal central/apis/net type via
// the hand-written conversions) is created, read back, and its fields (including
// the *int32 VNI pointer) survive the internal<->versioned round-trip.
func TestVPC_CRUD(t *testing.T) {
	// The envtest harness builds the apiserver binary with `-mod mod`, which
	// conflicts with the repo's go.work workspace mode. Disable workspace mode
	// for the in-test build so the aggregated server compiles.
	t.Setenv("GOWORK", "off")

	scheme := runtime.NewScheme()
	// Both groups are installed: the aggregated server binary serves both, and
	// the client scheme must know the net types to (de)serialize them.
	platforminstall.Install(scheme)
	netinstall.Install(scheme)
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiregistration scheme: %v", err)
	}

	env, err := kitenvtest.NewEnvironment(
		"github.com/trevex/ectobase/central/cmd/apiserver",
		nil,
		[]string{filepath.Join(".", "fixtures")},
	)
	if err != nil {
		t.Fatalf("NewEnvironment: %v", err)
	}

	if _, err := env.Start(scheme, os.Stderr); err != nil {
		t.Fatalf("env.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("env.Stop: %v", err)
		}
	})

	if err := env.WaitUntilReadyWithTimeout(apiServiceTimeout); err != nil {
		t.Fatalf("WaitUntilReadyWithTimeout: %v", err)
	}

	c, err := client.New(env.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("New client: %v", err)
	}

	ctx := kitenvtest.Context()

	// --- Create a namespaced VPC with a pinned VNI + default policy. ---
	vni := int32(4242)
	policy := string(netv1.VPCPolicyDeny)
	vpc := &netv1.VPC{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-vpc-",
			Namespace:    "default",
		},
		Spec: netv1.VPCSpec{
			VNI:           &vni,
			DefaultPolicy: &policy,
		},
	}
	if err := c.Create(ctx, vpc); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if vpc.Name == "" {
		t.Fatalf("Create: expected generated name, got empty")
	}
	if vpc.Namespace != "default" {
		t.Fatalf("Create: expected namespace=default, got %q", vpc.Namespace)
	}

	// --- Get it back; assert spec fields survived the conversion round-trip. ---
	got := &netv1.VPC{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(vpc), got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Spec.VNI == nil {
		t.Fatalf("Get: expected VNI=4242, got nil")
	}
	if *got.Spec.VNI != 4242 {
		t.Fatalf("Get: expected VNI=4242, got %d", *got.Spec.VNI)
	}
	if got.Spec.DefaultPolicy == nil || *got.Spec.DefaultPolicy != string(netv1.VPCPolicyDeny) {
		t.Fatalf("Get: expected DefaultPolicy=Deny, got %v", got.Spec.DefaultPolicy)
	}

	// --- List within the namespace must include our VPC. ---
	list := &netv1.VPCList{}
	if err := c.List(ctx, list, client.InNamespace("default")); err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for i := range list.Items {
		if list.Items[i].Name == vpc.Name {
			found = true
		}
	}
	if !found {
		t.Fatalf("List: created VPC %q not found (%d items)", vpc.Name, len(list.Items))
	}

	// --- Delete (cleanup / exercise delete path). ---
	if err := c.Delete(ctx, vpc); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}
