// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"context"
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

// startNetEnv boots the aggregated apiserver serving both the platform and net
// groups and returns a controller-runtime client for it.
func startNetEnv(t *testing.T) (client.Client, context.Context) {
	t.Helper()
	t.Setenv("GOWORK", "off")

	scheme := runtime.NewScheme()
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
	return c, kitenvtest.Context()
}

// TestNetworkInterface_CRUD proves a second net type (NetworkInterface) is served
// by the aggregated apiserver: a namespaced NetworkInterface is created and read
// back, and a couple of its spec fields survive the internal<->versioned
// conversion round-trip.
func TestNetworkInterface_CRUD(t *testing.T) {
	c, ctx := startNetEnv(t)

	nodeName := "node-a"
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-nic-",
			Namespace:    "default",
		},
		Spec: netv1.NetworkInterfaceSpec{
			VPCRef:   netv1.LocalObjectReference{Name: "vpc-1"},
			IPs:      []string{"10.0.0.5", "fd00::5"},
			MAC:      "aa:bb:cc:dd:ee:ff",
			NodeName: &nodeName,
		},
	}
	if err := c.Create(ctx, nic); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if nic.Name == "" {
		t.Fatalf("Create: expected generated name, got empty")
	}

	got := &netv1.NetworkInterface{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(nic), got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Spec.VPCRef.Name != "vpc-1" {
		t.Fatalf("Get: expected VPCRef.Name=vpc-1, got %q", got.Spec.VPCRef.Name)
	}
	if len(got.Spec.IPs) != 2 || got.Spec.IPs[0] != "10.0.0.5" || got.Spec.IPs[1] != "fd00::5" {
		t.Fatalf("Get: expected IPs=[10.0.0.5 fd00::5], got %v", got.Spec.IPs)
	}
	if got.Spec.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("Get: expected MAC preserved, got %q", got.Spec.MAC)
	}
	if got.Spec.NodeName == nil || *got.Spec.NodeName != "node-a" {
		t.Fatalf("Get: expected NodeName=node-a, got %v", got.Spec.NodeName)
	}

	if err := c.Delete(ctx, nic); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// TestCompiledNIC_SpecClusterNameSelector proves the CompiledNIC spec.clusterName
// field selector is served and bounded: two CompiledNICs (c1, c2) are created and
// a List filtered by spec.clusterName=c1 must return exactly the c1 one. This is
// the selector the per-cluster broker relies on.
func TestCompiledNIC_SpecClusterNameSelector(t *testing.T) {
	c, ctx := startNetEnv(t)

	newNIC := func(cluster string) *netv1.CompiledNIC {
		return &netv1.CompiledNIC{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cnic-" + cluster + "-",
				Namespace:    "default",
			},
			Spec: netv1.CompiledNICSpec{
				ClusterName: cluster,
				NodeName:    "node-" + cluster,
				VNI:         1000,
				Port:        netv1.PortStatus{Type: netv1.PortTypeTap, Name: "dtapvf_0"},
			},
		}
	}

	a := newNIC("c1")
	if err := c.Create(ctx, a); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	b := newNIC("c2")
	if err := c.Create(ctx, b); err != nil {
		t.Fatalf("Create b: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Delete(ctx, a)
		_ = c.Delete(ctx, b)
	})

	list := &netv1.CompiledNICList{}
	if err := c.List(ctx, list, client.InNamespace("default"), client.MatchingFields{"spec.clusterName": "c1"}); err != nil {
		t.Fatalf("List(spec.clusterName=c1): %v", err)
	}
	if len(list.Items) != 1 {
		names := make([]string, len(list.Items))
		for i := range list.Items {
			names[i] = list.Items[i].Name
		}
		t.Fatalf("List(spec.clusterName=c1): expected exactly 1 item, got %d: %v", len(list.Items), names)
	}
	if list.Items[0].Name != a.Name {
		t.Fatalf("List(spec.clusterName=c1): expected %q, got %q", a.Name, list.Items[0].Name)
	}
	if list.Items[0].Spec.ClusterName != "c1" {
		t.Fatalf("List(spec.clusterName=c1): expected ClusterName=c1, got %q", list.Items[0].Spec.ClusterName)
	}
}

// TestCompiledVM_SpecClusterNameSelector proves the CompiledVM spec.clusterName
// field selector is served (mirror of the CompiledNIC selector test) and that a
// basic create/get round-trip preserves the boot image: two CompiledVMs (c1, c2)
// are created and a List filtered by spec.clusterName=c1 must return exactly the
// c1 one. This is the selector the per-cluster broker's SyncCompiledVMs relies on.
func TestCompiledVM_SpecClusterNameSelector(t *testing.T) {
	c, ctx := startNetEnv(t)

	newVM := func(cluster string) *netv1.CompiledVM {
		return &netv1.CompiledVM{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cvm-" + cluster + "-",
				Namespace:    "default",
			},
			Spec: netv1.CompiledVMSpec{
				ClusterName: cluster,
				Image:       "fedora",
				RunStrategy: "RerunOnFailure",
				Interfaces:  []netv1.CompiledVMInterface{{MAC: "02:00:00:00:00:01", NetworkName: "flowplane-overlay"}},
			},
		}
	}

	a := newVM("c1")
	if err := c.Create(ctx, a); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	b := newVM("c2")
	if err := c.Create(ctx, b); err != nil {
		t.Fatalf("Create b: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Delete(ctx, a)
		_ = c.Delete(ctx, b)
	})

	// Basic create/get round-trip: Image survives the internal<->versioned conversion.
	gotA := &netv1.CompiledVM{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(a), gotA); err != nil {
		t.Fatalf("Get a: %v", err)
	}
	if gotA.Spec.Image != "fedora" {
		t.Fatalf("Get a: expected Image=fedora, got %q", gotA.Spec.Image)
	}

	list := &netv1.CompiledVMList{}
	if err := c.List(ctx, list, client.InNamespace("default"), client.MatchingFields{"spec.clusterName": "c1"}); err != nil {
		t.Fatalf("List(spec.clusterName=c1): %v", err)
	}
	if len(list.Items) != 1 {
		names := make([]string, len(list.Items))
		for i := range list.Items {
			names[i] = list.Items[i].Name
		}
		t.Fatalf("List(spec.clusterName=c1): expected exactly 1 item, got %d: %v", len(list.Items), names)
	}
	if list.Items[0].Name != a.Name {
		t.Fatalf("List(spec.clusterName=c1): expected %q, got %q", a.Name, list.Items[0].Name)
	}
	if list.Items[0].Spec.ClusterName != "c1" {
		t.Fatalf("List(spec.clusterName=c1): expected ClusterName=c1, got %q", list.Items[0].Spec.ClusterName)
	}
}
