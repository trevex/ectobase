// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// TestNATGatewayControllerEnvtest runs the NATGateway reconciler against a REAL in-process
// apiserver (controller-runtime envtest) via SetupWithManager — proving the parts a fake client
// cannot: the status-subresource update lands on a real apiserver, the CRD schema accepts the
// spec/status fields, and the manager's NATGateway watch + NIC→NATGateway mapping actually drive
// reconciles (no direct Sync call). Skips cleanly when KUBEBUILDER_ASSETS is unset (i.e. outside
// the nix devShell, which exports it to the kube-apiserver+etcd+kubectl assets).
func TestNATGatewayControllerEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}

	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

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
	defer func() { _ = env.Stop() }()

	// Manager drives the controller; a separate direct client does the test's writes/reads so we
	// don't depend on the manager cache for our own object mutations.
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"}, // disable the metrics listener (port clash)
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := (&NATGatewayReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup reconciler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgrDone := make(chan error, 1)
	go func() { mgrDone <- mgr.Start(ctx) }()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("manager cache did not sync")
	}

	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("direct client: %v", err)
	}

	// Two sources in VPC "blue" + one in "green" (must be excluded), and the gateway.
	mustCreateAllocatedNIC(ctx, t, direct, "nic-a", "blue", "10.0.0.1")
	mustCreateAllocatedNIC(ctx, t, direct, "nic-b", "blue", "10.0.0.2")
	mustCreateAllocatedNIC(ctx, t, direct, "nic-c", "green", "10.0.0.9")

	gw := &netv1.NATGateway{}
	gw.Name = "gw"
	gw.Namespace = "default"
	gw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	gw.Spec.PublicIPs = []string{"203.0.113.10"}
	gw.Spec.PortsPerSource = ptr(int32(1024))
	gw.Spec.EdgeUnderlay = "fd00:db8:0:9::e"
	mustCreate(ctx, t, direct, gw)

	// The watch-driven reconcile must populate a deterministic, disjoint, blue-only table.
	eventually(t, 15*time.Second, func() error {
		return checkAllocations(ctx, direct, 2)
	})

	// Adding a third blue NIC must re-trigger reconcile via natgwsForNIC → the table grows to 3.
	mustCreateAllocatedNIC(ctx, t, direct, "nic-d", "blue", "10.0.0.3")
	eventually(t, 15*time.Second, func() error {
		return checkAllocations(ctx, direct, 3)
	})

	cancel()
	select {
	case <-mgrDone:
	case <-time.After(10 * time.Second):
		t.Fatal("manager did not shut down")
	}
}

func mustCreate(ctx context.Context, t *testing.T, c client.Client, obj client.Object) {
	t.Helper()
	if err := c.Create(ctx, obj); err != nil {
		t.Fatalf("create %T %s: %v", obj, obj.GetName(), err)
	}
}

// mustCreateAllocatedNIC creates a NIC and then commits its allocated overlay IPs to status,
// which is what central IPAM does and the only place the NAT reconciler reads. A real
// apiserver drops status on create (it is a subresource), so seeding it in the object
// literal — as a fake client would allow — silently yields a NIC with no overlay IPs.
func mustCreateAllocatedNIC(ctx context.Context, t *testing.T, c client.Client, name, vpc string, ips ...string) {
	t.Helper()
	nic := &netv1.NetworkInterface{}
	nic.Name = name
	nic.Namespace = "default"
	nic.Spec.VPCRef = netv1.LocalObjectReference{Name: vpc}
	mustCreate(ctx, t, c, nic)
	nic.Status.State = "Allocated"
	nic.Status.ObservedGeneration = nic.Generation
	nic.Status.AllocatedIPs = ips
	if err := c.Status().Update(ctx, nic); err != nil {
		t.Fatalf("commit status for NIC %s: %v", name, err)
	}
}

// checkAllocations returns nil once the "gw" NATGateway is Ready with exactly wantN allocations,
// all on the public IP, all deterministic disjoint blocks, and the green source excluded.
func checkAllocations(ctx context.Context, c client.Client, wantN int) error {
	var got netv1.NATGateway
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "gw"}, &got); err != nil {
		return err
	}
	if got.Status.State != "Ready" {
		return fmt.Errorf("state=%q want Ready", got.Status.State)
	}
	if len(got.Status.Allocations) != wantN {
		return fmt.Errorf("allocations=%d want %d", len(got.Status.Allocations), wantN)
	}
	seen := map[string]netv1.NATAllocation{}
	for _, a := range got.Status.Allocations {
		if a.PublicIP != "203.0.113.10" {
			return fmt.Errorf("allocation %+v not on the public IP", a)
		}
		if a.Source == "10.0.0.9" {
			return fmt.Errorf("green source 10.0.0.9 must not be allocated")
		}
		for _, b := range seen {
			if a.PortMin <= b.PortMax && b.PortMin <= a.PortMax {
				return fmt.Errorf("port-blocks overlap: %+v %+v", a, b)
			}
		}
		seen[a.Source] = a
	}
	return nil
}

// eventually polls fn until it returns nil or the timeout elapses.
func eventually(t *testing.T, timeout time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if last = fn(); last == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %v", timeout, last)
}

// TestNATGatewayGrowsOverSuccessivePassesEnvtest proves the half of grow-on-demand a fake client
// cannot: that a gateway needing MORE than one extra address actually gets there.
//
// Growth is bounded to one new address per pass on purpose, so a gateway short three addresses
// converges only if each pass triggers the next. Nothing re-enqueues it explicitly — the status
// write does, via the manager's own NATGateway watch. If that self-trigger ever stops working
// this test times out at two allocations, which is exactly the production symptom: a gateway
// stuck in Exhausted with free addresses sitting in the pool.
func TestNATGatewayGrowsOverSuccessivePassesEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}

	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
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
	defer func() { _ = env.Stop() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("direct client: %v", err)
	}

	// The pool and every NIC exist BEFORE the manager starts, and nothing writes one
	// afterwards. That is what isolates the self-trigger: the NIC and IPPool watches can only
	// fire during the initial cache sync, when there is no NATGateway for them to map to, so
	// the reconciles that grow the address set can have come from nothing but the gateway's
	// own status writes.
	pool := &netv1.IPPool{}
	pool.Name = "pub"
	pool.Namespace = "default"
	v4 := "198.51.100.0/24"
	pool.Spec = netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: &v4}
	mustCreate(ctx, t, direct, pool)
	// No IPPoolReconciler runs here, so Ready is set by hand — a real apiserver drops status
	// on create, exactly like the NIC status above.
	pool.Status.State = "Ready"
	if err := direct.Status().Update(ctx, pool); err != nil {
		t.Fatalf("mark pool Ready: %v", err)
	}

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		mustCreateAllocatedNIC(ctx, t, direct, "nic-"+ip, "blue", ip)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		// Controller names are unique per PROCESS (they name a metric), and the envtest
		// above already registered "natgateway" in this same test binary.
		Controller: crconfig.Controller{SkipNameValidation: ptr(true)},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := (&NATGatewayReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		t.Fatalf("setup reconciler: %v", err)
	}
	mgrDone := make(chan error, 1)
	go func() { mgrDone <- mgr.Start(ctx) }()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("manager cache did not sync")
	}

	gw := &netv1.NATGateway{}
	gw.Name = "gw"
	gw.Namespace = "default"
	gw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	gw.Spec.PoolRef = netv1.LocalObjectReference{Name: "pub"}
	// 64512 usable ports per address / 64512 == exactly one source per address, so three
	// sources need three addresses and therefore three passes.
	gw.Spec.PortsPerSource = ptr(int32(64512))
	mustCreate(ctx, t, direct, gw)

	eventually(t, 30*time.Second, func() error {
		var got netv1.NATGateway
		if err := direct.Get(ctx, client.ObjectKey{Namespace: "default", Name: "gw"}, &got); err != nil {
			return err
		}
		var allocs netv1.IPAllocationList
		if err := direct.List(ctx, &allocs, client.InNamespace("default")); err != nil {
			return err
		}
		if got.Status.State != "Ready" || len(got.Status.Allocations) != 3 || len(allocs.Items) != 3 {
			return fmt.Errorf("state=%q blocks=%d ipallocations=%d, want Ready/3/3",
				got.Status.State, len(got.Status.Allocations), len(allocs.Items))
		}
		// One source per address, and every address genuinely distinct.
		ips := map[string]bool{}
		for _, a := range got.Status.Allocations {
			if ips[a.PublicIP] {
				return fmt.Errorf("two sources share %s: %+v", a.PublicIP, got.Status.Allocations)
			}
			ips[a.PublicIP] = true
		}
		return nil
	})

	cancel()
	select {
	case <-mgrDone:
	case <-time.After(10 * time.Second):
		t.Fatal("manager did not shut down")
	}
}
