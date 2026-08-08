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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// TestCompiledNICControllerEnvtest runs the CompiledNICReconciler against a real in-process
// apiserver (controller-runtime envtest), proving that:
//   - A policied NIC gets a CompiledNIC with the policy rules in Spec.Firewall.Ingress and
//     an allow-all in Spec.Firewall.Egress (since no egress rules were specified).
//   - An unpolicied NIC gets a CompiledNIC with allow-all in both directions.
//
// Skips cleanly when KUBEBUILDER_ASSETS is unset (i.e. outside the nix devShell).
func TestCompiledNICControllerEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}

	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
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
	if err := (&CompiledNICReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
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

	t.Run("Policied", func(t *testing.T) {
		// Create a NIC with labels that the policy will select.
		nic := &netv1.NetworkInterface{}
		nic.Name = "nic-frontend"
		nic.Namespace = "default"
		nic.Labels = map[string]string{"role": "frontend"}
		nic.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
		nic.Spec.IPs = []string{"10.0.0.10"}
		nodeName := "node-1"
		nic.Spec.NodeName = &nodeName
		mustCreate(ctx, t, direct, nic)

		// Create a matching FirewallPolicy with one ingress Allow rule.
		pol := &netv1.FirewallPolicy{}
		pol.Name = "allow-https"
		pol.Namespace = "default"
		pol.Spec.InterfaceSelector = &metav1.LabelSelector{
			MatchLabels: map[string]string{"role": "frontend"},
		}
		pol.Spec.Ingress = []netv1.FirewallPolicyRule{
			{CIDR: "10.0.0.0/24", Proto: "TCP", Port: 443, Action: "Allow"},
		}
		mustCreate(ctx, t, direct, pol)

		// Poll until the CompiledNIC appears and has the expected firewall rules.
		eventually(t, 15*time.Second, func() error {
			return checkCompiledNIC(ctx, direct, "default", "default-nic-frontend", func(c *netv1.CompiledNIC) error {
				// Ingress should have exactly the policy rule (no allow-all, since the policy governs it).
				if len(c.Spec.Firewall.Ingress) != 1 {
					return fmt.Errorf("ingress rules = %d, want 1", len(c.Spec.Firewall.Ingress))
				}
				r := c.Spec.Firewall.Ingress[0]
				if r.CIDR != "10.0.0.0/24" || r.Proto != "TCP" || r.Port != 443 || r.Action != "Allow" {
					return fmt.Errorf("ingress[0] = %+v, want CIDR=10.0.0.0/24 Proto=TCP Port=443 Action=Allow", r)
				}
				// Egress has no policy rules → allow-all materialized for both families.
				if len(c.Spec.Firewall.Egress) != 2 || !hasAllowCIDR(c.Spec.Firewall.Egress, "0.0.0.0/0") || !hasAllowCIDR(c.Spec.Firewall.Egress, "::/0") {
					return fmt.Errorf("egress = %+v, want v4+v6 allow-all", c.Spec.Firewall.Egress)
				}
				return nil
			})
		})
	})

	t.Run("Unpolicied", func(t *testing.T) {
		// A NIC with no matching policy → CompiledNIC gets allow-all in both directions.
		nic := &netv1.NetworkInterface{}
		nic.Name = "nic-backend"
		nic.Namespace = "default"
		nic.Labels = map[string]string{"role": "backend"} // no policy selects "backend"
		nic.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
		nic.Spec.IPs = []string{"10.0.0.20"}
		mustCreate(ctx, t, direct, nic)

		eventually(t, 15*time.Second, func() error {
			return checkCompiledNIC(ctx, direct, "default", "default-nic-backend", func(c *netv1.CompiledNIC) error {
				if len(c.Spec.Firewall.Ingress) != 2 || !hasAllowCIDR(c.Spec.Firewall.Ingress, "0.0.0.0/0") || !hasAllowCIDR(c.Spec.Firewall.Ingress, "::/0") {
					return fmt.Errorf("ingress = %+v, want v4+v6 allow-all", c.Spec.Firewall.Ingress)
				}
				if len(c.Spec.Firewall.Egress) != 2 || !hasAllowCIDR(c.Spec.Firewall.Egress, "0.0.0.0/0") || !hasAllowCIDR(c.Spec.Firewall.Egress, "::/0") {
					return fmt.Errorf("egress = %+v, want v4+v6 allow-all", c.Spec.Firewall.Egress)
				}
				return nil
			})
		})
	})

	cancel()
	select {
	case <-mgrDone:
	case <-time.After(10 * time.Second):
		t.Fatal("manager did not shut down")
	}
}

// TestCompiledNICControllerEnvtest_DeletedPolicyClearsRule proves — on a clean in-process apiserver
// (zero live pollution) — that DELETING a FirewallPolicy CLEARS its rule from the CompiledNIC. It:
//   - creates a NIC labeled {side: green},
//   - applies a policy selecting side=green with an ingress Deny of 0.0.0.0/0,
//   - waits until the CompiledNIC's Ingress contains that Deny,
//   - deletes the policy,
//   - waits until the Deny is GONE — the ruleless ingress reverts to the compiler's allow-all default
//     ([{0.0.0.0/0, Allow}, {::/0, Allow}]). The property under test is the ABSENCE of any Deny rule.
//
// This settles a prior claim (from a heavily-polluted, long-running controller pod) that the
// controller ACCUMULATES rules from deleted policies. The controller's Reconcile Lists policies fresh
// and REPLACES existing.Spec, and the FirewallPolicy Delete event re-enqueues affected NICs
// (GenerationChangedPredicate only overrides Update, so Delete passes) — so the rule should clear.
//
// Skips cleanly when KUBEBUILDER_ASSETS is unset (i.e. outside the nix devShell).
func TestCompiledNICControllerEnvtest_DeletedPolicyClearsRule(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}

	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	defer func() { _ = env.Stop() }()

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		// This test shares the test binary (and thus the global controller-name registry) with
		// TestCompiledNICControllerEnvtest, whose reconciler also derives the name "networkinterface".
		// Skip the uniqueness validation so both envtest managers can coexist in one `go test` run.
		Controller: config.Controller{SkipNameValidation: ptrTo(true)},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := (&CompiledNICReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
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

	// A NIC labeled {side: green}, scheduled to a node, with an overlay IP.
	nic := &netv1.NetworkInterface{}
	nic.Name = "nic-green"
	nic.Namespace = "default"
	nic.Labels = map[string]string{"side": "green"}
	nic.Spec.VPCRef = netv1.LocalObjectReference{Name: "green-vpc"}
	nic.Spec.IPs = []string{"10.0.20.11"}
	nodeName := "node-1"
	nic.Spec.NodeName = &nodeName
	mustCreate(ctx, t, direct, nic)

	// A FirewallPolicy selecting side=green with one ingress Deny of 0.0.0.0/0.
	pol := &netv1.FirewallPolicy{}
	pol.Name = "deny-all-green"
	pol.Namespace = "default"
	pol.Spec.InterfaceSelector = &metav1.LabelSelector{
		MatchLabels: map[string]string{"side": "green"},
	}
	pol.Spec.Ingress = []netv1.FirewallPolicyRule{
		{CIDR: "0.0.0.0/0", Action: "Deny"},
	}
	mustCreate(ctx, t, direct, pol)

	// The CompiledNIC's Ingress must contain the Deny rule.
	eventually(t, 15*time.Second, func() error {
		return checkCompiledNIC(ctx, direct, "default", "default-nic-green", func(c *netv1.CompiledNIC) error {
			if !hasFwRule(c.Spec.Firewall.Ingress, "0.0.0.0/0", "Deny") {
				return fmt.Errorf("ingress = %+v, want a {0.0.0.0/0 Deny} rule", c.Spec.Firewall.Ingress)
			}
			return nil
		})
	})

	// DELETE the policy.
	if err := direct.Delete(ctx, pol); err != nil {
		t.Fatalf("delete policy: %v", err)
	}

	// The Deny must be GONE: the now-ruleless ingress reverts to the compiler's allow-all default.
	// Assert on the ABSENCE of any Deny (the property under test), and — as a positive sanity check
	// — that the allow-all default has materialized for both families.
	eventually(t, 15*time.Second, func() error {
		return checkCompiledNIC(ctx, direct, "default", "default-nic-green", func(c *netv1.CompiledNIC) error {
			for _, r := range c.Spec.Firewall.Ingress {
				if r.Action == "Deny" {
					return fmt.Errorf("stale Deny rule persists after policy delete: ingress = %+v", c.Spec.Firewall.Ingress)
				}
			}
			if len(c.Spec.Firewall.Ingress) != 2 ||
				!hasAllowCIDR(c.Spec.Firewall.Ingress, "0.0.0.0/0") ||
				!hasAllowCIDR(c.Spec.Firewall.Ingress, "::/0") {
				return fmt.Errorf("ingress = %+v, want v4+v6 allow-all default after delete", c.Spec.Firewall.Ingress)
			}
			return nil
		})
	})

	cancel()
	select {
	case <-mgrDone:
	case <-time.After(10 * time.Second):
		t.Fatal("manager did not shut down")
	}
}

// ptrTo returns a pointer to v (for optional *bool config fields like SkipNameValidation).
func ptrTo[T any](v T) *T { return &v }

// hasFwRule reports whether the rule list contains a rule with the given CIDR and Action.
func hasFwRule(rules []netv1.CompiledFwRule, cidr, action string) bool {
	for _, r := range rules {
		if r.CIDR == cidr && r.Action == action {
			return true
		}
	}
	return false
}

// checkCompiledNIC fetches the CompiledNIC with the given namespace/name and runs check against it.
// Returns an error if the object doesn't exist yet or check fails.
func checkCompiledNIC(ctx context.Context, c client.Client, namespace, name string, check func(*netv1.CompiledNIC) error) error {
	var got netv1.CompiledNIC
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &got); err != nil {
		return err
	}
	return check(&got)
}
