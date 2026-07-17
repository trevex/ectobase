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

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

		// Create a matching NetworkPolicy with one ingress Allow rule.
		pol := &netv1.NetworkPolicy{}
		pol.Name = "allow-https"
		pol.Namespace = "default"
		pol.Spec.InterfaceSelector = &metav1.LabelSelector{
			MatchLabels: map[string]string{"role": "frontend"},
		}
		pol.Spec.Ingress = []netv1.NetworkPolicyRule{
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
				// Egress has no policy rules → allow-all materialized.
				if len(c.Spec.Firewall.Egress) != 1 {
					return fmt.Errorf("egress rules = %d, want 1 (allow-all)", len(c.Spec.Firewall.Egress))
				}
				e := c.Spec.Firewall.Egress[0]
				if e.CIDR != "0.0.0.0/0" || e.Action != "Allow" {
					return fmt.Errorf("egress[0] = %+v, want CIDR=0.0.0.0/0 Action=Allow", e)
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
				if len(c.Spec.Firewall.Ingress) != 1 || c.Spec.Firewall.Ingress[0].CIDR != "0.0.0.0/0" || c.Spec.Firewall.Ingress[0].Action != "Allow" {
					return fmt.Errorf("ingress = %+v, want [allow-all]", c.Spec.Firewall.Ingress)
				}
				if len(c.Spec.Firewall.Egress) != 1 || c.Spec.Firewall.Egress[0].CIDR != "0.0.0.0/0" || c.Spec.Firewall.Egress[0].Action != "Allow" {
					return fmt.Errorf("egress = %+v, want [allow-all]", c.Spec.Firewall.Egress)
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

// checkCompiledNIC fetches the CompiledNIC with the given namespace/name and runs check against it.
// Returns an error if the object doesn't exist yet or check fails.
func checkCompiledNIC(ctx context.Context, c client.Client, namespace, name string, check func(*netv1.CompiledNIC) error) error {
	var got netv1.CompiledNIC
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &got); err != nil {
		return err
	}
	return check(&got)
}
