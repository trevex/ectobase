// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"path/filepath"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	netinstall "github.com/trevex/ectobase/api/net/install"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	platforminstall "github.com/trevex/ectobase/api/platform/install"
)

// TestFirewallValidation_AggregatedAPIServer pins that the REAL aggregated apiserver runs the
// FirewallPolicy and VPC admission checks on create AND update. These types have no structural
// schema there, so their +kubebuilder:validation markers never execute; before these hooks a
// FirewallPolicy with action "Reject" or a VPC with defaultPolicy "allow" was stored and then
// silently misread by the compiler.
func TestFirewallValidation_AggregatedAPIServer(t *testing.T) {
	t.Setenv("GOWORK", "off")

	scheme := runtime.NewScheme()
	platforminstall.Install(scheme)
	netinstall.Install(scheme)
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("register client-go scheme: %v", err)
	}
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiregistration scheme: %v", err)
	}
	env, err := kitenvtest.NewEnvironment(
		"github.com/trevex/ectobase/dispatch/cmd/apiserver",
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
		t.Fatalf("client.New: %v", err)
	}
	ctx := kitenvtest.Context()

	policy := func(name, action string) *netv1.FirewallPolicy {
		return &netv1.FirewallPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: netv1.FirewallPolicySpec{
				InterfaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				Ingress:           []netv1.FirewallPolicyRule{{CIDR: "10.0.0.0/24", Proto: "TCP", Port: 443, Action: action}},
			},
		}
	}

	t.Run("FirewallPolicyCreateRejected", func(t *testing.T) {
		err := c.Create(ctx, policy("bad-action", "Reject"))
		if !apierrors.IsInvalid(err) {
			t.Fatalf("create with action Reject: want Invalid, got %v", err)
		}
	})

	t.Run("FirewallPolicyUpdateRejected", func(t *testing.T) {
		p := policy("edited", "Allow")
		if err := c.Create(ctx, p); err != nil {
			t.Fatalf("create valid policy: %v", err)
		}
		p.Spec.Ingress[0].CIDR = "10.0.0.5/24" // host bits set
		if err := c.Update(ctx, p); !apierrors.IsInvalid(err) {
			t.Fatalf("update to a CIDR with host bits: want Invalid, got %v", err)
		}
	})

	t.Run("VPCDefaultPolicyRejected", func(t *testing.T) {
		lower := "allow"
		vpc := &netv1.VPC{
			ObjectMeta: metav1.ObjectMeta{Name: "lowercase", Namespace: "default"},
			Spec:       netv1.VPCSpec{DefaultPolicy: &lower},
		}
		if err := c.Create(ctx, vpc); !apierrors.IsInvalid(err) {
			t.Fatalf("create VPC with defaultPolicy %q: want Invalid, got %v", lower, err)
		}
	})
}
