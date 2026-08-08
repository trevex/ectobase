// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestBuildPod(t *testing.T) {
	cc := &netv1.CompiledContainer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-ctr1"},
		Spec: netv1.CompiledContainerSpec{
			NodeName: "n1",
			Image:    "busybox:1.36",
			Command:  []string{"sleep", "3600"},
			Interfaces: []netv1.CompiledContainerInterface{{
				NetworkName:         "flowplane-overlay",
				NetworkInterfaceRef: "default/nic-a",
				MAC:                 "02:00:00:00:00:aa",
			}},
		},
	}
	pod := buildPod(cc)
	if pod.Name != "default-ctr1" || pod.Namespace != "default" {
		t.Fatalf("meta: %s/%s", pod.Namespace, pod.Name)
	}
	if pod.Labels[containerNameLabel] != "default-ctr1" {
		t.Fatalf("container label: %q", pod.Labels[containerNameLabel])
	}
	if got := pod.Annotations[multusNetworksAnnotation]; got != "flowplane-overlay" {
		t.Fatalf("networks annotation: %q", got)
	}
	if got := pod.Annotations[networkInterfaceAnnotation]; got != "default/nic-a" {
		t.Fatalf("network-interface annotation: %q", got)
	}
	if got := pod.Spec.NodeSelector["kubernetes.io/hostname"]; got != "n1" {
		t.Fatalf("nodeSelector: %q", got)
	}
	// RestartPolicy defaults to Always when empty.
	if pod.Spec.RestartPolicy != corev1.RestartPolicyAlways {
		t.Fatalf("restartPolicy default: %q", pod.Spec.RestartPolicy)
	}
	if pod.Spec.TerminationGracePeriodSeconds == nil || *pod.Spec.TerminationGracePeriodSeconds != 0 {
		t.Fatalf("terminationGracePeriodSeconds: %v", pod.Spec.TerminationGracePeriodSeconds)
	}
	if len(pod.Spec.Tolerations) != 1 || pod.Spec.Tolerations[0].Operator != corev1.TolerationOpExists {
		t.Fatalf("tolerations: %+v", pod.Spec.Tolerations)
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("containers: %+v", pod.Spec.Containers)
	}
	c := pod.Spec.Containers[0]
	if c.Name != "c" || c.Image != "busybox:1.36" {
		t.Fatalf("container: %+v", c)
	}
	if len(c.Command) != 2 || c.Command[0] != "sleep" {
		t.Fatalf("command: %+v", c.Command)
	}
}

func TestBuildPod_MultiInterfaceJoinsNetworks(t *testing.T) {
	cc := &netv1.CompiledContainer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-ctr1"},
		Spec: netv1.CompiledContainerSpec{
			Interfaces: []netv1.CompiledContainerInterface{
				{NetworkName: "net-a", NetworkInterfaceRef: "default/nic-a"},
				{NetworkName: "net-b", NetworkInterfaceRef: "default/nic-b"},
			},
		},
	}
	pod := buildPod(cc)
	if got := pod.Annotations[multusNetworksAnnotation]; got != "net-a,net-b" {
		t.Fatalf("networks annotation: %q", got)
	}
	// The single-valued network-interface annotation keeps index 0 (pod_test.go shape).
	if got := pod.Annotations[networkInterfaceAnnotation]; got != "default/nic-a" {
		t.Fatalf("network-interface annotation: %q", got)
	}
}

func TestBuildPod_RestartPolicyRespected(t *testing.T) {
	cc := &netv1.CompiledContainer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-ctr1"},
		Spec:       netv1.CompiledContainerSpec{RestartPolicy: corev1.RestartPolicyNever},
	}
	if pod := buildPod(cc); pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Fatalf("restartPolicy: %q", pod.Spec.RestartPolicy)
	}
}

// TestPodMaterializer_CreatesPod runs the reconciler against a real downstream apiserver with the
// CompiledContainer CRD installed and asserts the reconciler materializes a v1.Pod with the two
// overlay annotations, the hostname nodeSelector, the container label, the container (name/image),
// and the defaulted restartPolicy.
func TestPodMaterializer_CreatesPod(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}

	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	defer func() { _ = env.Stop() }()

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx := context.Background()

	cc := &netv1.CompiledContainer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "default-ctr1"},
		Spec: netv1.CompiledContainerSpec{
			ClusterName: "cluster-a",
			NodeName:    "n1",
			Image:       "busybox:1.36",
			Command:     []string{"sleep", "3600"},
			Interfaces: []netv1.CompiledContainerInterface{{
				NetworkName:         "flowplane-overlay",
				NetworkInterfaceRef: "default/nic-a",
				MAC:                 "02:00:00:00:00:aa",
			}},
		},
	}
	if err := c.Create(ctx, cc); err != nil {
		t.Fatalf("create compiledcontainer: %v", err)
	}

	r := &PodMaterializerReconciler{Client: c}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "default-ctr1"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var pod corev1.Pod
	if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "default-ctr1"}, &pod); err != nil {
		t.Fatalf("get materialized pod: %v", err)
	}
	if pod.Labels[containerNameLabel] != "default-ctr1" {
		t.Fatalf("container label: %q", pod.Labels[containerNameLabel])
	}
	if got := pod.Annotations[multusNetworksAnnotation]; got != "flowplane-overlay" {
		t.Fatalf("networks annotation: %q", got)
	}
	if got := pod.Annotations[networkInterfaceAnnotation]; got != "default/nic-a" {
		t.Fatalf("network-interface annotation: %q", got)
	}
	if got := pod.Spec.NodeSelector["kubernetes.io/hostname"]; got != "n1" {
		t.Fatalf("nodeSelector: %q", got)
	}
	if pod.Spec.RestartPolicy != corev1.RestartPolicyAlways {
		t.Fatalf("restartPolicy default: %q", pod.Spec.RestartPolicy)
	}
	if len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "c" || pod.Spec.Containers[0].Image != "busybox:1.36" {
		t.Fatalf("container: %+v", pod.Spec.Containers)
	}

	// Idempotent: a second reconcile must not error and must not duplicate.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "default-ctr1"}}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
}
