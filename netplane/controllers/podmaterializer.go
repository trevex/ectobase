// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"strings"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// podFieldOwner is this controller's server-side-apply field manager name.
	podFieldOwner = "pod-materializer"
	// podContainerName is the single container name in the materialized Pod (mirrors
	// test/lab/livetest/pod_test.go's raw manifest, which names its container "c").
	podContainerName = "c"
	// networkInterfaceAnnotation is the flowplane-cni NIC-ref annotation the plugin resolves
	// to the broker-synced CompiledNIC (matches pod_test.go's podManifest + the CNI plugin).
	networkInterfaceAnnotation = "net.ectobase.dev/network-interface"
	// multusNetworksAnnotation is the Multus secondary-network annotation that runs
	// flowplane-cni as an extra interface (matches pod_test.go's podManifest).
	multusNetworksAnnotation = "k8s.v1.cni.cncf.io/networks"
	// containerNameLabel labels the materialized Pod with its CompiledContainer name so
	// callers/tests can select it.
	containerNameLabel = "net.ectobase.dev/container"
)

// buildPod turns a CompiledContainer into a v1.Pod attached to the flowplane overlay via
// Multus + the flowplane-cni annotation. It reproduces the raw manifest from
// test/lab/livetest/pod_test.go (podManifest): the two overlay annotations, the
// hostname nodeSelector, the Exists toleration, terminationGracePeriodSeconds=0, and a
// single container built from the compiled spec. Pure: no I/O. TypeMeta is set so the
// object is self-describing for a server-side-apply patch.
func buildPod(cc *compiledv1.CompiledContainer) *corev1.Pod {
	// Multus annotation: join every interface's NetworkName (the NAD name). The
	// network-interface annotation is single-valued (flowplane-cni resolves one NIC per
	// pod); the tests use exactly one interface, so we take index 0.
	// TODO multi-interface: flowplane-cni's network-interface annotation is single-valued;
	// supporting N overlay interfaces needs a per-network ref encoding on the plugin side.
	networks := make([]string, 0, len(cc.Spec.Interfaces))
	for _, in := range cc.Spec.Interfaces {
		networks = append(networks, in.NetworkName)
	}
	annotations := map[string]string{}
	if len(networks) > 0 {
		annotations[multusNetworksAnnotation] = strings.Join(networks, ",")
	}
	if len(cc.Spec.Interfaces) > 0 {
		annotations[networkInterfaceAnnotation] = cc.Spec.Interfaces[0].NetworkInterfaceRef
	}

	restartPolicy := cc.Spec.RestartPolicy
	if restartPolicy == "" {
		restartPolicy = corev1.RestartPolicyAlways
	}

	grace := int64(0)
	pod := &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   cc.Namespace,
			Name:        cc.Name,
			Labels:      map[string]string{containerNameLabel: cc.Name},
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			RestartPolicy:                 restartPolicy,
			Tolerations:                   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			TerminationGracePeriodSeconds: &grace,
			Containers: []corev1.Container{{
				Name:      podContainerName,
				Image:     cc.Spec.Image,
				Command:   cc.Spec.Command,
				Args:      cc.Spec.Args,
				Env:       cc.Spec.Env,
				Resources: cc.Spec.Resources,
			}},
		},
	}
	// NodeName is an OPTIONAL node pin. When set, hard-pin the Pod to that host; when empty,
	// leave placement to kube-scheduler — the interface lands wherever the Pod is scheduled and
	// the node agent self-locates its policy by the interface's (VNI, overlay IP), so no host pin
	// is required for the datapath.
	if cc.Spec.NodeName != "" {
		pod.Spec.NodeSelector = map[string]string{"kubernetes.io/hostname": cc.Spec.NodeName}
	}
	return pod
}

// PodMaterializerReconciler turns local CompiledContainers into v1.Pods. It runs on the
// DOWNSTREAM compute cluster (a plain k8s cluster with Multus + flowplane-cni installed),
// not against the hub aggregated apiserver.
type PodMaterializerReconciler struct{ Client client.Client }

func (r *PodMaterializerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cc compiledv1.CompiledContainer
	if err := r.Client.Get(ctx, req.NamespacedName, &cc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	desired := buildPod(&cc)
	if err := ctrl.SetControllerReference(&cc, desired, r.Client.Scheme()); err != nil {
		return ctrl.Result{}, err
	}
	// Server-side apply (mirrors vm-materializer): the materializer owns ONLY the fields
	// buildPod sets, so kubelet/apiserver-defaulted fields aren't churned and re-applying
	// the same intent is a genuine no-op.
	if err := r.Client.Patch(ctx, desired, client.Apply, client.FieldOwner(podFieldOwner), client.ForceOwnership); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply pod: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *PodMaterializerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&compiledv1.CompiledContainer{}).
		Owns(&corev1.Pod{}).
		Complete(r)
}
