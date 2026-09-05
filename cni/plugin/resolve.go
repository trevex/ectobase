// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// multusNetworksAnnotation is the Multus network-selection annotation on a pod. For a KubeVirt
// virt-launcher pod, KubeVirt's network-binding plugin writes our NAD as a selection element
// carrying the interface MAC — the only NIC-identity signal a launcher exposes to the CNI (the
// launcher has no net.ectobase.dev/network-interface annotation, since KubeVirt, not us, creates it).
const multusNetworksAnnotation = "k8s.v1.cni.cncf.io/networks"

// resolved is the overlay config the CNI programs for an interface.
type resolved struct {
	VNI uint32
	IPs []string
	MAC string // the interface L2 address (set for VMs; empty = dataplane derives)
}

// resolvePodNIC reads the pod and returns its overlay {vni, ips, mac} from the broker-synced
// CompiledNIC (central policy — the compute cluster never needs the source CRDs). It supports two
// pods:
//   - a container Pod carries the net.ectobase.dev/network-interface annotation (written by the
//     pod-materializer) naming its NIC <ns>/<nic>; resolve the CompiledNIC <ns>-<nic> directly.
//   - a KubeVirt virt-launcher pod has NO such annotation (KubeVirt creates the pod); resolve the
//     CompiledNIC by the interface MAC in the Multus networks annotation. This is CompiledNIC-only
//     (no CompiledVM), so a VANILLA KubeVirt VM — authored directly against upstream KubeVirt + our
//     `flowplane` binding, not via our compute.VirtualMachine materializer — works with our SDN, as
//     long as it pins a MAC that matches a NetworkInterface (→ CompiledNIC.Spec.MAC).
func resolvePodNIC(ctx context.Context, c client.Client, conf *netConf, podNS, podName string) (resolved, error) {
	var pod corev1.Pod
	if err := c.Get(ctx, types.NamespacedName{Namespace: podNS, Name: podName}, &pod); err != nil {
		return resolved{}, fmt.Errorf("get pod %s/%s: %w", podNS, podName, err)
	}

	// Container path: explicit NetworkInterface annotation.
	if ref := pod.Annotations[networkInterfaceAnnotation]; ref != "" {
		ns, name, ok := strings.Cut(ref, "/")
		if !ok || ns == "" || name == "" {
			return resolved{}, fmt.Errorf("annotation %q value %q is not <ns>/<name>", networkInterfaceAnnotation, ref)
		}
		return resolveCompiledNIC(ctx, c, ns, name)
	}

	// VM (virt-launcher) path: resolve by the interface MAC from the Multus networks annotation.
	mac, err := macFromNetworksAnnotation(pod.Annotations[multusNetworksAnnotation], conf.Name)
	if err != nil {
		return resolved{}, fmt.Errorf("pod %s/%s has no %q annotation and no resolvable MAC: %w",
			podNS, podName, networkInterfaceAnnotation, err)
	}
	return resolveCompiledNICByMAC(ctx, c, podNS, mac)
}

// networkSelectionElement is the subset of a Multus network-selection element we need: the NAD name
// and the (optional) requested MAC. Matches the CNCF Network Attachment Selection annotation schema.
type networkSelectionElement struct {
	Name string `json:"name"`
	MAC  string `json:"mac,omitempty"`
}

// macFromNetworksAnnotation extracts the interface MAC our NAD carries in the pod's Multus networks
// annotation. Prefers the selection element whose `name` matches our NAD (nadName); for a single-NIC
// VM there is exactly one MAC-bearing element, so it falls back to that.
//
// TODO(multi-nic): a VM with >1 flowplane NIC carries multiple MAC-bearing selection elements and the
// CNI cannot map args.IfName -> the specific NIC here (the launcher's per-interface identity is not
// forwarded to the delegate). Single-NIC VMs only for now.
func macFromNetworksAnnotation(raw, nadName string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("no %q annotation", multusNetworksAnnotation)
	}
	var sels []networkSelectionElement
	if err := json.Unmarshal([]byte(raw), &sels); err != nil {
		return "", fmt.Errorf("parse %q: %w", multusNetworksAnnotation, err)
	}
	var withMAC []networkSelectionElement
	for _, s := range sels {
		if s.MAC == "" {
			continue
		}
		if nadName != "" && s.Name == nadName {
			return s.MAC, nil
		}
		withMAC = append(withMAC, s)
	}
	switch len(withMAC) {
	case 0:
		return "", fmt.Errorf("no MAC in any %q selection element", multusNetworksAnnotation)
	case 1:
		return withMAC[0].MAC, nil
	default:
		return "", fmt.Errorf("%d MAC-bearing selection elements, none matched NAD %q (multi-NIC VM unsupported)", len(withMAC), nadName)
	}
}

// resolveCompiledNIC reads the broker-synced CompiledNIC (central policy) for the NetworkInterface
// <ns>/<name> and returns the overlay {vni, ips, mac}. The compiler names the CompiledNIC "<ns>-<nic>"
// in the NIC's namespace. Kept pure (client.Client injected) so it unit-tests against a fake client.
func resolveCompiledNIC(ctx context.Context, c client.Client, ns, name string) (resolved, error) {
	compiledName := ns + "-" + name
	var cn compiledv1.CompiledNIC
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: compiledName}, &cn); err != nil {
		return resolved{}, fmt.Errorf("get CompiledNIC %s/%s (not compiled/synced yet?): %w", ns, compiledName, err)
	}

	// VNI==0 means the object exists but has not been fully compiled/synced (or the VPC
	// has no allocated VNI yet). Fail clearly so the kubelet retries CNI ADD.
	if cn.Spec.VNI == 0 {
		return resolved{}, fmt.Errorf("CompiledNIC %s/%s has no VNI (spec.vni is 0) — not compiled/synced yet", ns, compiledName)
	}

	return resolved{VNI: uint32(cn.Spec.VNI), IPs: cn.Spec.OverlayIPs, MAC: cn.Spec.MAC}, nil
}

// resolveCompiledNICByMAC finds the broker-synced CompiledNIC in `namespace` whose Spec.MAC matches
// `mac` (case-insensitive). Used for a KubeVirt virt-launcher pod, which has no
// net.ectobase.dev/network-interface annotation — the pinned MAC is the only key that ties the VM's
// interface to a NetworkInterface (→ CompiledNIC.Spec.MAC). CompiledNIC-only: no CompiledVM read, so
// vanilla KubeVirt VMs work too. Only that cluster's CompiledNICs are broker-synced here, so the
// namespace-scoped list is small.
func resolveCompiledNICByMAC(ctx context.Context, c client.Client, namespace, mac string) (resolved, error) {
	want := normMAC(mac)
	if want == "" {
		return resolved{}, fmt.Errorf("empty MAC")
	}
	var list compiledv1.CompiledNICList
	if err := c.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return resolved{}, fmt.Errorf("list CompiledNICs in %s: %w", namespace, err)
	}
	var match *compiledv1.CompiledNIC
	for i := range list.Items {
		if normMAC(list.Items[i].Spec.MAC) != want {
			continue
		}
		if match != nil {
			return resolved{}, fmt.Errorf("multiple CompiledNICs in %s match MAC %s (%s, %s)",
				namespace, mac, match.Name, list.Items[i].Name)
		}
		match = &list.Items[i]
	}
	if match == nil {
		return resolved{}, fmt.Errorf("no CompiledNIC in %s matches MAC %s (not compiled/synced yet?)", namespace, mac)
	}
	if match.Spec.VNI == 0 {
		return resolved{}, fmt.Errorf("CompiledNIC %s/%s matched MAC %s but has no VNI — not compiled/synced yet", namespace, match.Name, mac)
	}
	return resolved{VNI: uint32(match.Spec.VNI), IPs: match.Spec.OverlayIPs, MAC: match.Spec.MAC}, nil
}

func normMAC(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
