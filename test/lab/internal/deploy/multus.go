package deploy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// MultusVersion pins the thin Multus plugin. Bumping it is the single place the
// version changes; the URL helper below embeds it. The thin daemonset uses image
// ghcr.io/k8snetworkplumbingwg/multus-cni:<version>, which the in-fabric registry
// mirror pulls onto the nodes.
const MultusVersion = "v4.1.0"

// multusImage is the multus-cni image repo. The upstream daemonset manifest ships it at the
// rolling `:snapshot` tag; Multus rewrites that to `:MultusVersion` before applying (see below).
const multusImage = "ghcr.io/k8snetworkplumbingwg/multus-cni"

// multusDaemonsetURL is the versioned upstream thin-plugin daemonset manifest.
func multusDaemonsetURL() string {
	return "https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/" +
		MultusVersion + "/deployments/multus-daemonset.yml"
}

// Multus installs the thin Multus CNI plugin (pinned MultusVersion) onto one
// already-up COMPUTE cluster and waits for its DaemonSet to roll out.
//
// The thin daemonset snap-installs /opt/cni/bin/multus and writes
// /etc/cni/net.d/00-multus.conf, which delegates the pod's DEFAULT network to the
// lexicographically-first existing conf on the node (kindnet here). Our overlay is
// attached as a Multus SECONDARY network (via a NetworkAttachmentDefinition that
// references flowplane-cni + the pod's k8s.v1.cni.cncf.io/networks annotation), so
// Multus wrapping kindnet does not change the pod's primary connectivity — it just
// enables the secondary attach through our CNI.
//
// Idempotent (kubectl apply). kubectl runs on the HOST (which has internet); image
// pulls happen on the NODES via the registry mirror.
func Multus(ctx context.Context, r Runner, kubeconfig string) error {
	r = runnerOf(r)

	slog.Info("installing Multus (thin)", "version", MultusVersion, "kubeconfig", kubeconfig)
	// The upstream thin daemonset manifest hardcodes the ROLLING `multus-cni:snapshot` image
	// (main-branch — non-deterministic per pull and cache-unstable in the mirror) even at a pinned
	// manifest tag, so fetch the manifest and rewrite the image to the pinned MultusVersion before
	// applying. This makes the deployed image reproducible and lets the in-fabric mirror cache it
	// stably.
	raw, err := r.Output(ctx, "curl", "-fsSL", multusDaemonsetURL())
	if err != nil {
		return fmt.Errorf("fetch multus daemonset manifest: %w", err)
	}
	manifest := strings.ReplaceAll(string(raw), multusImage+":snapshot", multusImage+":"+MultusVersion)
	if err := r.RunStdin(ctx, manifest, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"); err != nil {
		return fmt.Errorf("apply multus daemonset: %w", err)
	}
	// Wait generously: a COLD pull of the multus image through the fabric mirror can exceed several
	// minutes on a slow uplink (the same fabric-cold-pull reason the dispatch apiserver gets 12m); once
	// the mirror has cached it, restarts are fast.
	slog.Info("waiting for the Multus DaemonSet to roll out (up to 12m)")
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", "kube-system",
		"rollout", "status", "ds/kube-multus-ds", "--timeout=12m"); err != nil {
		return fmt.Errorf("wait multus daemonset: %w", err)
	}
	slog.Info("Multus installed", "kubeconfig", kubeconfig)
	return nil
}
