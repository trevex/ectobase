package deploy

import (
	"context"
	"fmt"
	"log/slog"
)

// MultusVersion pins the thin Multus plugin. Bumping it is the single place the
// version changes; the URL helper below embeds it. The thin daemonset uses image
// ghcr.io/k8snetworkplumbingwg/multus-cni:<version>, which the in-fabric registry
// mirror pulls onto the nodes.
const MultusVersion = "v4.1.0"

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
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", multusDaemonsetURL()); err != nil {
		return fmt.Errorf("apply multus daemonset: %w", err)
	}
	slog.Info("waiting for the Multus DaemonSet to roll out (up to 5m)")
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", "kube-system",
		"rollout", "status", "ds/kube-multus-ds", "--timeout=5m"); err != nil {
		return fmt.Errorf("wait multus daemonset: %w", err)
	}
	slog.Info("Multus installed", "kubeconfig", kubeconfig)
	return nil
}
