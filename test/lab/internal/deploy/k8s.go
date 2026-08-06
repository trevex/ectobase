// Package deploy wraps helm/kubectl for post-bootstrap cluster setup: installing
// the CNI + a storage provisioner and waiting for nodes to converge. Every call
// targets a kubeconfig path explicitly (no global env mutation).
package deploy

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/wait"
)

// Cilium chart pin (installed by the cluster action).
const (
	CiliumRepo    = "https://helm.cilium.io"
	CiliumChart   = "cilium"
	CiliumVersion = "1.20.0"
)

// WaitAPIServer blocks until the Kubernetes API server answers /readyz via
// kubeconfig. After bootstrap the endpoint is the anycast API VIP, which is only
// announced once a node's apiserver is healthy — so this also waits out VIP + BGP
// convergence before anything (Cilium, kubectl) tries to talk to the cluster.
func WaitAPIServer(ctx context.Context, kubeconfig string) error {
	slog.Info("waiting for the Kubernetes API server")
	return wait.WaitFor(ctx, 5*time.Minute, 3*time.Second, func() (bool, error) {
		err := exec.Run(ctx, "kubectl", "--kubeconfig", kubeconfig,
			"get", "--raw=/readyz", "--request-timeout=5s")
		return err == nil, err
	})
}

// HelmInstall installs or upgrades chart (from repo, pinned to version) as release
// name in kube-system, applying valuesFile, and waits for the rollout.
func HelmInstall(ctx context.Context, kubeconfig, name, chart, repo, version, valuesFile string) error {
	slog.Info("installing helm release", "name", name, "chart", chart, "version", version)
	return exec.Run(ctx, "helm", "upgrade", "--install", name, chart,
		"--repo", repo, "--version", version,
		"--namespace", "kube-system",
		"--kubeconfig", kubeconfig,
		"--values", valuesFile,
		"--wait", "--timeout", "10m")
}

// Apply applies the manifest at path to the cluster (server-side create/update).
func Apply(ctx context.Context, kubeconfig, path string) error {
	slog.Info("applying manifest", "path", path)
	return exec.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", path)
}

// SetDefaultStorageClass marks sc the cluster's default StorageClass.
func SetDefaultStorageClass(ctx context.Context, kubeconfig, sc string) error {
	slog.Info("marking default StorageClass", "class", sc)
	return exec.Run(ctx, "kubectl", "--kubeconfig", kubeconfig,
		"patch", "storageclass", sc, "--type=merge",
		"-p", `{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}`)
}

// AllowSchedulingOnControlPlanes removes the control-plane NoSchedule taint from
// every node so workloads can run. Talos 1.14 bakes that taint into the generated
// KubeNodeConfig (and config-patch maps only deep-merge, so it can't be cleared in
// config); this cluster is control-plane-only, so removing it is the equivalent of
// the old allowSchedulingOnControlPlanes. Idempotent: removing an absent taint is
// not an error for kubectl.
func AllowSchedulingOnControlPlanes(ctx context.Context, kubeconfig string) error {
	slog.Info("removing control-plane NoSchedule taint (control-plane-only cluster)")
	return exec.Run(ctx, "kubectl", "--kubeconfig", kubeconfig,
		"taint", "nodes", "--all", "node-role.kubernetes.io/control-plane-")
}

// WaitNodesReady blocks until at least want nodes report Ready (post-CNI).
func WaitNodesReady(ctx context.Context, kubeconfig string, want int) error {
	slog.Info("waiting for nodes to become Ready", "want", want)
	return wait.WaitFor(ctx, 10*time.Minute, 5*time.Second, func() (bool, error) {
		out, err := exec.Output(ctx, "kubectl", "--kubeconfig", kubeconfig, "get", "nodes", "--no-headers")
		if err != nil {
			return false, err
		}
		return ReadyNodes(out) >= want, nil
	})
}

// ReadyNodes counts `kubectl get nodes --no-headers` lines whose STATUS column
// (2nd field) is exactly "Ready".
func ReadyNodes(out []byte) int {
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "Ready" {
			n++
		}
	}
	return n
}
