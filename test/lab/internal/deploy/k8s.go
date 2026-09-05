// Package deploy wraps helm/kubectl for post-bootstrap cluster setup: installing
// the CNI + a storage provisioner and waiting for nodes to converge. Every call
// targets a kubeconfig path explicitly (no global env mutation).
package deploy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/clab"
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
// kubeconfig. kubeconfig's server is the anycast API VIP, which lives on a
// per-node vip0 dummy interface ONLY while that node's own apiserver is healthy
// (see the cluster-patch api-vip pod) — reachable from the host over the fabric
// only once GoBGP/RA have converged and stayed converged. Right after bootstrap
// that is exactly what is still flapping, so this reaches it instead via `nsenter
// -t <pid> -n` into nodeContainer's OWN network namespace (pid resolved with
// clab.ContainerPID): for a single-CP cluster the VIP (and the node itself) is
// on-link inside that netns, immune to fabric-routing flaps. nodeContainer is the
// clab container name of a control-plane node (the caller picks one that should be
// currently serving the VIP).
func WaitAPIServer(ctx context.Context, kubeconfig, nodeContainer string) error {
	slog.Info("waiting for the Kubernetes API server", "via", nodeContainer)
	pid, err := clab.ContainerPID(ctx, nodeContainer)
	if err != nil {
		return fmt.Errorf("resolve %s container pid for nsenter: %w", nodeContainer, err)
	}
	return wait.WaitFor(ctx, 5*time.Minute, 3*time.Second, func() (bool, error) {
		nsArgs := []string{"nsenter", "-t", pid, "-n", "kubectl", "--kubeconfig", kubeconfig,
			"get", "--raw=/readyz", "--request-timeout=5s"}
		err := exec.Sudo(ctx, nsArgs...)
		return err == nil, err
	})
}

// HelmInstall installs or upgrades chart (from repo, pinned to version) as release
// name in kube-system, applying valuesFile, and waits for the rollout.
func HelmInstall(ctx context.Context, kubeconfig, name, chart, repo, version, valuesFile string, sets ...string) error {
	slog.Info("installing helm release", "name", name, "chart", chart, "version", version)
	args := []string{"upgrade", "--install", name, chart,
		"--repo", repo, "--version", version,
		"--namespace", "kube-system",
		"--kubeconfig", kubeconfig,
		"--values", valuesFile}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	args = append(args, "--wait", "--timeout", "10m")
	return exec.Run(ctx, "helm", args...)
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
