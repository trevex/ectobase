package talos

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/wait"
)

// Bootstrap brings up an HA Talos control plane reachable at endpoints: it waits
// for the Talos API, bootstraps etcd, and writes kubeconfig once the API serves.
// Nodes are not yet Ready (no CNI); the caller installs the CNI and then waits
// for Ready. talosconfig and kubeconfig are file paths; a pre-existing
// talosconfig is required.
func Bootstrap(ctx context.Context, talosconfig, kubeconfig string, endpoints []string) error {
	if len(endpoints) == 0 {
		return fmt.Errorf("talos bootstrap: no endpoints")
	}
	if _, err := os.Stat(talosconfig); err != nil {
		return fmt.Errorf("no talosconfig at %s — render first: %w", talosconfig, err)
	}
	tcmd := func(args ...string) []string { return append([]string{"--talosconfig", talosconfig}, args...) }
	first := endpoints[0]
	if err := exec.Run(ctx, "talosctl", tcmd(append([]string{"config", "endpoint"}, endpoints...)...)...); err != nil {
		return err
	}
	if err := exec.Run(ctx, "talosctl", tcmd("config", "node", first)...); err != nil {
		return err
	}

	slog.Info("waiting for the Talos API", "endpoint", first)
	if err := wait.WaitFor(ctx, 2*time.Minute, 2*time.Second, func() (bool, error) {
		err := exec.Run(ctx, "talosctl", tcmd("-n", first, "version")...)
		return err == nil, err
	}); err != nil {
		return fmt.Errorf("talos API unreachable at %s (lab up? wan up?): %w", first, err)
	}

	slog.Info("bootstrapping etcd", "node", first)
	if err := exec.Run(ctx, "talosctl", tcmd("-n", first, "bootstrap")...); err != nil {
		slog.Debug("etcd bootstrap (already bootstrapped?)", "err", err)
	}

	// Write kubeconfig once the API is serving. Nodes will NOT reach Ready yet —
	// there is no CNI until the `cluster` action installs Cilium — so the caller
	// installs the CNI and then waits for Ready (see k8s.WaitNodesReady).
	slog.Info("writing kubeconfig", "path", kubeconfig)
	if err := wait.WaitFor(ctx, 5*time.Minute, 5*time.Second, func() (bool, error) {
		err := exec.Run(ctx, "talosctl", tcmd("-n", first, "kubeconfig", "-f", kubeconfig)...)
		return err == nil, err
	}); err != nil {
		return fmt.Errorf("fetch kubeconfig: %w", err)
	}
	slog.Info("control plane bootstrapped", "endpoint", first)
	return nil
}
