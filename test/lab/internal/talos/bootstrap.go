package talos

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/wait"
)

// Bootstrap brings up a container-mode Talos control plane for one cluster: it
// resolves each node's clab-mgmt address, points talosctl at them, waits for the
// Talos API, bootstraps etcd once (on the single first control plane), and writes
// the kubeconfig once the API serves.
//
// Reachability: bootstrap runs over clab-mgmt (eth0), NOT the fabric — talosctl
// reaches the Talos API on each node's mgmt IP. At this point the anycast API VIP
// and the nodes' GoBGP peerings have not converged (the api-vip static pod only
// claims the VIP once the local apiserver is healthy, which needs etcd bootstrapped
// first), so the mgmt net is the only reachable control channel during bring-up.
//
// Nodes are NOT Ready when this returns: the cluster CNI is "none" (flannel
// stripped), so the caller installs Cilium and then waits for Ready. talosconfig
// and kubeconfig are file paths; talosconfig must already exist (talos.Gen /
// `talosctl gen config` writes it into build/<name>/talos/<cluster>/talosconfig).
func Bootstrap(ctx context.Context, cfg *config.Config, cluster, talosconfig, kubeconfig string) error {
	dc, ok := cfg.Derived.Clusters[cluster]
	if !ok {
		return fmt.Errorf("talos bootstrap: no cluster %q in the config", cluster)
	}
	if len(dc.Nodes) == 0 {
		return fmt.Errorf("talos bootstrap: cluster %q has no nodes", cluster)
	}
	if _, err := os.Stat(talosconfig); err != nil {
		return fmt.Errorf("no talosconfig at %s — render first: %w", talosconfig, err)
	}

	// Resolve every node's clab-mgmt address as a talosctl endpoint; the first is the
	// single control plane etcd is bootstrapped on (the others join as etcd learners).
	mgmtNet := cfg.Name + "-mgmt"
	endpoints := make([]string, 0, len(dc.Nodes))
	for _, n := range dc.Nodes {
		container := clab.ContainerName(cfg.Name, n.Name())
		ip, err := clab.MgmtIP(ctx, container, mgmtNet)
		if err != nil {
			return fmt.Errorf("resolve mgmt IP for %s: %w", container, err)
		}
		endpoints = append(endpoints, ip)
	}
	first := endpoints[0]

	tcmd := func(args ...string) []string { return append([]string{"--talosconfig", talosconfig}, args...) }
	if err := exec.Run(ctx, "talosctl", tcmd(append([]string{"config", "endpoint"}, endpoints...)...)...); err != nil {
		return err
	}
	if err := exec.Run(ctx, "talosctl", tcmd("config", "node", first)...); err != nil {
		return err
	}

	slog.Info("waiting for the Talos API", "cluster", cluster, "endpoint", first)
	if err := wait.WaitFor(ctx, 2*time.Minute, 2*time.Second, func() (bool, error) {
		err := exec.Run(ctx, "talosctl", tcmd("-n", first, "version")...)
		return err == nil, err
	}); err != nil {
		return fmt.Errorf("talos API unreachable at %s (lab up? mgmt up?): %w", first, err)
	}

	slog.Info("bootstrapping etcd", "cluster", cluster, "node", first)
	if err := exec.Run(ctx, "talosctl", tcmd("-n", first, "bootstrap")...); err != nil {
		// bootstrap is once-only; a re-run of a live cluster errors "already bootstrapped".
		slog.Debug("etcd bootstrap (already bootstrapped?)", "err", err)
	}

	// Fetch the kubeconfig once the API serves (its server is the anycast API VIP, so
	// this retries out VIP + GoBGP convergence). --force overwrites any stale file.
	slog.Info("writing kubeconfig", "cluster", cluster, "path", kubeconfig)
	if err := wait.WaitFor(ctx, 5*time.Minute, 5*time.Second, func() (bool, error) {
		err := exec.Run(ctx, "talosctl", tcmd("-n", first, "kubeconfig", kubeconfig, "--force")...)
		return err == nil, err
	}); err != nil {
		return fmt.Errorf("fetch kubeconfig: %w", err)
	}
	slog.Info("control plane bootstrapped", "cluster", cluster, "endpoint", first)
	return nil
}
