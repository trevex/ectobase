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

// Bootstrap brings up a container-mode Talos control plane for one cluster: it points
// talosctl at each node's fabric /128 (dummy0 VTEP), waits for the Talos API, bootstraps
// etcd once (on the single first control plane), and writes the kubeconfig once the API serves.
//
// Reachability: the Talos nodes have no clab-mgmt interface (network-mode: none), so
// their only interfaces are the two fabric uplinks + dummy0 and the fabric-borne path to
// their Talos API is the node's GoBGP-advertised /128, reached from the host via the
// jump-veth. That path is unreliable exactly while it matters most: right after boot the
// node's routing is still converging (GoBGP peering, RA), so talosctl-over-the-fabric can
// wedge on the very churn it needs to survive. Instead every network-touching talosctl call
// below runs via `sudo nsenter -t <pid> -n` into the target node's OWN container network
// namespace (pid resolved with clab.ContainerPID) — the node's /128 lives on dummy0 INSIDE
// that netns, so it is on-link and reachable with no routing at all, immune to fabric
// flaps. The /128 is a cert SAN (talos.Gen --additional-sans), so TLS to it still
// validates. `talosctl config endpoint/node` merely write the local talosconfig file (no
// network I/O), so those stay host-side.
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

	// Each node's fabric /128 (dummy0 VTEP, GoBGP-advertised) is a talosctl endpoint; the first
	// is the single control plane etcd is bootstrapped on (the others join as etcd learners).
	endpoints := make([]string, 0, len(dc.Nodes))
	for _, n := range dc.Nodes {
		endpoints = append(endpoints, n.IdentityAddr)
	}
	first := endpoints[0]
	firstContainer := clab.ContainerName(cfg.Name, dc.Nodes[0].Name())

	tcmd := func(args ...string) []string { return append([]string{"--talosconfig", talosconfig}, args...) }
	if err := exec.Run(ctx, "talosctl", tcmd(append([]string{"config", "endpoint"}, endpoints...)...)...); err != nil {
		return err
	}
	if err := exec.Run(ctx, "talosctl", tcmd("config", "node", first)...); err != nil {
		return err
	}

	// Resolve the first node's container pid up front — clab.Deploy already ran, so the
	// container exists — and reach the Talos API through it for every step below.
	pid, err := clab.ContainerPID(ctx, firstContainer)
	if err != nil {
		return fmt.Errorf("resolve %s container pid for nsenter: %w", firstContainer, err)
	}
	talosctlLocal := func(args ...string) error {
		nsArgs := append([]string{"nsenter", "-t", pid, "-n", "talosctl"}, args...)
		return exec.Sudo(ctx, nsArgs...)
	}

	// Wait out Talos boot (the node's own netns, so no fabric convergence needed).
	slog.Info("waiting for the Talos API (local, via nsenter)", "cluster", cluster, "endpoint", first)
	if err := wait.WaitFor(ctx, 5*time.Minute, 3*time.Second, func() (bool, error) {
		err := talosctlLocal(tcmd("-n", first, "version")...)
		return err == nil, err
	}); err != nil {
		return fmt.Errorf("talos API unreachable at %s (node container %s up? talos booted?): %w", first, firstContainer, err)
	}

	slog.Info("bootstrapping etcd", "cluster", cluster, "node", first)
	if err := talosctlLocal(tcmd("-n", first, "bootstrap")...); err != nil {
		// bootstrap is once-only; a re-run of a live cluster errors "already bootstrapped".
		slog.Debug("etcd bootstrap (already bootstrapped?)", "err", err)
	}

	// Fetch the kubeconfig once the API serves. --force overwrites any stale file. Still
	// via nsenter (local to the node), so this does not depend on the anycast API VIP
	// having propagated over the fabric yet — talosctl asks the node directly for it.
	slog.Info("writing kubeconfig", "cluster", cluster, "path", kubeconfig)
	if err := wait.WaitFor(ctx, 5*time.Minute, 5*time.Second, func() (bool, error) {
		err := talosctlLocal(tcmd("-n", first, "kubeconfig", kubeconfig, "--force")...)
		return err == nil, err
	}); err != nil {
		return fmt.Errorf("fetch kubeconfig: %w", err)
	}
	slog.Info("control plane bootstrapped", "cluster", cluster, "endpoint", first)
	return nil
}
