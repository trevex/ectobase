package talos

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/wait"
)

// Bootstrap brings up a container-mode Talos control plane for one cluster: it points
// talosctl at each node's fabric /128 (dummy0 VTEP), waits for the Talos API, bootstraps
// etcd once (on the single first control plane), and writes the kubeconfig once the API serves.
//
// Reachability: bootstrap runs over the FABRIC, not a mgmt net — the Talos nodes have no
// clab-mgmt interface (network-mode: none), so their only interfaces are the two fabric
// uplinks + dummy0 and the sole path to their Talos API is the node's GoBGP-advertised /128,
// reached from the host via the jump-veth. talosctl therefore waits out Talos boot + GoBGP
// convergence before the API answers on the /128. The /128 is a cert SAN (talos.Gen
// --additional-sans), so TLS to it validates. This makes node egress fabric-only by
// construction (no mgmt default to leak past the fabric RA/BGP default).
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
	// is the single control plane etcd is bootstrapped on (the others join as etcd learners). The
	// host reaches these over the fabric (jump-veth) once GoBGP advertises them — no mgmt net.
	endpoints := make([]string, 0, len(dc.Nodes))
	for _, n := range dc.Nodes {
		endpoints = append(endpoints, n.IdentityAddr)
	}
	first := endpoints[0]

	tcmd := func(args ...string) []string { return append([]string{"--talosconfig", talosconfig}, args...) }
	if err := exec.Run(ctx, "talosctl", tcmd(append([]string{"config", "endpoint"}, endpoints...)...)...); err != nil {
		return err
	}
	if err := exec.Run(ctx, "talosctl", tcmd("config", "node", first)...); err != nil {
		return err
	}

	// Over the fabric the API only answers after Talos boots + GoBGP peers + the /128 propagates to
	// the host (node -> ToR -> edge -> jump-veth), so wait more generously than the old mgmt path.
	slog.Info("waiting for the Talos API over the fabric", "cluster", cluster, "endpoint", first)
	if err := wait.WaitFor(ctx, 5*time.Minute, 3*time.Second, func() (bool, error) {
		err := exec.Run(ctx, "talosctl", tcmd("-n", first, "version")...)
		return err == nil, err
	}); err != nil {
		return fmt.Errorf("talos API unreachable at %s over the fabric (lab up? GoBGP converged? jump-veth route present?): %w", first, err)
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
