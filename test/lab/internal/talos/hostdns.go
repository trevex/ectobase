package talos

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// RebindHostDNS makes Talos re-create its host DNS listeners once the node is up.
//
// Without it NO POD in the cluster can resolve an external name. Talos's dns-resolve-cache serves
// pods from a fixed ULA — fd54:616c:6f73:0:204f:5320:444e:531, "Talos OS DNS1" spelled in ASCII —
// and every pod's upstream resolver points at it. In container mode the runner starts before that
// address has been assigned to the node's loopback and loses the race:
//
//	WARN ignoring ipv6 dns runner error {"component": "dns-resolve-cache", "error": "error
//	creating \"udp6\" packet conn: listen udp6 [fd54:...]:53: bind: cannot assign requested address"}
//
// "ignoring" is literal: Talos logs it, carries on and never retries, so the v6 listener is
// permanently absent while kubelet keeps pointing CoreDNS at it. CoreDNS then answers SERVFAIL for
// every external name, and anything that resolves one fails — which is why a CDI bootImage import
// could never complete, and why `TestTier2Failover` could pass while its disk never attached (the
// old assertion accepted CDI's prime claim, which binds before the import it is waiting on).
//
// There is no config knob. The obvious fix is rejected by Talos outright:
//
//	hostDNS.forwardKubeDNSToHost: false  ->  "forwardKubeDNSToHost must be enabled in container mode"
//
// What the runner does do is re-create every listener when ResolverConfig changes, and by the time
// a cluster is Ready the address exists — so re-applying the resolvers is enough to bind it.
//
// The patch ROTATES the nameservers rather than changing them. Talos needs a diff to react to, and
// the two edge resolvers are interchangeable endpoints of one DNS64 service, so their order carries
// no meaning: the rotation is a no-op to everything except the reconcile it triggers. Pass the same
// addresses the ResolverConfig render uses, or this would quietly repoint the node's resolvers.
//
// Call after the cluster is Ready, on a freshly booted node: the node then still holds the rendered
// order, so the rotated list is always a diff.
func RebindHostDNS(ctx context.Context, cfg *config.Config, cluster, talosconfig string, nameservers []string) error {
	dc, ok := cfg.Derived.Clusters[cluster]
	if !ok {
		return fmt.Errorf("talos rebind host dns: no cluster %q in the config", cluster)
	}
	if len(nameservers) < 2 {
		return fmt.Errorf("talos rebind host dns: need >=2 nameservers to rotate, got %d", len(nameservers))
	}

	rotated := append([]string{nameservers[len(nameservers)-1]}, nameservers[:len(nameservers)-1]...)
	patch := "apiVersion: v1alpha1\nkind: ResolverConfig\nnameservers:\n"
	for _, ns := range rotated {
		patch += "    - address: " + ns + "\n"
	}
	path := filepath.Join(filepath.Dir(talosconfig), "resolver-rebind.yaml")
	if err := os.WriteFile(path, []byte(patch), 0o644); err != nil {
		return fmt.Errorf("write the resolver rebind patch: %w", err)
	}

	// Via nsenter into each node's OWN netns, for the same reason Bootstrap does it: the node's
	// /128 is on-link inside that namespace, so this cannot wedge on fabric convergence.
	for _, n := range dc.Nodes {
		container := clab.ContainerName(cfg.Name, n.Name())
		pid, err := clab.ContainerPID(ctx, container)
		if err != nil {
			return fmt.Errorf("resolve %s container pid for nsenter: %w", container, err)
		}
		if err := exec.Sudo(ctx, "nsenter", "-t", pid, "-n", "talosctl",
			"--talosconfig", talosconfig, "-n", n.IdentityAddr,
			"patch", "machineconfig", "--mode=auto", "--patch", "@"+path); err != nil {
			return fmt.Errorf("rebind host dns on %s: %w", n.Name(), err)
		}
	}
	slog.Info("host DNS listeners rebound", "cluster", cluster, "nodes", len(dc.Nodes))
	return nil
}
