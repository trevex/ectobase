// Package talos wraps talosctl to render the machine-config set for a container-mode
// Talos cluster: it gens the cluster PKI + base config, strips the flannel-CNI doc so
// the cluster CNI resolves to "none" (the ectobase datapath owns pod networking),
// applies the per-node patch (the /128-VTEP identity on dummy0), appends the GoBGP
// BGPPeerConfig doc, and emits each node's config as a base64 USERDATA env-file the
// clab Talos node reads at boot.
package talos

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"

	"github.com/trevex/ectobase/test/lab/internal/docstrip"
	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// Userdata is the container USERDATA env value carrying a base64 machine config.
func Userdata(machineConfig []byte) string {
	return "USERDATA=" + base64.StdEncoding.EncodeToString(machineConfig) + "\n"
}

// NodeSpec is one node's render inputs: its unique Name (<cluster>-<index>, the clab
// node / env-file / mounts basename), its rendered per-node Patch, and the extra Peer
// doc(s) appended to its config (the BGPPeerConfig; nil to skip).
type NodeSpec struct {
	Name  string
	Patch []byte
	Peer  []byte
}

// GenSpec drives Gen for one cluster: a container-mode Talos control plane rendered
// into Dir.
type GenSpec struct {
	Dir          string // build/<name>/talos/<cluster> (already created & clean)
	SecretsPath  string // persisted PKI, OUTSIDE Dir, per cluster (stable across renders)
	MountsDir    string // per-node /run,/var,/etc/cni bind sources live under here
	ClusterName  string
	Endpoint     string   // https://[apiVip]:6443
	SANs         []string // additional SANs (API VIP + node identities)
	ClusterPatch []byte   // rendered cluster-wide patch -> Dir/cluster.yaml
	StripDocs    []string // machine-config doc kinds to drop from controlplane
	Nodes        []NodeSpec
}

// Gen renders the full Talos machine-config set for one container-mode cluster.
func Gen(ctx context.Context, s GenSpec) error {
	if err := os.WriteFile(filepath.Join(s.Dir, "cluster.yaml"), s.ClusterPatch, 0o644); err != nil {
		return err
	}
	// Secrets live OUTSIDE Dir so the PKI stays stable across re-renders (Dir is wiped
	// each render). Gen them once; reuse thereafter.
	if _, err := os.Stat(s.SecretsPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(s.SecretsPath), 0o755); err != nil {
			return err
		}
		if err := exec.Run(ctx, "talosctl", "gen", "secrets", "-o", s.SecretsPath); err != nil {
			return err
		}
	}
	if err := exec.Run(ctx, "talosctl", "gen", "config", s.ClusterName, s.Endpoint,
		"--output-dir", s.Dir, "--force", "--with-secrets", s.SecretsPath,
		"--with-docs=false", "--with-examples=false",
		"--additional-sans", strings.Join(s.SANs, ","),
		"--config-patch", "@"+filepath.Join(s.Dir, "cluster.yaml"),
	); err != nil {
		return err
	}
	// Strip the CNI-flannel (+ discovery/hostname) docs from the control-plane base:
	// with no CNI doc and no legacy .cluster.network, Talos 1.14 resolves the cluster
	// CNI to "none".
	cpPath := filepath.Join(s.Dir, "controlplane.yaml")
	cp, err := os.ReadFile(cpPath)
	if err != nil {
		return err
	}
	stripped, err := docstrip.Strip(cp, s.StripDocs...)
	if err != nil {
		return err
	}
	// Drop the control-plane NoSchedule taint from KubeNodeConfig: these are
	// control-plane-only clusters (every node is a fabric host that must run the
	// ectobase datapath + workloads), so the control planes must stay schedulable.
	// Talos OWNS + reconciles this taint back, so a one-shot `kubectl taint ... -`
	// races (cert-manager & the pool pods only schedule while it's briefly off);
	// removing it from the declarative config is the only durable fix on Talos 1.14
	// (the deprecated cluster.allowSchedulingOnControlPlanes conflicts with the taint
	// and fails config validation at boot, and patch can't delete a map key).
	stripped, err = docstrip.RemoveKeys(stripped, "KubeNodeConfig", "taints")
	if err != nil {
		return err
	}
	if err := os.WriteFile(cpPath, stripped, 0o644); err != nil {
		return err
	}
	for _, n := range s.Nodes {
		npPath := filepath.Join(s.Dir, n.Name+"-patch.yaml")
		if err := os.WriteFile(npPath, n.Patch, 0o644); err != nil {
			return err
		}
		nodeCfg := filepath.Join(s.Dir, n.Name+".yaml")
		// -o overwrites, so the append below always targets a fresh file (idempotent).
		if err := exec.Run(ctx, "talosctl", "machineconfig", "patch", cpPath, "--patch", "@"+npPath, "-o", nodeCfg); err != nil {
			return err
		}
		if n.Peer != nil {
			if err := appendFile(nodeCfg, n.Peer); err != nil {
				return err
			}
		}
		raw, err := os.ReadFile(nodeCfg)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(s.Dir, n.Name+".env"), []byte(Userdata(raw)), 0o644); err != nil {
			return err
		}
		// Talos' SetupSharedFilesystems marks /var, /etc/cni and /run MS_SHARED, which
		// needs them to be real mount points; bind per-node dirs (on disk, so /var is
		// not pinned in RAM).
		for _, sub := range []string{"run", "var", "cni"} {
			if err := os.MkdirAll(filepath.Join(s.MountsDir, n.Name, sub), 0o755); err != nil {
				return err
			}
		}
	}
	return nil
}

// appendFile appends b to the file at path (which must exist).
func appendFile(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
