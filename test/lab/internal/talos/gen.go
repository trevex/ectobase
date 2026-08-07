package talos

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/docstrip"
	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// cpTaint matches the control-plane NoSchedule taint entry `talosctl gen config`
// emits in the KubeNodeConfig doc. A config-patch can't clear it (Talos's typed merge
// unions map keys but keeps the base value; the legacy cluster.allowSchedulingOnControlPlanes
// errors "already set" on v1.14), so we strip it post-gen — the lab's single
// control-plane-only nodes must run every workload.
var cpTaint = regexp.MustCompile(`taints:\n\s*node-role\.kubernetes\.io/control-plane: NoSchedule`)

// stripControlPlaneTaint removes the control-plane NoSchedule taint from a generated
// machine config, leaving an empty taints map, so the control-plane node is schedulable.
func stripControlPlaneTaint(cfg []byte) []byte {
	return cpTaint.ReplaceAll(cfg, []byte("taints: {}"))
}

// Userdata is the container USERDATA env value carrying a base64 machine config.
func Userdata(machineConfig []byte) string {
	return "USERDATA=" + base64.StdEncoding.EncodeToString(machineConfig) + "\n"
}

// appendFile appends s to the file at path (which must exist).
func appendFile(path, s string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(s); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// GenSpec drives Gen: a container-mode Talos control plane for ONE cluster,
// rendered into Dir with our multi-cluster <cluster>-<index> file names.
type GenSpec struct {
	Dir          string // build/<name>/talos (already created & clean)
	SecretsPath  string // persisted PKI, OUTSIDE Dir
	MountsDir    string // build/<name>/mounts; per-node /run,/var,/etc/cni bind sources live under here
	ClusterName  string
	Endpoint     string   // https://[apivip]:6443
	K8sVersion   string   // desired Kubernetes version (talosctl --kubernetes-version); "" = talosctl default
	SANs         []string // additional SANs
	ClusterPatch []byte   // rendered cluster-wide patch → Dir/cluster.yaml
	StripDocs    []string // machine-config doc kinds to drop from controlplane
	Nodes        []config.DerivedNode
	NodePatch    func(n config.DerivedNode) ([]byte, error) // per-node config patch
	PeerConfig   func(n config.DerivedNode) ([]byte, error) // extra docs appended to node (may be nil)
}

// Gen renders the full Talos machine-config set for a container-mode cluster.
func Gen(ctx context.Context, s GenSpec) error {
	if err := os.WriteFile(filepath.Join(s.Dir, "cluster.yaml"), s.ClusterPatch, 0o644); err != nil {
		return err
	}
	if _, err := os.Stat(s.SecretsPath); os.IsNotExist(err) {
		if err := exec.Run(ctx, "talosctl", "gen", "secrets", "-o", s.SecretsPath); err != nil {
			return err
		}
	}
	genArgs := []string{"gen", "config", s.ClusterName, s.Endpoint,
		"--output-dir", s.Dir, "--force", "--with-secrets", s.SecretsPath,
		"--with-docs=false", "--with-examples=false",
		"--additional-sans", strings.Join(s.SANs, ","),
		"--config-patch", "@" + filepath.Join(s.Dir, "cluster.yaml"),
	}
	if s.K8sVersion != "" {
		genArgs = append(genArgs, "--kubernetes-version", s.K8sVersion)
	}
	if err := exec.Run(ctx, "talosctl", genArgs...); err != nil {
		return err
	}
	cpPath := filepath.Join(s.Dir, "controlplane.yaml")
	cp, err := os.ReadFile(cpPath)
	if err != nil {
		return err
	}
	stripped, err := docstrip.Strip(cp, s.StripDocs...)
	if err != nil {
		return err
	}
	stripped = stripControlPlaneTaint(stripped)
	if err := os.WriteFile(cpPath, stripped, 0o644); err != nil {
		return err
	}
	for _, nd := range s.Nodes {
		name := fmt.Sprintf("%s-%d", nd.Cluster, nd.Index)
		np, err := s.NodePatch(nd)
		if err != nil {
			return fmt.Errorf("node %s patch: %w", name, err)
		}
		npPath := filepath.Join(s.Dir, fmt.Sprintf("node-%s.yaml", name))
		if err := os.WriteFile(npPath, np, 0o644); err != nil {
			return err
		}
		nodeCfg := filepath.Join(s.Dir, fmt.Sprintf("%s.yaml", name))
		// -o overwrites, so the append below always targets a fresh file (idempotent).
		if err := exec.Run(ctx, "talosctl", "machineconfig", "patch", cpPath, "--patch", "@"+npPath, "-o", nodeCfg); err != nil {
			return err
		}
		if s.PeerConfig != nil {
			peer, err := s.PeerConfig(nd)
			if err != nil {
				return fmt.Errorf("node %s peer: %w", name, err)
			}
			if err := appendFile(nodeCfg, string(peer)); err != nil {
				return err
			}
		}
		raw, err := os.ReadFile(nodeCfg)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(s.Dir, fmt.Sprintf("%s.env", name)), []byte(Userdata(raw)), 0o644); err != nil {
			return err
		}
		for _, sub := range []string{"run", "var", "cni"} {
			if err := os.MkdirAll(filepath.Join(s.MountsDir, name, sub), 0o755); err != nil {
				return err
			}
		}
	}
	return nil
}
