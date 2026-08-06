// Package topology is the lab's orchestration layer: it expands every render
// template into build/<name>/, drives containerlab, and bootstraps + configures
// each cluster. It is the single place the render/up/down CLI commands call into.
//
// Build-dir layout (paths are relative to the clab topology file at
// build/<name>/<name>.clab.yml, so clab binds/startup-configs resolve):
//
//	build/<name>/
//	  <name>.clab.yml                 fabric.clab.yml.tmpl
//	  vyos/{edge1,edge2,sw1,sw2}.boot vyos .set → RenderBoot
//	  talos/
//	    <cluster>-<index>.env         per-node USERDATA (flat, matches clab bind)
//	    <cluster>-<index>.yaml        per-node machine config
//	    <cluster>-talosconfig         per-cluster talosconfig (Bootstrap)
//	    <cluster>-secrets.yaml        per-cluster PKI
//	    talosconfig, controlplane.yaml, cluster.yaml, node-*.yaml  (scratch)
//	  mounts/<cluster>-<index>/{run,var,cni}
//	  k8s/cilium-<cluster>.yaml       cilium-values.yaml.tmpl
//	  registry/config.yml             registry/config.yml.tmpl
//	  registry-cache/                 persistent mirror cache (preserved on down)
//
// Per-cluster talosconfig wrinkle: `talosctl gen config` writes talosconfig +
// controlplane.yaml into --output-dir. All clusters share the flat talos/ dir so
// the per-node .env files land flat where the clab template expects them
// (talos/<cluster>-<index>.env). Each cluster's Gen therefore overwrites the
// scratch talosconfig; we copy it to talos/<cluster>-talosconfig right after each
// cluster's Gen (secrets are already per-cluster via SecretsPath) so Bootstrap has
// a distinct talosconfig per cluster.
package topology

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/deploy"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
	"github.com/trevex/ectobase/test/lab/internal/registry"
	"github.com/trevex/ectobase/test/lab/internal/render"
	"github.com/trevex/ectobase/test/lab/internal/talos"
	"github.com/trevex/ectobase/test/lab/internal/vyos"
	"github.com/trevex/ectobase/test/lab/templates"
)

// stripDocs are the machine-config doc kinds dropped from the generated
// controlplane: HostnameConfig (talosctl v1.14 emits one that collides with our
// machine.network.hostname → validate fails) and KubeFlannelCNIConfig (CNI=none,
// Cilium installs the CNI).
var stripDocs = []string{"HostnameConfig", "KubeFlannelCNIConfig"}

// paths bundles the build-tree paths for one lab.
type paths struct {
	build  string // build/<name>
	topo   string // build/<name>/<name>.clab.yml
	vyos   string // build/<name>/vyos
	talos  string // build/<name>/talos
	mounts string // build/<name>/mounts
	k8s    string // build/<name>/k8s
	reg    string // build/<name>/registry
}

func buildPaths(cfg *config.Config) paths {
	b := render.BuildDir(cfg.Name)
	return paths{
		build:  b,
		topo:   filepath.Join(b, cfg.Name+".clab.yml"),
		vyos:   filepath.Join(b, "vyos"),
		talos:  filepath.Join(b, "talos"),
		mounts: filepath.Join(b, "mounts"),
		k8s:    filepath.Join(b, "k8s"),
		reg:    filepath.Join(b, "registry"),
	}
}

// clusterTalosconfig is the per-cluster talosconfig Bootstrap uses.
func (p paths) clusterTalosconfig(cluster string) string {
	return filepath.Join(p.talos, cluster+"-talosconfig")
}

func (p paths) clusterKubeconfig(cluster string) string {
	return filepath.Join(p.build, cluster+".kubeconfig")
}

func (p paths) ciliumValues(cluster string) string {
	return filepath.Join(p.k8s, "cilium-"+cluster+".yaml")
}

// Render expands every template into build/<name>/ and runs talosctl gen per
// cluster. It is idempotent: templates are re-rendered and per-cluster secrets are
// reused when present.
func Render(ctx context.Context, cfg *config.Config) error {
	p := buildPaths(cfg)
	v := fabric.Build(cfg)

	for _, dir := range []string{p.build, p.vyos, p.talos, p.mounts, p.k8s, p.reg} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	// clab topology.
	if err := render.FileFS(templates.FS, "fabric.clab.yml.tmpl", p.topo, v); err != nil {
		return fmt.Errorf("render clab topology: %w", err)
	}

	// VyOS edges + switches: render the .set, then convert to config.boot.
	vyosImage := cfg.Images["vyos"]
	for _, e := range []int{1, 2} {
		set, err := render.StringFS(templates.FS, "vyos/edge.set.tmpl", vyos.EdgeCtx{View: v, Edge: e})
		if err != nil {
			return fmt.Errorf("render edge%d set: %w", e, err)
		}
		boot, err := vyos.RenderBoot(ctx, vyosImage, []byte(set))
		if err != nil {
			return fmt.Errorf("render edge%d boot: %w", e, err)
		}
		if err := os.WriteFile(filepath.Join(p.vyos, fmt.Sprintf("edge%d.boot", e)), boot, 0o644); err != nil {
			return err
		}
	}
	for _, s := range []int{1, 2} {
		set, err := render.StringFS(templates.FS, "vyos/switch.set.tmpl", vyos.SwitchCtx{View: v, SW: s})
		if err != nil {
			return fmt.Errorf("render sw%d set: %w", s, err)
		}
		boot, err := vyos.RenderBoot(ctx, vyosImage, []byte(set))
		if err != nil {
			return fmt.Errorf("render sw%d boot: %w", s, err)
		}
		if err := os.WriteFile(filepath.Join(p.vyos, fmt.Sprintf("sw%d.boot", s)), boot, 0o644); err != nil {
			return err
		}
	}

	// Per-cluster Talos machine configs + Cilium values.
	for _, cl := range cfg.Fabric.Clusters {
		dc := cfg.Derived.Clusters[cl.Name]
		if err := genCluster(ctx, cfg, v, p, cl.Name, dc); err != nil {
			return fmt.Errorf("cluster %s: %w", cl.Name, err)
		}
		if err := render.FileFS(templates.FS, "k8s/cilium-values.yaml.tmpl",
			p.ciliumValues(cl.Name), talos.NewClusterCtx(v, cl.Name)); err != nil {
			return fmt.Errorf("render cilium values for %s: %w", cl.Name, err)
		}
	}

	// Registry config + persistent cache dir.
	if err := render.FileFS(templates.FS, "registry/config.yml.tmpl",
		filepath.Join(p.reg, "config.yml"), v); err != nil {
		return fmt.Errorf("render registry config: %w", err)
	}
	if err := registry.EnsureCache(ctx, p.build); err != nil {
		return fmt.Errorf("registry cache dir: %w", err)
	}

	slog.Info("rendered lab", "build", p.build, "clusters", len(cfg.Fabric.Clusters))
	return nil
}

// genCluster renders one cluster's Talos machine-config set and preserves its
// talosconfig under a per-cluster name (see the package doc for the flat-dir
// rationale).
func genCluster(ctx context.Context, cfg *config.Config, v *fabric.View, p paths, cluster string, dc config.DerivedCluster) error {
	clusterPatch, err := render.StringFS(templates.FS, "talos/cluster-patch.yaml.tmpl", talos.NewClusterCtx(v, cluster))
	if err != nil {
		return fmt.Errorf("render cluster patch: %w", err)
	}
	nodePatch := func(n config.DerivedNode) ([]byte, error) {
		s, err := render.StringFS(templates.FS, "talos/node-patch.yaml.tmpl", talos.NewNodeCtx(v, n))
		return []byte(s), err
	}
	peerConfig := func(n config.DerivedNode) ([]byte, error) {
		s, err := render.StringFS(templates.FS, "talos/bgp-peer.yaml.tmpl", talos.NewNodeCtx(v, n))
		return []byte(s), err
	}
	spec := talos.GenSpec{
		Dir:          p.talos,
		SecretsPath:  filepath.Join(p.talos, cluster+"-secrets.yaml"),
		MountsDir:    p.mounts,
		ClusterName:  cluster,
		Endpoint:     fmt.Sprintf("https://[%s]:6443", dc.APIVipAddr),
		K8sVersion:   "", // talosctl default
		SANs:         []string{dc.APIVipAddr, "127.0.0.1"},
		ClusterPatch: []byte(clusterPatch),
		StripDocs:    stripDocs,
		Nodes:        dc.Nodes,
		NodePatch:    nodePatch,
		PeerConfig:   peerConfig,
	}
	if err := talos.Gen(ctx, spec); err != nil {
		return err
	}
	// Preserve this cluster's talosconfig before the next cluster's gen overwrites it.
	tc, err := os.ReadFile(filepath.Join(p.talos, "talosconfig"))
	if err != nil {
		return fmt.Errorf("read talosconfig: %w", err)
	}
	if err := os.WriteFile(p.clusterTalosconfig(cluster), tc, 0o644); err != nil {
		return fmt.Errorf("write per-cluster talosconfig: %w", err)
	}
	return nil
}

// Up renders the build tree, deploys the containerlab topology, pushes the local
// :dev images into the in-fabric mirror, then per cluster bootstraps the Talos
// control plane, installs Cilium, waits for Ready, and un-taints the control-plane
// nodes. Finally it deploys the ectobase substrate (T17 stub for now).
func Up(ctx context.Context, cfg *config.Config) error {
	p := buildPaths(cfg)
	if err := Render(ctx, cfg); err != nil {
		return err
	}

	c := clab.Clab{TopoFile: p.topo}
	if err := c.Deploy(ctx); err != nil {
		return fmt.Errorf("clab deploy: %w", err)
	}

	// Push local images best-effort: the registry container must be reachable on
	// the fabric first, and a fresh checkout may not have built the :dev images.
	reg := registry.New("[" + fabric.RegistryAddr + "]:" + fabric.RegistryPort)
	if err := reg.PushLocal(ctx, cfg.Fabric.Registry.Push); err != nil {
		slog.Warn("push-local images failed (registry unreachable or images not built?)", "err", err)
	}

	for _, cl := range cfg.Fabric.Clusters {
		dc := cfg.Derived.Clusters[cl.Name]
		talosconfig := p.clusterTalosconfig(cl.Name)
		kubeconfig := p.clusterKubeconfig(cl.Name)
		if err := talos.Bootstrap(ctx, talosconfig, kubeconfig, []string{dc.APIVipAddr}); err != nil {
			return fmt.Errorf("cluster %s bootstrap: %w", cl.Name, err)
		}
		if err := deploy.WaitAPIServer(ctx, kubeconfig); err != nil {
			return fmt.Errorf("cluster %s api server: %w", cl.Name, err)
		}
		if err := deploy.HelmInstall(ctx, kubeconfig, "cilium", deploy.CiliumChart,
			deploy.CiliumRepo, deploy.CiliumVersion, p.ciliumValues(cl.Name)); err != nil {
			return fmt.Errorf("cluster %s cilium: %w", cl.Name, err)
		}
		if err := deploy.WaitNodesReady(ctx, kubeconfig, len(dc.Nodes)); err != nil {
			return fmt.Errorf("cluster %s nodes ready: %w", cl.Name, err)
		}
		if err := deploy.AllowSchedulingOnControlPlanes(ctx, kubeconfig); err != nil {
			return fmt.Errorf("cluster %s untaint: %w", cl.Name, err)
		}
	}

	if err := deployEctobase(ctx, cfg); err != nil {
		return err
	}
	slog.Info("lab up", "name", cfg.Name)
	return nil
}

// deployEctobase deploys the ectobase substrate onto the clusters. Stub until T17.
func deployEctobase(_ context.Context, _ *config.Config) error {
	slog.Info("ectobase deploy: TODO T17")
	return nil
}

// Down destroys the containerlab topology and removes build/<name>/ while
// preserving the registry cache for a warm re-up. With purge, it removes the whole
// build tree including the cache.
func Down(ctx context.Context, cfg *config.Config, purge bool) error {
	p := buildPaths(cfg)

	c := clab.Clab{TopoFile: p.topo}
	if err := c.Destroy(ctx); err != nil {
		slog.Warn("clab destroy (already down?)", "err", err)
	}

	if purge {
		slog.Info("purging build tree (including registry cache)", "build", p.build)
		return os.RemoveAll(p.build)
	}

	// Remove everything under build/<name>/ except the registry cache.
	entries, err := os.ReadDir(p.build)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.Name() == registry.CacheDirName {
			continue
		}
		if err := os.RemoveAll(filepath.Join(p.build, e.Name())); err != nil {
			return err
		}
	}
	slog.Info("lab down (registry cache preserved)", "build", p.build)
	return nil
}
