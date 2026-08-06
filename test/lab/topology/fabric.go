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
	"strings"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/deploy"
	"github.com/trevex/ectobase/test/lab/internal/exec"
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
	v.ModulesDir = detectModulesDir()

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

	// The host reaches the fabric (node identities + anycast API VIPs, all under
	// fd00:cafe::/32) only through the wan container, whose mgmt address is the
	// host's single next hop into the lab. Add that route so talosctl/kubectl can
	// reach the nodes.
	if err := addHostFabricRoute(ctx, cfg.Name); err != nil {
		return fmt.Errorf("host fabric route: %w", err)
	}

	// Give the fabric real native-IPv6 internet: the wan masquerades fabric egress
	// onto the clab mgmt subnet, which docker does NOT NAT66 to the host uplink, so
	// the host must. (v4 dsts already work via the tayga NAT64 path; this covers
	// dual-stack registries that resolve to a real AAAA.) Best-effort: a host with
	// no native v6 uplink still gets v4/NAT64 egress.
	if err := setupHostEgress(ctx); err != nil {
		slog.Warn("host native-v6 egress setup failed (v4/NAT64 egress still works)", "err", err)
	}

	// Push local images best-effort. Push goes via the registry container's
	// host-published localhost port (127.0.0.1:5000, which is in docker's default
	// insecure-registries — no host dockerd reconfig needed); the nodes pull the
	// same registry:2 process via its fabric mirror addr. A fresh checkout may not
	// have built the :dev images.
	reg := registry.New("127.0.0.1:" + fabric.RegistryPort)
	if err := reg.PushLocal(ctx, cfg.Fabric.Registry.Push); err != nil {
		slog.Warn("push-local images failed (registry unreachable or images not built?)", "err", err)
	}

	for _, cl := range cfg.Fabric.Clusters {
		dc := cfg.Derived.Clusters[cl.Name]
		talosconfig := p.clusterTalosconfig(cl.Name)
		kubeconfig := p.clusterKubeconfig(cl.Name)
		// Bootstrap targets the nodes' own dummy0 identities, not the API VIP: the
		// health-gated VIP is only held (and BGP-advertised) once the apiserver is
		// up, i.e. AFTER bootstrap — targeting it here would be a chicken-and-egg.
		endpoints := make([]string, len(dc.Nodes))
		for i, n := range dc.Nodes {
			endpoints[i] = n.IdentityAddr
		}
		if err := talos.Bootstrap(ctx, talosconfig, kubeconfig, endpoints); err != nil {
			return fmt.Errorf("cluster %s bootstrap: %w", cl.Name, err)
		}
		if err := deploy.WaitAPIServer(ctx, kubeconfig); err != nil {
			return fmt.Errorf("cluster %s api server: %w", cl.Name, err)
		}
		// Untaint BEFORE installing Cilium: these are control-plane-only clusters,
		// so the cilium-operator Deployment can't schedule (→ no pod CIDR → the
		// agent never goes Ready → helm --wait times out) until the control-plane
		// NoSchedule taint is gone.
		if err := deploy.AllowSchedulingOnControlPlanes(ctx, kubeconfig); err != nil {
			return fmt.Errorf("cluster %s untaint: %w", cl.Name, err)
		}
		if err := deploy.HelmInstall(ctx, kubeconfig, "cilium", deploy.CiliumChart,
			deploy.CiliumRepo, deploy.CiliumVersion, p.ciliumValues(cl.Name)); err != nil {
			return fmt.Errorf("cluster %s cilium: %w", cl.Name, err)
		}
		if err := deploy.WaitNodesReady(ctx, kubeconfig, len(dc.Nodes)); err != nil {
			return fmt.Errorf("cluster %s nodes ready: %w", cl.Name, err)
		}
	}

	if err := deployEctobase(ctx, cfg); err != nil {
		return err
	}
	slog.Info("lab up", "name", cfg.Name)
	return nil
}

// Deploy runs ONLY the ectobase substrate deploy against an already-up fabric
// (all cluster kubeconfigs must already exist under build/<name>/). It is the
// `lab deploy` entry point, so the deploy can be re-run while iterating without a
// full re-up.
func Deploy(ctx context.Context, cfg *config.Config) error {
	return deployEctobase(ctx, cfg)
}

// centralCluster is the cluster that hosts the central aggregated apiserver +
// controller + reflector. Compute clusters run the ectobase chart with a broker.
const centralCluster = "central"

// deployEctobase builds the flat EctobaseSpec from cfg + the build-tree paths and
// deploys the ectobase substrate onto the clusters.
func deployEctobase(ctx context.Context, cfg *config.Config) error {
	root, err := repoRoot()
	if err != nil {
		return fmt.Errorf("locate repo root: %w", err)
	}
	dc, ok := cfg.Derived.Clusters[centralCluster]
	if !ok {
		return fmt.Errorf("no cluster named %q in the config (need a central cluster for the apiserver + reflector)", centralCluster)
	}
	if len(dc.Nodes) == 0 {
		return fmt.Errorf("central cluster %q has no nodes", centralCluster)
	}

	p := buildPaths(cfg)
	var compute []deploy.ComputeCluster
	for _, cl := range cfg.Fabric.Clusters {
		if cl.Name == centralCluster {
			continue
		}
		compute = append(compute, deploy.ComputeCluster{
			Name:       cl.Name,
			Kubeconfig: p.clusterKubeconfig(cl.Name),
		})
	}

	spec := deploy.EctobaseSpec{
		RepoRoot:          root,
		WorkDir:           filepath.Join(p.build, "deploy"),
		CentralKubeconfig: p.clusterKubeconfig(centralCluster),
		CentralAPIVip:     dc.APIVipAddr,
		CentralIdentity:   dc.Nodes[0].IdentityAddr,
		ChartPath:         filepath.Join(root, "deploy/charts/ectobase"),
		NADCRDPath:        filepath.Join(root, "test/lab/deploy/nad-crd.yaml"),
		Compute:           compute,
	}
	return deploy.Ectobase(ctx, spec)
}

// repoRoot walks up from the current working directory (the config dir, i.e.
// test/lab) until it finds the dir containing go.work (the repo root).
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.work not found walking up from %q", dir)
		}
		dir = parent
	}
}

// fabricHostPrefix is the aggregate the host routes into the fabric: every
// cluster's node identities and anycast API VIPs live under fd00:cafe::/32.
const fabricHostPrefix = "fd00:cafe::/32"

// addHostFabricRoute points fd00:cafe::/32 at the wan container's mgmt address so
// the host (talosctl/kubectl) can reach the nodes + API VIPs through the fabric.
func addHostFabricRoute(ctx context.Context, labName string) error {
	via, err := clab.MgmtIP6(ctx, labName, "wan")
	if err != nil {
		return fmt.Errorf("wan mgmt IPv6: %w", err)
	}
	if via == "" {
		return fmt.Errorf("wan container has no mgmt IPv6 (is the mgmt network dual-stack?)")
	}
	slog.Info("routing host into the fabric", "prefix", fabricHostPrefix, "via", via)
	return exec.Sudo(ctx, "ip", "-6", "route", "replace", fabricHostPrefix, "via", via)
}

// delHostFabricRoute removes the host→fabric route (best-effort, on down).
func delHostFabricRoute(ctx context.Context) {
	if err := exec.Sudo(ctx, "ip", "-6", "route", "del", fabricHostPrefix); err != nil {
		slog.Debug("remove host fabric route (already gone?)", "err", err)
	}
}

// detectV6Uplink returns the host interface carrying the default IPv6 route (the
// real internet uplink the fabric masquerades onto), or "" if the host has none.
func detectV6Uplink(ctx context.Context) string {
	out, err := exec.OutputStr(ctx, "ip", "-6", "route", "show", "default")
	if err != nil {
		return ""
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// setupHostEgress enables the host to forward + NAT66 the clab mgmt subnet onto
// its real IPv6 uplink, so the wan's masqueraded native-v6 fabric egress reaches
// the internet. Idempotent (rules are -C-guarded). No-op if the host has no v6
// uplink (v4/NAT64 egress via tayga is unaffected).
func setupHostEgress(ctx context.Context) error {
	uplink := detectV6Uplink(ctx)
	if uplink == "" {
		slog.Info("no host IPv6 uplink; skipping native-v6 fabric egress (v4/NAT64 unaffected)")
		return nil
	}
	slog.Info("enabling native-v6 fabric egress", "uplink", uplink, "subnet", fabric.MgmtV6Subnet)
	if err := exec.Sudo(ctx, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"); err != nil {
		return err
	}
	rules := [][]string{
		{"-t", "nat", "POSTROUTING", "-s", fabric.MgmtV6Subnet, "-o", uplink, "-j", "MASQUERADE"},
		{"FORWARD", "-s", fabric.MgmtV6Subnet, "-o", uplink, "-j", "ACCEPT"},
		{"FORWARD", "-d", fabric.MgmtV6Subnet, "-i", uplink, "-j", "ACCEPT"},
	}
	for _, r := range rules {
		// -C to check, -I to add only if absent (idempotent).
		check := insertAfterTable(append([]string{"ip6tables"}, r...), "-C")
		if exec.Sudo(ctx, check...) == nil {
			continue
		}
		add := insertAfterTable(append([]string{"ip6tables"}, r...), "-I")
		if err := exec.Sudo(ctx, add...); err != nil {
			return err
		}
	}
	return nil
}

// insertAfterTable splices the ip6tables op (-C/-I) after an optional "-t <table>"
// prefix so both `ip6tables -t nat -C ...` and `ip6tables -C ...` form correctly.
func insertAfterTable(argv []string, op string) []string {
	// argv[0]=="ip6tables"; if argv[1]=="-t", op goes after argv[2].
	if len(argv) > 2 && argv[1] == "-t" {
		out := append([]string{argv[0], argv[1], argv[2], op}, argv[3:]...)
		return out
	}
	return append([]string{argv[0], op}, argv[1:]...)
}

// teardownHostEgress removes the native-v6 egress rules (best-effort, on down).
func teardownHostEgress(ctx context.Context) {
	uplink := detectV6Uplink(ctx)
	if uplink == "" {
		return
	}
	dels := [][]string{
		{"-t", "nat", "-D", "POSTROUTING", "-s", fabric.MgmtV6Subnet, "-o", uplink, "-j", "MASQUERADE"},
		{"-D", "FORWARD", "-s", fabric.MgmtV6Subnet, "-o", uplink, "-j", "ACCEPT"},
		{"-D", "FORWARD", "-d", fabric.MgmtV6Subnet, "-i", uplink, "-j", "ACCEPT"},
	}
	for _, d := range dels {
		_ = exec.Sudo(ctx, append([]string{"ip6tables"}, d...)...)
	}
}

// Down destroys the containerlab topology and removes build/<name>/ while
// preserving the registry cache for a warm re-up. With purge, it removes the whole
// build tree including the cache.
func Down(ctx context.Context, cfg *config.Config, purge bool) error {
	p := buildPaths(cfg)

	delHostFabricRoute(ctx)
	teardownHostEgress(ctx)

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

// detectModulesDir returns the host kernel-modules parent dir for the running
// kernel (bind-mounted into the Talos container nodes). Standard on most distros
// is /usr/lib/modules or /lib/modules; NixOS keeps them under /run/booted-system.
// Falls back to /usr/lib/modules (the container's own expected path) if none hold
// the running kernel — clab will then error clearly on the missing bind.
func detectModulesDir() string {
	rel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	kver := strings.TrimSpace(string(rel))
	for _, cand := range []string{
		"/usr/lib/modules",
		"/lib/modules",
		"/run/booted-system/kernel-modules/lib/modules",
		"/run/current-system/kernel-modules/lib/modules",
	} {
		if kver != "" {
			if st, err := os.Stat(filepath.Join(cand, kver)); err == nil && st.IsDir() {
				return cand
			}
		}
	}
	return "/usr/lib/modules"
}
