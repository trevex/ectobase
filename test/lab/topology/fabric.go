// Package topology is the lab's orchestration layer: it expands every render
// template into build/<name>/, drives containerlab, and bootstraps + configures
// each cluster. It is the single place the render/up/down CLI commands call into.
//
// Build-dir layout (paths are relative to the clab topology file at
// build/<name>/<name>.clab.yml, so clab binds/startup-configs resolve):
//
//	build/<name>/
//	  <name>.clab.yml                 fabric.clab.yml.tmpl
//	  frr/{edge1,edge2,sw1,sw2}.conf + daemons  FRR configs
//	  kind/
//	    <cluster>-kind.yaml           per-cluster kind Cluster config
//	    <cluster>-<index>.prefix      per-node underlay /64 (extraMount → /etc/fabric/prefix)
//	    <cluster>-uplinks             fabric BGP uplinks (extraMount → /etc/fabric/uplinks)
//	    <cluster>-certs.d/            containerd registry-mirror hosts.toml (extraMount)
//	  <cluster>.kubeconfig            collected from `kind get kubeconfig`
//	  registry/config.yml             registry/config.yml.tmpl
//	  registry-cache/                 persistent mirror cache (preserved on down)
package topology

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/deploy"
	"github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
	"github.com/trevex/ectobase/test/lab/internal/frr"
	"github.com/trevex/ectobase/test/lab/internal/registry"
	"github.com/trevex/ectobase/test/lab/internal/render"
	"github.com/trevex/ectobase/test/lab/templates"
)

// paths bundles the build-tree paths for one lab.
type paths struct {
	build string // build/<name>
	topo  string // build/<name>/<name>.clab.yml
	frr   string // build/<name>/frr (edge{1,2}.conf, sw{1,2}.conf, daemons)
	kind  string // build/<name>/kind (per-cluster kind Cluster configs + prefix/uplinks)
	reg   string // build/<name>/registry
}

func buildPaths(cfg *config.Config) paths {
	b := render.BuildDir(cfg.Name)
	return paths{
		build: b,
		topo:  filepath.Join(b, cfg.Name+".clab.yml"),
		frr:   filepath.Join(b, "frr"),
		kind:  filepath.Join(b, "kind"),
		reg:   filepath.Join(b, "registry"),
	}
}

func (p paths) clusterKubeconfig(cluster string) string {
	return filepath.Join(p.build, cluster+".kubeconfig")
}

// Render expands every template into build/<name>/. It is idempotent: templates are
// re-rendered on each call.
func Render(ctx context.Context, cfg *config.Config) error {
	p := buildPaths(cfg)
	v := fabric.Build(cfg)

	for _, dir := range []string{p.build, p.frr, p.kind, p.reg} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	// clab topology.
	if err := render.FileFS(templates.FS, "fabric.clab.yml.tmpl", p.topo, v); err != nil {
		return fmt.Errorf("render clab topology: %w", err)
	}

	// FRR edges + switches: render frr.conf per node, plus the shared daemons file.
	// clab bind-mounts frr/<node>.conf at /etc/frr/frr.conf; the default frrouting/frr
	// entrypoint reads it. No offline compile (unlike VyOS).
	for _, e := range []int{1, 2} {
		out := filepath.Join(p.frr, fmt.Sprintf("edge%d.conf", e))
		if err := render.FileFS(templates.FS, "frr/edge.conf.tmpl", out, frr.EdgeCtx{View: v, Edge: e}); err != nil {
			return fmt.Errorf("render edge%d frr.conf: %w", e, err)
		}
	}
	for _, s := range []int{1, 2} {
		out := filepath.Join(p.frr, fmt.Sprintf("sw%d.conf", s))
		if err := render.FileFS(templates.FS, "frr/switch.conf.tmpl", out, frr.SwitchCtx{View: v, SW: s}); err != nil {
			return fmt.Errorf("render sw%d frr.conf: %w", s, err)
		}
	}
	// Shared daemons file (static: copy verbatim embed → build).
	daemons, err := templates.FS.ReadFile("frr/daemons")
	if err != nil {
		return fmt.Errorf("read embedded frr/daemons: %w", err)
	}
	if err := os.WriteFile(filepath.Join(p.frr, "daemons"), daemons, 0o644); err != nil {
		return fmt.Errorf("write frr/daemons: %w", err)
	}

	// Per-cluster kind Cluster configs (+ prefix/uplinks files). The CNI is kindnet
	// (kind default) — no Cilium values to render.
	for _, cl := range cfg.Fabric.Clusters {
		dc := cfg.Derived.Clusters[cl.Name]
		if err := genKindCluster(cfg, v, p, cl.Name, dc); err != nil {
			return fmt.Errorf("cluster %s: %w", cl.Name, err)
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

	// Optional Ceph node: render its FRR sidecar files (preboot script + daemons +
	// frr.conf) into build/<name>/ceph/. Guarded so the base fabric stays lean.
	if cfg.Fabric.Ceph.Enabled {
		cephDir := filepath.Join(p.build, "ceph")
		if err := os.MkdirAll(cephDir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", cephDir, err)
		}
		if err := render.FileFS(templates.FS, "ceph/frr.conf.tmpl", filepath.Join(cephDir, "frr.conf"), v); err != nil {
			return fmt.Errorf("render ceph frr.conf: %w", err)
		}
		// ceph-preboot.sh templates in the mon addr (dummy0 /64).
		if err := render.FileFS(templates.FS, "ceph/ceph-preboot.sh", filepath.Join(cephDir, "ceph-preboot.sh"), v); err != nil {
			return fmt.Errorf("render ceph preboot: %w", err)
		}
		// frr-daemons is a static shell file: copy verbatim (embed → build).
		daemons, err := templates.FS.ReadFile("ceph/frr-daemons")
		if err != nil {
			return fmt.Errorf("read embedded ceph/frr-daemons: %w", err)
		}
		if err := os.WriteFile(filepath.Join(cephDir, "frr-daemons"), daemons, 0o644); err != nil {
			return fmt.Errorf("write ceph/frr-daemons: %w", err)
		}
	}

	slog.Info("rendered lab", "build", p.build, "clusters", len(cfg.Fabric.Clusters))
	return nil
}

// kindNodeCtx / kindClusterCtx are the k8s/kind-cluster.yaml.tmpl data. One
// kindClusterCtx is rendered per cluster; each node contributes a kindNodeCtx
// whose PrefixPath/UplinksPath are ABSOLUTE (kind rejects relative extraMounts
// hostPaths).
type kindNodeCtx struct{ Role, Image, PrefixPath, UplinksPath, CertsDir string }

// mirroredRegistries are the upstream registries the kind nodes pull through the
// in-fabric registry mirror (containerd 2.x config_path/hosts.toml).
var mirroredRegistries = []string{"ghcr.io", "quay.io", "docker.io", "registry.k8s.io", "gcr.io"}

type kindClusterCtx struct {
	RegistryHost string
	Nodes        []kindNodeCtx
}

// genKindCluster writes one cluster's kind artifacts under build/<name>/kind/:
// a per-node <cluster>-<index>.prefix (the node's /64), a single shared
// <cluster>-uplinks (the fabric BGP uplinks), and the kind Cluster config
// <cluster>-kind.yaml (control-plane for node 1, workers thereafter). The
// per-node preboot reads /etc/fabric/{prefix,uplinks} from the extraMounts.
func genKindCluster(cfg *config.Config, v *fabric.View, p paths, cluster string, dc config.DerivedCluster) error {
	// Absolute base for extraMounts hostPaths (kind rejects relative ones).
	absKind, err := filepath.Abs(p.kind)
	if err != nil {
		return fmt.Errorf("abs kind dir: %w", err)
	}

	// One shared uplinks file per cluster.
	uplinksName := cluster + "-uplinks"
	if err := os.WriteFile(filepath.Join(p.kind, uplinksName), []byte(v.NodeUplinks()+"\n"), 0o644); err != nil {
		return fmt.Errorf("write kind uplinks: %w", err)
	}
	uplinksPath := filepath.Join(absKind, uplinksName)

	// containerd 2.x registry mirror: one hosts.toml per upstream registry under a
	// certs.d dir mounted at /etc/containerd/certs.d. Each points the upstream at the
	// in-fabric registry (pull-through cache) over http (skip_verify).
	certsRel := cluster + "-certs.d"
	for _, reg := range mirroredRegistries {
		dir := filepath.Join(p.kind, certsRel, reg)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir certs.d %s: %w", reg, err)
		}
		hosts := fmt.Sprintf("[host.\"http://%s\"]\n  capabilities = [\"pull\", \"resolve\"]\n  skip_verify = true\n", v.RegistryHost())
		if err := os.WriteFile(filepath.Join(dir, "hosts.toml"), []byte(hosts), 0o644); err != nil {
			return fmt.Errorf("write hosts.toml %s: %w", reg, err)
		}
	}
	certsDir := filepath.Join(absKind, certsRel)

	nodes := make([]kindNodeCtx, 0, len(dc.Nodes))
	for _, n := range dc.Nodes {
		prefixName := fmt.Sprintf("%s-%d.prefix", n.Cluster, n.Index)
		if err := os.WriteFile(filepath.Join(p.kind, prefixName), []byte(n.NodeNet64+"\n"), 0o644); err != nil {
			return fmt.Errorf("write kind prefix for %s-%d: %w", n.Cluster, n.Index, err)
		}
		role := "worker"
		if n.Index == 1 {
			role = "control-plane"
		}
		nodes = append(nodes, kindNodeCtx{
			Role:        role,
			Image:       v.Images()["kindNode"],
			PrefixPath:  filepath.Join(absKind, prefixName),
			UplinksPath: uplinksPath,
			CertsDir:    certsDir,
		})
	}

	return render.FileFS(templates.FS, "k8s/kind-cluster.yaml.tmpl",
		filepath.Join(p.kind, cluster+"-kind.yaml"),
		kindClusterCtx{RegistryHost: v.RegistryHost(), Nodes: nodes})
}

// Up renders the build tree, deploys the containerlab topology (the clab k8s-kind
// nodes create the kind clusters with kindnet), pushes the local :dev images into
// the in-fabric mirror, then per cluster collects the kind kubeconfig, waits for the
// API + nodes Ready, and finally deploys the ectobase substrate.
func Up(ctx context.Context, cfg *config.Config) error {
	p := buildPaths(cfg)
	if err := Render(ctx, cfg); err != nil {
		return err
	}

	c := clab.Clab{TopoFile: p.topo}
	if err := c.Deploy(ctx); err != nil {
		return fmt.Errorf("clab deploy: %w", err)
	}

	// Route the host into the fabric via the WAN-segment jump veth (see
	// addHostFabricRoute) so talosctl/kubectl can reach the nodes.
	if err := addHostFabricRoute(ctx); err != nil {
		return fmt.Errorf("host fabric route: %w", err)
	}

	// Push the local :dev images to the in-fabric mirror; a push failure is fatal
	// (a missing image otherwise surfaces ~12 min later as a waitAggregatedAPI
	// timeout in deployEctobase). `make lab-up` builds them first via lab-app-images.
	// Push goes via the registry container's host-published localhost port
	// (127.0.0.1:5000, which is in docker's default insecure-registries — no host
	// dockerd reconfig needed); the nodes pull the same registry:2 process via its
	// fabric mirror addr.
	reg := registry.New("127.0.0.1:" + fabric.RegistryPort)
	if err := reg.PushLocal(ctx, cfg.Fabric.Registry.Push); err != nil {
		return fmt.Errorf("push-local images to the in-fabric mirror (build them first: make lab-app-images): %w", err)
	}

	for _, cl := range cfg.Fabric.Clusters {
		dc := cfg.Derived.Clusters[cl.Name]
		kubeconfig := p.clusterKubeconfig(cl.Name)
		// clab's k8s-kind node creates + owns the kind cluster (no talosctl bootstrap);
		// there is one k8s-kind lifecycle node per cluster, named after the cluster, so
		// the kind cluster name IS the cluster name. Collect its kubeconfig into
		// build/<name>/<cluster>.kubeconfig where the deploy pipeline expects it.
		kindName := cl.Name
		if err := writeKindKubeconfig(ctx, kindName, kubeconfig); err != nil {
			return fmt.Errorf("cluster %s kubeconfig: %w", cl.Name, err)
		}
		if err := deploy.WaitAPIServer(ctx, kubeconfig); err != nil {
			return fmt.Errorf("cluster %s api server: %w", cl.Name, err)
		}
		// The CNI is kind's default (kindnet) + kube-proxy — installed by `kind create`
		// itself, so there is no CNI step here; the node reaches Ready on its own.
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

// Ceph deploys Ceph (pool + external ceph-csi-rbd + csi-addons) onto an
// already-up fabric with fabric.ceph.enabled. It is the `lab ceph` entry point.
// When purge is set it uninstalls instead (helm uninstall + delete namespaces).
func Ceph(ctx context.Context, cfg *config.Config, purge bool) error {
	if !cfg.Fabric.Ceph.Enabled {
		return fmt.Errorf("fabric.ceph.enabled is false in %s — enable ceph and re-up the fabric first", cfg.Name)
	}
	p := buildPaths(cfg)

	// Dispatch is the fence-executor / provisioner cluster (csi-addons controller +
	// the ceph-csi provisioner it dials). Compute clusters run ceph-csi too so their
	// nodes can attach RBD.
	dispatchKubeconfig := p.clusterKubeconfig(dispatchCluster)
	var clusters []deploy.ComputeCluster
	for _, cl := range cfg.Fabric.Clusters {
		clusters = append(clusters, deploy.ComputeCluster{
			Name:       cl.Name,
			Kubeconfig: p.clusterKubeconfig(cl.Name),
		})
	}

	if purge {
		return cephPurge(ctx, clusters)
	}

	// Compute clusters attach RBD (krbd) and so need the nodeplugin krbd fixup. The dispatch
	// runs only the provisioner (librbd, no attach), so it is excluded.
	var computeClusters []deploy.ComputeCluster
	for _, c := range clusters {
		if c.Name == dispatchCluster {
			continue
		}
		computeClusters = append(computeClusters, c)
	}

	// Step 1: create the pool + emit the external-cluster params (run against the
	// shared clab ceph node; the params are cluster-independent).
	params, err := deploy.CephDemo(ctx, deploy.CephDemoSpec{
		LabName: cfg.Name,
		WorkDir: p.build,
		MonAddr: cfg.Derived.CephMonAddr,
		MonEndp: "[" + cfg.Derived.CephMonAddr + "]:3300",
	})
	if err != nil {
		return fmt.Errorf("ceph demo (pool + params): %w", err)
	}

	// Step 2: external ceph-csi-rbd on every cluster (dispatch = fence executor +
	// compute = attach). Values render under build/<name>/ceph/. (The nodes are never
	// tainted — cluster-patch strips the control-plane taint — so every pod schedules.)
	cephValuesDir := filepath.Join(p.build, "ceph")
	// ceph-csi is independent per cluster (own kubeconfig), so install concurrently.
	var cephEG errgroup.Group
	for _, c := range clusters {
		cephEG.Go(func() error {
			if err := deploy.CephCSI(ctx, nil, c.Kubeconfig, c.Name, cephValuesDir, params); err != nil {
				return fmt.Errorf("cluster %s: ceph-csi: %w", c.Name, err)
			}
			return nil
		})
	}
	if err := cephEG.Wait(); err != nil {
		return err
	}

	// Step 3: csi-addons controller + sidecar into the dispatch (fence executor)
	// provisioner.
	if err := deploy.CSIAddons(ctx, nil, dispatchKubeconfig, deploy.CSIAddonsVersion); err != nil {
		return fmt.Errorf("csi-addons on dispatch: %w", err)
	}

	// Step 4: krbd nodeplugin fixup so compute-node attach works.
	deploy.EnsureNodeKrbd(ctx, nil, computeClusters)

	slog.Info("ceph deployed", "clusters", len(clusters), "fenceExecutor", dispatchCluster)
	return nil
}

// cephPurge uninstalls the ceph-csi-rbd release and deletes the ceph-csi +
// csi-addons namespaces on every cluster (best-effort).
func cephPurge(ctx context.Context, clusters []deploy.ComputeCluster) error {
	for _, c := range clusters {
		deploy.CephPurge(ctx, nil, c.Kubeconfig, c.Name)
	}
	slog.Info("ceph purged", "clusters", len(clusters))
	return nil
}

// Tier2 deploys the Tier-2 (VM live-migration + fencing) prerequisites onto an
// already-up fabric: KubeVirt + CDI + the flowplane network binding on every compute
// cluster, and the ceph fsid wired into the dispatch controller's ceph-csi fence
// actuator. It is the `lab tier2 up` entry point. Requires fabric.ceph.enabled (RBD
// is the Tier-2 storage) and that `lab ceph` has already run (it consumes the fsid
// from build/<name>/ceph.env).
func Tier2(ctx context.Context, cfg *config.Config) error {
	if !cfg.Fabric.Ceph.Enabled {
		return fmt.Errorf("fabric.ceph.enabled is false in %s — Tier-2 needs RBD; enable ceph, re-up, and run `lab ceph` first", cfg.Name)
	}
	p := buildPaths(cfg)

	// The ceph fsid was emitted by CephDemo into build/<name>/ceph.env (CEPH_FSID=...).
	fsid, err := readCephFSID(filepath.Join(p.build, "ceph.env"))
	if err != nil {
		return err
	}

	// The vm-materializer (CompiledVM -> KubeVirt VirtualMachine + RBD DataVolume) is the
	// compute-side half of the Tier-2 VM pipeline. It ships (gated off) in the ectobase-pool
	// chart, so `lab tier2` turns it on by upgrading the pool release with vmMaterializer.enabled.
	root, err := repoRoot()
	if err != nil {
		return fmt.Errorf("locate repo root: %w", err)
	}
	poolChart := filepath.Join(root, "charts/ectobase-pool")

	// KubeVirt + CDI on every compute cluster, then enable the vm-materializer (the dispatch runs no
	// VMs — it is the fence executor / provisioner only). Each compute cluster is independent (own
	// kubeconfig) and each install blocks ~10-20m on operator Available, so run them concurrently.
	var kvEG errgroup.Group
	for _, cl := range cfg.Fabric.Clusters {
		if cl.Name == dispatchCluster {
			continue
		}
		kc := p.clusterKubeconfig(cl.Name)
		name := cl.Name
		kvEG.Go(func() error {
			if err := deploy.KubeVirtCDI(ctx, nil, kc); err != nil {
				return fmt.Errorf("cluster %s: kubevirt+cdi: %w", name, err)
			}
			if err := deploy.EnableVMMaterializer(ctx, nil, kc, poolChart); err != nil {
				return fmt.Errorf("cluster %s: vm-materializer: %w", name, err)
			}
			return nil
		})
	}
	if err := kvEG.Wait(); err != nil {
		return err
	}

	// Wire the ceph fsid into the dispatch controller's ceph-csi fence actuator.
	if err := deploy.PatchDispatchCSIClusterID(ctx, nil, p.clusterKubeconfig(dispatchCluster), fsid); err != nil {
		return fmt.Errorf("wire dispatch csi-cluster-id: %w", err)
	}

	slog.Info("tier2 deployed", "computeClusters", len(cfg.Fabric.Clusters)-1, "fsid", fsid)
	return nil
}

// readCephFSID reads the CEPH_FSID= value from a ceph.env file (written by CephDemo).
func readCephFSID(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("ceph.env not found — run `lab ceph` first (%s): %w", path, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "CEPH_FSID="); ok {
			if v = strings.TrimSpace(v); v != "" {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("no non-empty CEPH_FSID= line in %s — run `lab ceph` first", path)
}

// dispatchCluster is the cluster that hosts the dispatch aggregated apiserver +
// controller + reflector. Compute clusters run the ectobase chart with a broker.
const dispatchCluster = "dispatch"

// deployEctobase builds the flat EctobaseSpec from cfg + the build-tree paths and
// deploys the ectobase substrate onto the clusters.
func deployEctobase(ctx context.Context, cfg *config.Config) error {
	root, err := repoRoot()
	if err != nil {
		return fmt.Errorf("locate repo root: %w", err)
	}
	dc, ok := cfg.Derived.Clusters[dispatchCluster]
	if !ok {
		return fmt.Errorf("no cluster named %q in the config (need a dispatch cluster for the apiserver + reflector)", dispatchCluster)
	}
	if len(dc.Nodes) == 0 {
		return fmt.Errorf("dispatch cluster %q has no nodes", dispatchCluster)
	}

	// Route-bus mTLS PKI is on by default; set ECTOBASE_ROUTEBUS_MTLS=false to bring the
	// fabric up on the plaintext route bus (dev/debug baseline).
	mtls := os.Getenv("ECTOBASE_ROUTEBUS_MTLS") != "false"

	p := buildPaths(cfg)
	var compute []deploy.ComputeCluster
	for _, cl := range cfg.Fabric.Clusters {
		if cl.Name == dispatchCluster {
			continue
		}
		// Constrain this pool's route-bus intermediate to its own underlay /48 so it can only
		// mint node leaves inside the pool's underlay (the reflector then binds nexthops to that).
		compute = append(compute, deploy.ComputeCluster{
			Name:          cl.Name,
			Kubeconfig:    p.clusterKubeconfig(cl.Name),
			UnderlayCIDRs: cfg.Derived.Clusters[cl.Name].Prefix48,
		})
	}

	spec := deploy.EctobaseSpec{
		RepoRoot:           root,
		WorkDir:            filepath.Join(p.build, "deploy"),
		DispatchKubeconfig: p.clusterKubeconfig(dispatchCluster),
		DispatchIdentity:   dc.Nodes[0].IdentityAddr,
		DispatchChartPath:  filepath.Join(root, "charts/ectobase-dispatch"),
		PoolChartPath:      filepath.Join(root, "charts/ectobase-pool"),
		NADCRDPath:         filepath.Join(root, "test/lab/deploy/nad-crd.yaml"),
		UnderlayWithin:     fabric.NodeAggr,
		Compute:            compute,
		RouteBusMTLS:       mtls,
		// Agents dial the reflector at the dispatch identity, so that bare IP is the reflector
		// server cert's SAN.
		ReflectorIP: dc.Nodes[0].IdentityAddr,
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

// addHostFabricRoute brings up the host end of the WAN-segment jump veth and routes
// fd00:cafe::/32 (node identities + anycast API VIPs) into the fabric via the wan
// container (fd00:29::1), which ECMPs to both edges. Replaces the old mgmt-network
// next hop (mgmt net removal is task B2).
func addHostFabricRoute(ctx context.Context) error {
	if err := exec.Sudo(ctx, "ip", "-6", "addr", "replace", fabric.JumpHostAddr+"/64", "dev", fabric.JumpIface); err != nil {
		return fmt.Errorf("assign jump addr on %s: %w", fabric.JumpIface, err)
	}
	if err := exec.Sudo(ctx, "ip", "link", "set", fabric.JumpIface, "up"); err != nil {
		return fmt.Errorf("bring up %s: %w", fabric.JumpIface, err)
	}
	slog.Info("routing host into the fabric", "prefix", fabricHostPrefix, "via", fabric.JumpVia, "dev", fabric.JumpIface)
	return exec.Sudo(ctx, "ip", "-6", "route", "replace", fabricHostPrefix, "via", fabric.JumpVia, "dev", fabric.JumpIface)
}

// delHostFabricRoute removes the host→fabric route (best-effort, on down).
func delHostFabricRoute(ctx context.Context) {
	if err := exec.Sudo(ctx, "ip", "-6", "route", "del", fabricHostPrefix); err != nil {
		slog.Debug("remove host fabric route (already gone?)", "err", err)
	}
}

// writeKindKubeconfig writes the kind cluster's kubeconfig (host-accessible server)
// to dst. The kind cluster name is the clab k8s-kind node's short name. `lab up` runs as
// root (sudo), so the file is chowned back to the invoking user so a plain
// `kubectl --kubeconfig build/<name>/<cluster>.kubeconfig` works without sudo.
func writeKindKubeconfig(ctx context.Context, kindName, dst string) error {
	out, err := exec.Output(ctx, "kind", "get", "kubeconfig", "--name", kindName)
	if err != nil {
		return fmt.Errorf("kind get kubeconfig %s: %w\n%s", kindName, err, out)
	}
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		return err
	}
	chownToSudoUser(dst)
	return nil
}

// chownToSudoUser chowns path to the pre-sudo invoking user ($SUDO_UID:$SUDO_GID) when the
// process runs under sudo, so root-created lab artifacts (e.g. kubeconfigs) stay user-accessible.
// Best-effort and a no-op when not run under sudo (the file is already user-owned).
func chownToSudoUser(path string) {
	uidS, gidS := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if uidS == "" || gidS == "" {
		return
	}
	uid, err1 := strconv.Atoi(uidS)
	gid, err2 := strconv.Atoi(gidS)
	if err1 != nil || err2 != nil {
		return
	}
	_ = os.Chown(path, uid, gid)
}

// cleanupHostRBD force-releases any host krbd devices the ceph-csi nodeplugin left
// mapped. kind shares the host kernel, so an RBD PVC / VM-disk `rbd map` creates
// /dev/rbdN on the HOST; those kernel maps outlive `clab destroy` (which only removes
// the node containers) and, pointing at a destroyed mon, hang system shutdown and
// leave orphaned inodes. Each is force-removed via the rbd sysfs interface — no mon
// round-trip, and "force" tolerates a device the kernel can no longer flush. No-op
// when the rbd module was never loaded (/sys/bus/rbd absent), i.e. a ceph-less lab.
func cleanupHostRBD(ctx context.Context) {
	devs, err := os.ReadDir("/sys/bus/rbd/devices")
	if err != nil || len(devs) == 0 {
		return
	}
	remove := "/sys/bus/rbd/remove_single_major" // modern kernels; older expose only remove
	if _, err := os.Stat(remove); err != nil {
		remove = "/sys/bus/rbd/remove"
	}
	for _, d := range devs {
		if err := exec.SudoStdin(ctx, d.Name()+" force\n", "tee", remove); err != nil {
			slog.Debug("rbd force-unmap", "id", d.Name(), "err", err)
			continue
		}
		slog.Info("force-unmapped leftover host rbd device", "id", d.Name())
	}
}

// Down destroys the containerlab topology and removes build/<name>/ while
// preserving the registry cache for a warm re-up. With purge, it removes the whole
// build tree including the cache.
func Down(ctx context.Context, cfg *config.Config, purge bool) error {
	p := buildPaths(cfg)

	delHostFabricRoute(ctx)

	c := clab.Clab{TopoFile: p.topo}
	if err := c.Destroy(ctx); err != nil {
		slog.Warn("clab destroy (already down?)", "err", err)
	}

	// kind shares the host kernel, so an RBD PVC / VM-disk `rbd map` (ceph-csi
	// nodeplugin) creates /dev/rbdN on the HOST. clab destroy removes the node
	// containers but NOT these kernel maps, so they dangle at the now-gone mon —
	// which hangs system shutdown ("cannot connect to ceph") and orphans the
	// rbd-backed filesystem. Force-release them now that the holders (nodes) are gone.
	cleanupHostRBD(ctx)

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
