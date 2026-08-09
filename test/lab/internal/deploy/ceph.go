package deploy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/wait"
)

// Runner is the command-execution seam the ceph deploy runs through so the argv
// composition + values render can be unit-tested with a fake (no live fabric).
// The real implementation (execRunner) delegates to the exec package.
type Runner interface {
	// Run runs name+args, streaming output; wraps failures.
	Run(ctx context.Context, name string, args ...string) error
	// Output runs name+args and returns stdout.
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
	// RunStdin runs name+args feeding stdin.
	RunStdin(ctx context.Context, stdin, name string, args ...string) error
	// Sudo runs args as root (directly if already root, else `sudo -n`).
	Sudo(ctx context.Context, args ...string) error
	// SudoOutput is Sudo returning stdout.
	SudoOutput(ctx context.Context, args ...string) ([]byte, error)
}

// execRunner is the production Runner: it forwards to the exec package.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.Run(ctx, name, args...)
}
func (execRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.Output(ctx, name, args...)
}
func (execRunner) RunStdin(ctx context.Context, stdin, name string, args ...string) error {
	return exec.RunStdin(ctx, stdin, name, args...)
}
func (execRunner) Sudo(ctx context.Context, args ...string) error { return exec.Sudo(ctx, args...) }
func (execRunner) SudoOutput(ctx context.Context, args ...string) ([]byte, error) {
	return exec.SudoOutput(ctx, args...)
}

// DefaultRunner is the production command runner (delegates to exec.*).
var DefaultRunner Runner = execRunner{}

// CephParams are the external-cluster connection params emitted by CephDemo and
// consumed by CephCSI (the ceph-csi-rbd Helm values). The CEPH_* output fields
// match the old ceph-demo env format.
type CephParams struct {
	FSID string // ceph cluster fsid  -> StorageClass/csiConfig clusterID
	Mon  string // v6 mon endpoint    -> csiConfig monitors ([addr]:3300, msgr-v2)
	Pool string // RBD pool           -> StorageClass pool
	Key  string // client.rbd key     -> csi-rbd-secret userKey
}

// CephDemoSpec is the flat input to CephDemo (primitives only, no topology types).
type CephDemoSpec struct {
	Runner  Runner // command seam (nil -> DefaultRunner)
	LabName string // clab lab name (the ceph container is clab-<name>-ceph)
	WorkDir string // build/<name> (ceph.env is written here)
	MonAddr string // bare v6 mon addr, e.g. fd00:cafe:<h>::1
	MonEndp string // bracketed msgr-v2 endpoint, e.g. [fd00:cafe:<h>::1]:3300
	Pool    string // RBD pool (default replicapool)
}

const defaultCephPool = "replicapool"

// runnerOf returns s.Runner or DefaultRunner.
func runnerOf(r Runner) Runner {
	if r == nil {
		return DefaultRunner
	}
	return r
}

// CephDemo creates the RBD pool on the shared clab ceph/demo fabric node and
// emits the external-cluster connection params (fsid, mon, client key) for
// external ceph-csi. Dev-only, NOT production. (Ported to Go from the old ceph-demo bring-up script.)
//
// The ceph/demo mon is msgr-v2 ONLY (bound [<mon>]:3300; `ceph mon dump` shows no
// v1 addr — the demo pins the monmap to the :3300 endpoint under IPv6).
// librados/ceph-csi connect to :3300 as v2. The legacy v1 port 6789 gets
// connection-refused (nothing listens there).
func CephDemo(ctx context.Context, s CephDemoSpec) (CephParams, error) {
	r := runnerOf(s.Runner)
	pool := s.Pool
	if pool == "" {
		pool = defaultCephPool
	}
	cephCtr := "clab-" + s.LabName + "-ceph"

	// --- host prep so the ceph-csi RBD nodeplugin can `rbd map` (krbd) at ATTACH
	// time --- A PVC *provisions* via librbd in the provisioner without any of this;
	// modprobe is ONLY needed when a pod/VM ATTACHES the RBD (NodeStage -> krbd map).
	// Talos nodes ship no modules but share the host kernel, so loading rbd/nbd once
	// on the host makes krbd available to every node (else "Module rbd not found").
	for _, m := range []string{"rbd", "nbd"} {
		if err := r.Sudo(ctx, "modprobe", m); err != nil {
			// Best-effort: the module may be built-in or already loaded.
			slog.Debug("modprobe (already loaded / built-in?)", "module", m, "err", err)
		}
	}
	slog.Info("host rbd/nbd modules loaded")

	ex := func(args ...string) ([]byte, error) {
		return r.Output(ctx, "docker", append([]string{"exec", cephCtr}, args...)...)
	}

	// Readiness = mon responsive + the OSD up+in. We do NOT gate on HEALTH_OK/WARN:
	// the ceph/demo node runs a single v6 OSD and Squid's OSD_UNREACHABLE health
	// check FALSE-POSITIVES on IPv6 (it claims the osd's public addr "is not in the
	// subnet" though it plainly is), leaving the cluster HEALTH_ERR forever. RBD
	// provisions fine regardless; we mute the bogus check below so `ceph -s` reports
	// HEALTH_WARN.
	slog.Info("waiting for ceph mon + osd", "container", cephCtr)
	if err := wait.WaitFor(ctx, 5*time.Minute, 5*time.Second, func() (bool, error) {
		out, err := ex("ceph", "osd", "stat")
		if err != nil {
			return false, err
		}
		return cephOSDUp(out), nil
	}); err != nil {
		return CephParams{}, fmt.Errorf("ceph mon/osd not ready: %w", err)
	}

	// Mute the known-cosmetic v6 reachability false-positive (sticky: stays muted if
	// it re-fires).
	if _, err := ex("ceph", "health", "mute", "OSD_UNREACHABLE", "--sticky"); err != nil {
		slog.Debug("mute OSD_UNREACHABLE (not firing?)", "err", err)
	}

	// Create + init the pool (idempotent: pool-create errors if it exists).
	if _, err := ex("ceph", "osd", "pool", "create", pool, "8", "8"); err != nil {
		slog.Debug("pool create (already exists?)", "pool", pool, "err", err)
	}
	if _, err := ex("rbd", "pool", "init", pool); err != nil {
		slog.Debug("rbd pool init (already init?)", "pool", pool, "err", err)
	}

	// mon caps: `profile rbd` lets the client blocklist (osd blocklist range ADD) so
	// csi-addons can FENCE, but it does NOT permit `osd blocklist range rm` — the
	// Tier-2 recovery UN-fence then fails EACCES and the blocklist entry leaks. The
	// explicit `allow command "osd blocklist"` grants both add + rm.
	const rbdMonCaps = `profile rbd, allow command "osd blocklist"`
	rbdOSDCaps := "profile rbd pool=" + pool
	keyOut, err := ex("ceph", "auth", "get-or-create-key", "client.rbd", "mon", rbdMonCaps, "osd", rbdOSDCaps)
	if err != nil {
		return CephParams{}, fmt.Errorf("ceph auth get-or-create-key client.rbd: %w", err)
	}
	// get-or-create-key does NOT update caps on an already-existing key; ensure the
	// blocklist-rm cap is present even when the client pre-exists (idempotent re-runs).
	if _, err := ex("ceph", "auth", "caps", "client.rbd", "mon", rbdMonCaps, "osd", rbdOSDCaps); err != nil {
		return CephParams{}, fmt.Errorf("ceph auth caps client.rbd: %w", err)
	}
	fsidOut, err := ex("ceph", "fsid")
	if err != nil {
		return CephParams{}, fmt.Errorf("ceph fsid: %w", err)
	}

	params := CephParams{
		FSID: strings.TrimSpace(string(fsidOut)),
		Mon:  s.MonEndp,
		Pool: pool,
		Key:  strings.TrimSpace(string(keyOut)),
	}

	// Emit build/<name>/ceph.env (the CEPH_* external-cluster param file).
	if s.WorkDir != "" {
		if err := os.MkdirAll(s.WorkDir, 0o755); err != nil {
			return CephParams{}, fmt.Errorf("mkdir workdir: %w", err)
		}
		envPath := filepath.Join(s.WorkDir, "ceph.env")
		if err := os.WriteFile(envPath, []byte(cephEnv(params)), 0o600); err != nil {
			return CephParams{}, fmt.Errorf("write ceph.env: %w", err)
		}
		slog.Info("wrote ceph external-cluster params", "path", envPath, "fsid", params.FSID, "mon", params.Mon)
	}
	return params, nil
}

// cephOSDUp reports whether `ceph osd stat` output shows at least one OSD up.
// `ceph osd stat` prints e.g. "1 osds: 1 up (since ...), 1 in (since ...)".
func cephOSDUp(out []byte) bool {
	// Match "<n> up" where n>=1 (e.g. "1 osds: 1 up (since ...), 1 in").
	fields := strings.Fields(string(out))
	for i := 1; i < len(fields); i++ {
		if fields[i] == "up" {
			n := strings.TrimRight(fields[i-1], ",")
			if n != "0" && n != "" {
				// crude positive-integer check
				allDigits := true
				for _, c := range n {
					if c < '0' || c > '9' {
						allDigits = false
						break
					}
				}
				if allDigits {
					return true
				}
			}
		}
	}
	return false
}

// cephEnv renders the CEPH_* env file (external-cluster params for ceph-csi).
func cephEnv(p CephParams) string {
	return fmt.Sprintf("CEPH_FSID=%s\nCEPH_MON=%s\nCEPH_POOL=%s\nCEPH_RBD_KEY=%s\n",
		p.FSID, p.Mon, p.Pool, p.Key)
}

// Ceph-CSI chart pin (ported to Go from the old external-ceph bring-up script).
const (
	CephCSIRepo    = "https://ceph.github.io/csi-charts"
	CephCSIChart   = "ceph-csi/ceph-csi-rbd"
	CephCSIRelease = "ceph-csi-rbd"
	CephCSIVersion = "3.11.0"
	CephCSINS      = "ceph-csi"
	// CSIUser is the ceph client user the csi-rbd-secret is minted for.
	CSIUser = "rbd"
)

// cephCSIValues renders the ceph-csi-rbd Helm values YAML from params (ported to Go
// from the old external-ceph bring-up script's heredoc). The chart renders the ceph-csi-config ConfigMap from
// csiConfig, the csi-rbd-secret from secret.*, and a StorageClass from
// storageClass.*. The StorageClass secret refs default to secret.name in the
// release namespace, i.e. csi-rbd-secret / ceph-csi — which is exactly what the
// hub failover controller's -csi-secret-name/-namespace point at.
//
// Pure function (no I/O) so the values render is unit-tested directly.
func cephCSIValues(p CephParams) string {
	pool := p.Pool
	if pool == "" {
		pool = defaultCephPool
	}
	return fmt.Sprintf(`csiConfig:
  - clusterID: "%s"
    monitors:
      - "%s"
provisioner:
  replicaCount: 1            # single-node cluster: the chart default (3) leaves 2 replicas Pending
  # NOTE: the provisioner runs on the POD network and reaches the ceph mon's /64 because
  # kindnet plain-MASQUERADEs pod egress to the per-packet route source (the egress
  # uplink's RA-SLAAC addr, which the fabric routes back symmetrically via the same ToR).
  # This also lets the csi-addons fence RPC (ceph osd blocklist, served from this pod)
  # reach the mon for the Tier-2 gate.
secret:
  create: true
  name: csi-rbd-secret
  userID: "%s"
  userKey: "%s"
storageClass:
  create: true
  name: ceph-rbd
  clusterID: "%s"
  pool: "%s"
  imageFeatures: "layering"
  # krbd (the kernel rbd client used at NodeStage/`+"`rbd map`"+`, e.g. by CDI import + VM attach)
  # must be told ms_mode to reach this msgr-v2-ONLY mon on :3300 — otherwise it tries legacy msgr1
  # and fails "rbd: failed to get mon address (possible ms_mode mismatch)". prefer-crc negotiates v2
  # (crc, no encryption) and is supported on modern kernels (>=5.11). librbd (provisioner) doesn't
  # need this.
  mapOptions: "ms_mode=prefer-crc"
  mountOptions: []
  reclaimPolicy: Delete
  allowVolumeExpansion: true
  fstype: ext4
`, p.FSID, p.Mon, CSIUser, p.Key, p.FSID, pool)
}

// cephCSIHelmArgs composes the `helm upgrade --install` argv for the ceph-csi-rbd
// chart against kubeconfig, reading valuesFile. Pure function so the argv is
// unit-tested.
func cephCSIHelmArgs(kubeconfig, valuesFile string) []string {
	return []string{"upgrade", "--install", CephCSIRelease, CephCSIChart,
		"--kubeconfig", kubeconfig,
		"--version", CephCSIVersion,
		"--namespace", CephCSINS, "--create-namespace",
		"-f", valuesFile,
		"--wait", "--timeout", "5m"}
}

// CephCSI installs external ceph-csi (RBD) into one cluster via the upstream Helm
// chart, wired to the shared clab ceph/demo node using params from CephDemo.
// Dev-only. (Ported to Go from the old external-ceph bring-up script.)
//
// Installs the ceph-csi-rbd chart (provisioner + nodeplugin + CSIDriver + rbac +
// the ceph-csi-config ConfigMap) into namespace ceph-csi, and — via chart values —
// the csi-rbd-secret Secret + a ceph-rbd StorageClass. Helm namespaces everything
// cleanly (the raw manifests hardcode namespace: default) and lets us pin
// provisioner.replicaCount=1 for single-node clusters (the chart default 3 + pod
// anti-affinity leaves 2 replicas Pending forever). Idempotent (upgrade --install).
//
// valuesDir is where the rendered values YAML is written
// (build/<name>/ceph/csi-values-<cluster>.yaml); cluster names that file.
func CephCSI(ctx context.Context, r Runner, kubeconfig, cluster, valuesDir string, p CephParams) error {
	r = runnerOf(r)
	slog.Info("installing ceph-csi-rbd Helm chart", "cluster", cluster, "version", CephCSIVersion, "clusterID", p.FSID)

	if err := os.MkdirAll(valuesDir, 0o755); err != nil {
		return fmt.Errorf("mkdir ceph values dir: %w", err)
	}
	valuesFile := filepath.Join(valuesDir, "csi-values-"+cluster+".yaml")
	if err := os.WriteFile(valuesFile, []byte(cephCSIValues(p)), 0o644); err != nil {
		return fmt.Errorf("write ceph-csi values: %w", err)
	}

	// The upstream repo add/update is idempotent; best-effort (a pre-added repo or a
	// transient index fetch shouldn't abort the install if the chart resolves).
	if err := r.Run(ctx, "helm", "repo", "add", "ceph-csi", CephCSIRepo); err != nil {
		slog.Debug("helm repo add ceph-csi (already added?)", "err", err)
	}
	if err := r.Run(ctx, "helm", "repo", "update", "ceph-csi"); err != nil {
		slog.Debug("helm repo update ceph-csi", "err", err)
	}

	// Pre-create the ceph-csi namespace PSA-privileged: the ceph-csi RBD nodeplugin
	// runs privileged + hostPID + hostPath (it krbd-maps + mounts on the host), which
	// Talos's baseline PSA enforcement rejects unless the ns is labeled privileged.
	// Stamp it Helm-owned first so the chart (which manages the same ns) can adopt it.
	if err := ensureHelmNamespaceRunner(ctx, r, kubeconfig, CephCSINS, CephCSIRelease); err != nil {
		return fmt.Errorf("cluster %s: ensure ceph-csi namespace: %w", cluster, err)
	}

	if err := r.Run(ctx, "helm", cephCSIHelmArgs(kubeconfig, valuesFile)...); err != nil {
		return fmt.Errorf("cluster %s: helm install ceph-csi-rbd: %w", cluster, err)
	}
	slog.Info("external ceph-csi (RBD) installed", "cluster", cluster, "namespace", CephCSINS)
	return nil
}

// ensureHelmNamespaceRunner is ensureHelmNamespace routed through a Runner (so the
// ceph deploy stays unit-testable). It idempotently creates ns pre-stamped Helm-
// owned + PSA-privileged (see ensureHelmNamespace).
func ensureHelmNamespaceRunner(ctx context.Context, r Runner, kubeconfig, ns, release string) error {
	m := fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    app.kubernetes.io/managed-by: Helm
    pod-security.kubernetes.io/enforce: privileged
  annotations:
    meta.helm.sh/release-name: %s
    meta.helm.sh/release-namespace: %s
`, ns, release, ns)
	return r.RunStdin(ctx, m, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-")
}

// CephPurge uninstalls the ceph-csi-rbd Helm release and deletes the ceph-csi +
// csi-addons namespaces on one cluster (best-effort; each step is logged, not
// fatal — a purge should clean up as much as it can). The `lab ceph --purge` path.
func CephPurge(ctx context.Context, r Runner, kubeconfig, cluster string) {
	r = runnerOf(r)
	slog.Info("purging ceph from cluster", "cluster", cluster)
	if err := r.Run(ctx, "helm", "uninstall", CephCSIRelease, "--kubeconfig", kubeconfig, "--namespace", CephCSINS); err != nil {
		slog.Warn("helm uninstall ceph-csi-rbd (already gone?)", "cluster", cluster, "err", err)
	}
	for _, ns := range []string{CephCSINS, CSIAddonsNS} {
		if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "delete", "namespace", ns, "--ignore-not-found"); err != nil {
			slog.Warn("delete namespace", "cluster", cluster, "namespace", ns, "err", err)
		}
	}
}

// CephCSINodeplugin is the ceph-csi RBD nodeplugin DaemonSet name.
const CephCSINodeplugin = "ceph-csi-rbd-nodeplugin"

// EnsureNodeKrbd makes the ceph-csi RBD nodeplugin able to `rbd map` (krbd) at
// NodeStage on each compute cluster. Talos container nodes give the kubelet — and so
// the nodeplugin's hostPath /dev — a small tmpfs /dev, so the kernel's dynamically-
// created /dev/rbdN device nodes never appear and `rbd map` fails "mapping succeeded
// but /dev/rbdN is not accessible, is host /dev mounted?". The kind harness fixed this
// with `mount -t devtmpfs devtmpfs /dev` on the node, but Talos nodes ship no
// mount/sh binary (the docker-exec approach silently no-ops). So run the mount INSIDE
// the privileged nodeplugin container (which has util-linux) via kubectl exec — the
// `rbd map` runs in that same container, and devtmpfs surfaces every kernel device
// node to it. Best-effort per cluster (logged, not fatal: krbd is only needed for
// ATTACH, not PVC provisioning). Reverts if the nodeplugin restarts; re-run `lab ceph`
// to reapply.
func EnsureNodeKrbd(ctx context.Context, r Runner, clusters []ComputeCluster) {
	r = runnerOf(r)
	for _, c := range clusters {
		// Wait for the nodeplugin pod to be Ready so the exec lands.
		_ = wait.WaitFor(ctx, 2*time.Minute, 5*time.Second, func() (bool, error) {
			err := r.Run(ctx, "kubectl", "--kubeconfig", c.Kubeconfig, "-n", CephCSINS,
				"rollout", "status", "ds/"+CephCSINodeplugin, "--timeout=10s")
			return err == nil, nil
		})
		if err := r.Run(ctx, "kubectl", "--kubeconfig", c.Kubeconfig, "-n", CephCSINS,
			"exec", "ds/"+CephCSINodeplugin, "-c", "csi-rbdplugin", "--",
			"mount", "-t", "devtmpfs", "devtmpfs", "/dev"); err != nil {
			slog.Warn("krbd prep: mount devtmpfs in nodeplugin failed", "cluster", c.Name, "err", err)
		} else {
			slog.Info("krbd prep: devtmpfs mounted in nodeplugin", "cluster", c.Name)
		}
	}
}
