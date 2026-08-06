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

// EctobaseSpec is the flat, primitives-only input to Ectobase. It deliberately
// depends on no topology/config types so the deploy package stays a leaf the
// topology layer can import without a cycle. All addresses are derived by the
// caller (never hardcoded here).
type EctobaseSpec struct {
	RepoRoot          string           // repo root (dir containing go.work)
	WorkDir           string           // build/<name>/deploy scratch dir (created if missing)
	CentralKubeconfig string           // path to central's kubeconfig
	CentralAPIVip     string           // bare v6, e.g. fd00:cafe:<h>:1::1 (broker's central server host)
	CentralIdentity   string           // bare v6, e.g. fd00:cafe:<h>::1 (reflector host on the fabric)
	ChartPath         string           // <repoRoot>/deploy/charts/ectobase
	NADCRDPath        string           // NetworkAttachmentDefinition CRD manifest (abs or repo-relative)
	Compute           []ComputeCluster // compute clusters running the broker (k02, k03, …)
}

// ComputeCluster is one broker-running compute cluster.
type ComputeCluster struct {
	Name       string
	Kubeconfig string
}

// Ectobase deploys the (non-Ceph subset of the) ectobase substrate onto an
// already-up multi-cluster fabric: the central aggregated apiserver + controller
// + reflector on the central cluster, a broker identity + pre-created ClusterPools,
// a shared broker→central kubeconfig, then the chart (with a broker) on each
// compute cluster, and finally waits for both pools to report Ready.
//
// It assumes every referenced kubeconfig already exists (the fabric is up). Every
// kubectl/helm call passes --kubeconfig explicitly.
func Ectobase(ctx context.Context, s EctobaseSpec) error {
	if err := os.MkdirAll(s.WorkDir, 0o755); err != nil {
		return fmt.Errorf("mkdir workdir: %w", err)
	}

	// --- Central cluster ---
	slog.Info("deploying central apiserver + controller", "kustomize", filepath.Join(s.RepoRoot, "central/config"))
	if err := kubectlApplyKustomize(ctx, s.CentralKubeconfig, filepath.Join(s.RepoRoot, "central/config")); err != nil {
		return fmt.Errorf("apply central/config: %w", err)
	}
	if err := waitAggregatedAPI(ctx, s.CentralKubeconfig); err != nil {
		return fmt.Errorf("central aggregated API: %w", err)
	}

	slog.Info("deploying shared reflector")
	// Create ectobase-system + the SAs first, then mark the namespace PSA-privileged
	// BEFORE applying the reflector: the reflector runs hostNetwork (+ hostPort 1338),
	// which Talos's baseline PSA enforcement rejects. Applying the reflector first
	// would leave its ReplicaSet in a long FailedCreate backoff even after the label
	// lands. Order matters — label must precede the pod-creating manifest.
	if err := kubectlApply(ctx, s.CentralKubeconfig,
		filepath.Join(s.RepoRoot, "config/deploy/namespace.yaml"),
		filepath.Join(s.RepoRoot, "config/deploy/rbac.yaml"),
	); err != nil {
		return fmt.Errorf("apply reflector namespace/rbac: %w", err)
	}
	if err := labelPSAPrivileged(ctx, s.CentralKubeconfig, "ectobase-system"); err != nil {
		return fmt.Errorf("label reflector namespace privileged: %w", err)
	}
	if err := kubectlApply(ctx, s.CentralKubeconfig,
		filepath.Join(s.RepoRoot, "config/deploy/reflector.yaml"),
	); err != nil {
		return fmt.Errorf("apply reflector: %w", err)
	}

	slog.Info("creating broker central identity (SA + RBAC)")
	brokerRBAC := filepath.Join(s.WorkDir, "broker-rbac.yaml")
	if err := os.WriteFile(brokerRBAC, []byte(brokerRBACManifest), 0o644); err != nil {
		return fmt.Errorf("write broker rbac: %w", err)
	}
	if err := kubectlApply(ctx, s.CentralKubeconfig, brokerRBAC); err != nil {
		return fmt.Errorf("apply broker rbac: %w", err)
	}

	slog.Info("pre-creating compute ClusterPools", "count", len(s.Compute))
	poolsYAML := clusterPoolsManifest(s.Compute)
	poolsPath := filepath.Join(s.WorkDir, "clusterpools.yaml")
	if err := os.WriteFile(poolsPath, []byte(poolsYAML), 0o644); err != nil {
		return fmt.Errorf("write clusterpools: %w", err)
	}
	if err := kubectlApply(ctx, s.CentralKubeconfig, poolsPath); err != nil {
		return fmt.Errorf("apply clusterpools: %w", err)
	}

	// --- Shared broker→central kubeconfig ---
	slog.Info("minting broker central token")
	token, err := exec.OutputStr(ctx, "kubectl", "--kubeconfig", s.CentralKubeconfig,
		"create", "token", "ectobase-broker", "-n", "system", "--duration=24h")
	if err != nil {
		return fmt.Errorf("create broker token: %w", err)
	}
	brokerKubeconfig := filepath.Join(s.WorkDir, "broker-central.kubeconfig")
	if err := os.WriteFile(brokerKubeconfig,
		[]byte(mintKubeconfig(s.CentralAPIVip, strings.TrimSpace(token))), 0o600); err != nil {
		return fmt.Errorf("write broker kubeconfig: %w", err)
	}

	// --- Each compute cluster ---
	for _, c := range s.Compute {
		slog.Info("deploying ectobase chart on compute cluster", "cluster", c.Name)
		// The chart renders a NetworkAttachmentDefinition unconditionally, so the NAD
		// CRD must exist first.
		if err := kubectlApply(ctx, c.Kubeconfig, s.NADCRDPath); err != nil {
			return fmt.Errorf("cluster %s: apply NAD CRD: %w", c.Name, err)
		}
		// The broker-central-kubeconfig Secret must exist before the chart's broker
		// pod starts, so create the namespace + secret ahead of helm.
		if err := ensureHelmNamespace(ctx, c.Kubeconfig, "ectobase-system", "ectobase"); err != nil {
			return fmt.Errorf("cluster %s: ensure namespace: %w", c.Name, err)
		}
		if err := createSecretFromFile(ctx, c.Kubeconfig, "ectobase-system",
			"broker-central-kubeconfig", "kubeconfig", brokerKubeconfig); err != nil {
			return fmt.Errorf("cluster %s: create broker secret: %w", c.Name, err)
		}
		if err := helmInstallEctobase(ctx, c.Kubeconfig, c.Name, s.ChartPath, s.CentralIdentity); err != nil {
			return fmt.Errorf("cluster %s: helm install ectobase: %w", c.Name, err)
		}
	}

	// --- Readiness ---
	if err := waitPoolsReady(ctx, s.CentralKubeconfig, s.Compute); err != nil {
		return fmt.Errorf("cluster pools ready: %w", err)
	}
	slog.Info("ectobase substrate deployed", "compute", len(s.Compute))
	return nil
}

// kubectlApplyKustomize applies a kustomize dir to the cluster.
func kubectlApplyKustomize(ctx context.Context, kubeconfig, dir string) error {
	return exec.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-k", dir)
}

// kubectlApply applies one or more manifest paths in a single kubectl call.
func kubectlApply(ctx context.Context, kubeconfig string, paths ...string) error {
	args := []string{"--kubeconfig", kubeconfig, "apply"}
	for _, p := range paths {
		args = append(args, "-f", p)
	}
	return exec.Run(ctx, "kubectl", args...)
}

// kubectlApplyStdin pipes yaml into `kubectl apply -f -` (idempotent create/update).
func kubectlApplyStdin(ctx context.Context, kubeconfig, yaml string) error {
	return exec.RunStdin(ctx, yaml, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-")
}

// ensureHelmNamespace idempotently creates a namespace pre-stamped with Helm's
// ownership label + annotations so the chart (whose own namespace.yaml manages the
// same namespace) can adopt it. Without these, `helm install` refuses a
// pre-existing namespace ("invalid ownership metadata"). We must create it ahead of
// helm because the broker-central-kubeconfig Secret has to exist before the chart's
// broker pod starts.
//
// It also stamps pod-security.kubernetes.io/enforce=privileged: Talos enforces the
// baseline PodSecurity level cluster-wide, which rejects the dataplane pods
// (flowplane is privileged + hostPID + hostPath; agent/broker are hostNetwork).
// Kind does not enforce PSA, so this only bites on Talos.
func ensureHelmNamespace(ctx context.Context, kubeconfig, ns, release string) error {
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
	return kubectlApplyStdin(ctx, kubeconfig, m)
}

// labelPSAPrivileged marks ns as PodSecurity privileged so hostNetwork/privileged
// pods are admitted under Talos's baseline-enforcing default (see ensureHelmNamespace).
func labelPSAPrivileged(ctx context.Context, kubeconfig, ns string) error {
	return exec.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "label", "ns", ns,
		"pod-security.kubernetes.io/enforce=privileged", "--overwrite")
}

// waitAggregatedAPI blocks until the central aggregated API actually serves the
// platform group — APIService availability + aggregation can lag the apply.
func waitAggregatedAPI(ctx context.Context, kubeconfig string) error {
	// Generous: the central-apiserver pod must cold-pull its :dev image from the
	// in-fabric registry, start, and have its APIService become Available before the
	// aggregated group is served.
	slog.Info("waiting for the central aggregated API to serve")
	return wait.WaitFor(ctx, 6*time.Minute, 3*time.Second, func() (bool, error) {
		err := exec.Run(ctx, "kubectl", "--kubeconfig", kubeconfig,
			"get", "clusterpools.platform.ectobase.dev", "--request-timeout=5s")
		return err == nil, err
	})
}

// createSecretFromFile idempotently creates (or updates) an Opaque secret with a
// single file-backed key via the dry-run|apply pattern.
func createSecretFromFile(ctx context.Context, kubeconfig, ns, name, key, path string) error {
	manifest, err := exec.Output(ctx, "kubectl", "--kubeconfig", kubeconfig,
		"create", "secret", "generic", name, "-n", ns,
		"--from-file="+key+"="+path, "--dry-run=client", "-o", "yaml")
	if err != nil {
		return fmt.Errorf("render secret manifest: %w", err)
	}
	return kubectlApplyStdin(ctx, kubeconfig, string(manifest))
}

// helmInstallEctobase installs/upgrades the ectobase chart with a broker on one
// compute cluster. apiserverAddress is the LOCAL cluster (the agent reads/writes
// its own cluster); reflectorAddress points at central's reflector on the fabric.
func helmInstallEctobase(ctx context.Context, kubeconfig, clusterName, chartPath, centralIdentity string) error {
	return exec.Run(ctx, "helm", "upgrade", "--install", "ectobase", chartPath,
		"--kubeconfig", kubeconfig,
		"--namespace", "ectobase-system", "--create-namespace",
		"--set", "broker.enabled=true",
		"--set", "broker.clusterName="+clusterName,
		"--set", "apiserverAddress=https://127.0.0.1:6443",
		"--set", "reflectorAddress=["+centralIdentity+"]:1338",
		"--set", "installCRDs=true",
		"--set", "dataplane=ebpf",
		"--wait", "--timeout", "8m")
}

// waitPoolsReady blocks until every compute pool reports status.phase == Ready
// with a non-empty status.nodePrefixes.
func waitPoolsReady(ctx context.Context, kubeconfig string, compute []ComputeCluster) error {
	slog.Info("waiting for compute ClusterPools to become Ready", "count", len(compute))
	return wait.WaitFor(ctx, 5*time.Minute, 5*time.Second, func() (bool, error) {
		allReady := true
		var lastErr error
		for _, c := range compute {
			phase, err := poolField(ctx, kubeconfig, c.Name, "{.status.phase}")
			if err != nil {
				lastErr = err
				allReady = false
				continue
			}
			prefixes, err := poolField(ctx, kubeconfig, c.Name, "{.status.nodePrefixes}")
			if err != nil {
				lastErr = err
				allReady = false
				continue
			}
			slog.Info("clusterpool status", "pool", c.Name, "phase", phase, "nodePrefixes", prefixes)
			if phase != "Ready" || strings.TrimSpace(prefixes) == "" || prefixes == "[]" {
				allReady = false
			}
		}
		return allReady, lastErr
	})
}

// poolField reads a jsonpath field of a ClusterPool via kubectl. It uses the fully
// qualified plural resource (clusterpools.platform.ectobase.dev): the aggregated
// API's short-name discovery intermittently flakes ("the server doesn't have a
// resource type \"clusterpool\""), which would make the readiness poll error
// forever even once the pools are Ready.
func poolField(ctx context.Context, kubeconfig, name, jsonpath string) (string, error) {
	out, err := exec.OutputStr(ctx, "kubectl", "--kubeconfig", kubeconfig,
		"get", "clusterpools.platform.ectobase.dev", name, "-o", "jsonpath="+jsonpath)
	return strings.TrimSpace(out), err
}

// mintKubeconfig hand-writes a token kubeconfig for the broker→central connection.
// The bracketed-IPv6 server MUST be double-quoted: an unquoted https://[..]:6443
// is a YAML flow sequence and fails to parse. TLS verify is skipped because
// central's serving cert is self-signed.
func mintKubeconfig(centralAPIVip, token string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: central
  cluster:
    server: "https://[%s]:6443"
    insecure-skip-tls-verify: true
contexts:
- name: broker@central
  context:
    cluster: central
    user: ectobase-broker
current-context: broker@central
users:
- name: ectobase-broker
  user:
    token: %s
`, centralAPIVip, token)
}

// clusterPoolsManifest renders one cluster-scoped ClusterPool per compute cluster
// (spec.region: eu). The broker Gets + heartbeats the pool; the agent stamps
// status.nodePrefixes.
func clusterPoolsManifest(compute []ComputeCluster) string {
	var b strings.Builder
	for _, c := range compute {
		b.WriteString(fmt.Sprintf(`---
apiVersion: platform.ectobase.dev/v1alpha1
kind: ClusterPool
metadata:
  name: %s
spec:
  region: eu
`, c.Name))
	}
	return b.String()
}

// brokerRBACManifest is the broker's central identity: a ServiceAccount in the
// system namespace plus a ClusterRole/Binding granting read on the compiled net
// resources and read/write on ClusterPools (+ status) for heartbeating.
const brokerRBACManifest = `---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ectobase-broker
  namespace: system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ectobase-broker
rules:
- apiGroups: ["net.ectobase.dev"]
  resources: ["compilednics", "compiledvms", "compiledvolumeattachments"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["platform.ectobase.dev"]
  resources: ["clusterpools"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: ["platform.ectobase.dev"]
  resources: ["clusterpools/status"]
  verbs: ["get", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ectobase-broker
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ectobase-broker
subjects:
- kind: ServiceAccount
  name: ectobase-broker
  namespace: system
`
