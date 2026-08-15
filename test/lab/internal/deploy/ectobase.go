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
	RepoRoot       string           // repo root (dir containing go.work)
	WorkDir        string           // build/<name>/deploy scratch dir (created if missing)
	DispatchKubeconfig  string           // path to dispatch's kubeconfig
	DispatchIdentity    string           // bare v6, e.g. fd00:cafe:<h>::1 (dispatch's fabric address: the broker's dispatch server host AND the reflector host)
	DispatchChartPath   string           // <repoRoot>/charts/ectobase-dispatch
	PoolChartPath  string           // <repoRoot>/charts/ectobase-pool
	NADCRDPath     string           // NetworkAttachmentDefinition CRD manifest (abs or repo-relative)
	UnderlayWithin string           // node-underlay aggregate CIDR (fd00:cafe::/32) for flowplane's underlay filter
	Compute        []ComputeCluster // compute clusters running the broker (k02, k03, …)
}

// ComputeCluster is one broker-running compute cluster.
type ComputeCluster struct {
	Name       string
	Kubeconfig string
}

// Ectobase deploys the (non-Ceph subset of the) ectobase substrate onto an
// already-up multi-cluster fabric by installing the two Helm charts exactly as a
// user would: the ectobase-dispatch chart on the dispatch cluster (aggregated apiserver +
// controller + kine + compiler + reflector + dispatch-side broker identity), then the
// ectobase-pool chart on each compute cluster (dataplane + agent + broker + cni +
// materializers). Lab-only bits — the broker→dispatch token/kubeconfig and the
// pre-created ClusterPools — are minted here as fixtures around the installs.
//
// It assumes every referenced kubeconfig already exists (the fabric is up). Every
// kubectl/helm call passes --kubeconfig explicitly.
func Ectobase(ctx context.Context, s EctobaseSpec) error {
	if err := os.MkdirAll(s.WorkDir, 0o755); err != nil {
		return fmt.Errorf("mkdir workdir: %w", err)
	}

	// --- Dispatch cluster: one Helm release ---
	// The ectobase-dispatch chart carries the aggregated apiserver + controller + kine, the mesh
	// compiler, the reflector, and the dispatch-side dispatch-broker identity. --create-namespace makes the
	// release namespace (system, whose pods are baseline-PSA-safe); the chart itself creates the
	// PSA-privileged ectobase-system namespace for the hostNetwork compiler + reflector. The
	// reflector runs on the dispatch's fabric identity, so the controller's -reflector-admin is pointed
	// there via a chart value (retiring the old post-apply patch). The clusters set
	// cluster.allowSchedulingOnControlPlanes so control-plane nodes are never tainted.
	slog.Info("installing ectobase-dispatch chart", "chart", s.DispatchChartPath)
	if err := helmInstallDispatch(ctx, s.DispatchKubeconfig, s.DispatchChartPath, s.DispatchIdentity); err != nil {
		return fmt.Errorf("helm install ectobase-dispatch: %w", err)
	}
	if err := waitAggregatedAPI(ctx, s.DispatchKubeconfig); err != nil {
		return fmt.Errorf("dispatch aggregated API: %w", err)
	}

	// --- Shared broker→dispatch kubeconfig (lab fixture) ---
	// The dispatch-side dispatch-broker ServiceAccount is created by the ectobase-dispatch chart (system ns); mint
	// a token for it and hand-write the broker's kubeconfig to the dispatch's fabric address.
	slog.Info("minting broker dispatch token")
	token, err := exec.OutputStr(ctx, "kubectl", "--kubeconfig", s.DispatchKubeconfig,
		"create", "token", "dispatch-broker", "-n", "system", "--duration=24h")
	if err != nil {
		return fmt.Errorf("create broker token: %w", err)
	}
	brokerKubeconfig := filepath.Join(s.WorkDir, "broker-dispatch.kubeconfig")
	if err := os.WriteFile(brokerKubeconfig,
		[]byte(mintKubeconfig(s.DispatchIdentity, strings.TrimSpace(token))), 0o600); err != nil {
		return fmt.Errorf("write broker kubeconfig: %w", err)
	}

	// Pre-create one ClusterPool per compute cluster (lab fixture). platform.ectobase.dev is served
	// by the aggregated apiserver, so this must run after waitAggregatedAPI.
	slog.Info("pre-creating compute ClusterPools", "count", len(s.Compute))
	poolsYAML := clusterPoolsManifest(s.Compute)
	poolsPath := filepath.Join(s.WorkDir, "clusterpools.yaml")
	if err := os.WriteFile(poolsPath, []byte(poolsYAML), 0o644); err != nil {
		return fmt.Errorf("write clusterpools: %w", err)
	}
	if err := kubectlApply(ctx, s.DispatchKubeconfig, poolsPath); err != nil {
		return fmt.Errorf("apply clusterpools: %w", err)
	}

	// --- Each compute cluster ---
	for _, c := range s.Compute {
		slog.Info("installing ectobase-pool chart on compute cluster", "cluster", c.Name)
		// The chart renders a NetworkAttachmentDefinition unconditionally, so the NAD CRD must
		// exist first.
		if err := kubectlApply(ctx, c.Kubeconfig, s.NADCRDPath); err != nil {
			return fmt.Errorf("cluster %s: apply NAD CRD: %w", c.Name, err)
		}
		// The pool chart does not manage its release namespace, and the broker-dispatch-kubeconfig Secret
		// must exist before the chart's broker pod starts — so pre-create the (PSA-privileged)
		// ectobase-system namespace + the secret ahead of helm.
		if err := ensureHelmNamespace(ctx, c.Kubeconfig, "ectobase-system", "ectobase-pool"); err != nil {
			return fmt.Errorf("cluster %s: ensure namespace: %w", c.Name, err)
		}
		if err := createSecretFromFile(ctx, c.Kubeconfig, "ectobase-system",
			"broker-dispatch-kubeconfig", "kubeconfig", brokerKubeconfig); err != nil {
			return fmt.Errorf("cluster %s: create broker secret: %w", c.Name, err)
		}
		if err := helmInstallPool(ctx, c.Kubeconfig, c.Name, s.PoolChartPath, s.DispatchIdentity, s.UnderlayWithin); err != nil {
			return fmt.Errorf("cluster %s: helm install ectobase-pool: %w", c.Name, err)
		}
		// The broker mounts broker-dispatch-kubeconfig as a volume, so an existing broker pod keeps the
		// OLD kubeconfig across a re-`deploy` that rewrote the secret (helm won't roll it — the
		// secret is created outside the chart). On a fresh up the broker starts after the secret so
		// this is a no-op; on re-deploy it makes the broker pick up the current dispatch address.
		// Best-effort.
		if err := exec.Run(ctx, "kubectl", "--kubeconfig", c.Kubeconfig, "-n", "ectobase-system",
			"rollout", "restart", "deploy/dispatch-broker"); err != nil {
			slog.Debug("rollout restart dispatch-broker", "cluster", c.Name, "err", err)
		}
		// Multus (thin) so a Pod annotated onto our overlay is attached via Multus ->
		// flowplane-cni (a SECONDARY network) instead of a hand-driven gRPC attach. Installed
		// AFTER the chart so flowplane-cni + the dataplane-kubeconfig already exist. Compute
		// clusters only. The pod-materializer now ships in the ectobase-pool chart (base
		// substrate), so it is no longer applied here.
		if err := Multus(ctx, nil, c.Kubeconfig); err != nil {
			return fmt.Errorf("cluster %s: install Multus: %w", c.Name, err)
		}
	}

	// --- Readiness ---
	if err := waitPoolsReady(ctx, s.DispatchKubeconfig, s.Compute); err != nil {
		return fmt.Errorf("cluster pools ready: %w", err)
	}
	slog.Info("ectobase substrate deployed", "compute", len(s.Compute))
	return nil
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

// ensureHelmNamespace idempotently creates a namespace pre-stamped PSA-privileged (Talos
// enforces the baseline PodSecurity level cluster-wide, which rejects the dataplane pods —
// flowplane is privileged + hostPID + hostPath; agent/broker are hostNetwork; kind does not
// enforce PSA so this only bites on Talos). It also stamps Helm's managed-by label + release
// annotations so a chart that DID manage the namespace could adopt it; the pool chart does not
// manage its release namespace, so those are harmless here — the reason to pre-create is that the
// broker-dispatch-kubeconfig Secret has to exist before the chart's broker pod starts.
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

// waitAggregatedAPI blocks until the dispatch aggregated API actually serves the
// platform group — APIService availability + aggregation can lag the apply.
func waitAggregatedAPI(ctx context.Context, kubeconfig string) error {
	// Generous: the dispatch-apiserver pod must cold-pull its :dev image from the
	// in-fabric registry, start, and have its APIService become Available before the
	// aggregated group is served.
	slog.Info("waiting for the dispatch aggregated API to serve")
	// 12m: a cold boot pulls dispatch-apiserver over the in-fabric registry (slow) and
	// the pod may restart once while kine/postgres settle — 6m was occasionally too short.
	return wait.WaitFor(ctx, 12*time.Minute, 3*time.Second, func() (bool, error) {
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

// helmInstallDispatch installs/upgrades the ectobase-dispatch chart on the dispatch cluster. The reflector runs
// on the dispatch's fabric identity, so the dispatch-controller's -reflector-admin (a chart value) points
// there. --create-namespace makes the baseline-safe `system` release namespace; the chart creates
// the PSA-privileged ectobase-system namespace itself.
func helmInstallDispatch(ctx context.Context, kubeconfig, chartPath, dispatchIdentity string) error {
	args := []string{"upgrade", "--install", "ectobase-dispatch", chartPath,
		"--kubeconfig", kubeconfig,
		"--namespace", "system", "--create-namespace",
		"--set", "reflectorAdmin=[" + dispatchIdentity + "]:1338",
	}
	return exec.Run(ctx, "helm", args...)
}

// helmInstallPool installs/upgrades the ectobase-pool chart with a broker on one compute cluster.
// apiserverAddress is the LOCAL cluster (the agent reads/writes its own cluster); reflectorAddress
// points at the dispatch's reflector on the fabric. The release namespace (ectobase-system) is
// pre-created by the caller (ensureHelmNamespace), so no --create-namespace here.
func helmInstallPool(ctx context.Context, kubeconfig, clusterName, chartPath, dispatchIdentity, underlayWithin string) error {
	args := []string{"upgrade", "--install", "ectobase-pool", chartPath,
		"--kubeconfig", kubeconfig,
		"--namespace", "ectobase-system",
		"--set", "broker.clusterName=" + clusterName,
		"--set", "apiserverAddress=https://127.0.0.1:6443",
		"--set", "reflectorAddress=[" + dispatchIdentity + "]:1338",
		"--set", "installCRDs=true",
		"--set", "dataplane=ebpf",
	}
	if underlayWithin != "" {
		// flowplane picks the node's fabric underlay as the host address inside this aggregate — the
		// authoritative filter past a mgmt hostIP / Talos hostDNS lo ULA. The CIDR has no comma so
		// helm --set takes it literally (`:` and `/` are not --set metacharacters).
		args = append(args, "--set", "underlayWithin="+underlayWithin)
	}
	args = append(args, "--wait", "--timeout", "8m")
	return exec.Run(ctx, "helm", args...)
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

// mintKubeconfig hand-writes a token kubeconfig for the broker→dispatch connection.
// The bracketed-IPv6 server MUST be double-quoted: an unquoted https://[..]:6443
// is a YAML flow sequence and fails to parse. TLS verify is skipped because
// the dispatch's serving cert is self-signed.
func mintKubeconfig(dispatchHost, token string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: dispatch
  cluster:
    server: "https://[%s]:6443"
    insecure-skip-tls-verify: true
contexts:
- name: broker@dispatch
  context:
    cluster: dispatch
    user: dispatch-broker
current-context: broker@dispatch
users:
- name: dispatch-broker
  user:
    token: %s
`, dispatchHost, token)
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
