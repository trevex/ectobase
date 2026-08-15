package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/wait"
)

// KubeVirt/CDI pins (ported to Go from the old install-stack bring-up script). Bumping these is the single
// place versions change; the URL helpers below embed them.
const (
	KubeVirtVersion = "v1.5.0"
	CDIVersion      = "v1.61.0"
)

// kubevirtOperatorURL is the versioned KubeVirt operator manifest URL.
func kubevirtOperatorURL() string {
	return "https://github.com/kubevirt/kubevirt/releases/download/" + KubeVirtVersion + "/kubevirt-operator.yaml"
}

// kubevirtCRURL is the versioned KubeVirt CR manifest URL.
func kubevirtCRURL() string {
	return "https://github.com/kubevirt/kubevirt/releases/download/" + KubeVirtVersion + "/kubevirt-cr.yaml"
}

// cdiOperatorURL is the versioned CDI operator manifest URL.
func cdiOperatorURL() string {
	return "https://github.com/kubevirt/containerized-data-importer/releases/download/" + CDIVersion + "/cdi-operator.yaml"
}

// cdiCRURL is the versioned CDI CR manifest URL.
func cdiCRURL() string {
	return "https://github.com/kubevirt/containerized-data-importer/releases/download/" + CDIVersion + "/cdi-cr.yaml"
}

// kubevirtCRPatch is the merge-patch applied to the KubeVirt CR (ported to Go
// from the old install-stack bring-up script). It:
//   - enables software emulation (useEmulation:true) — clab/kind nodes have no KVM —
//     and the NetworkBindingPlugins feature gate,
//   - registers the `flowplane` network binding as domainAttachmentType=tap wired to
//     our NAD ectobase-system/flowplane (NOT managedTap, which bridges + hijacks DHCP).
//
// Pure (no I/O) so the exact JSON is unit-tested. Single line.
func kubevirtCRPatch() string {
	return `{"spec":{"configuration":{"developerConfiguration":{"useEmulation":true,"featureGates":["NetworkBindingPlugins"]},"network":{"binding":{"flowplane":{"domainAttachmentType":"tap","networkAttachmentDefinition":"ectobase-system/flowplane"}}}}}}`
}

// KubeVirtCDI installs KubeVirt + CDI onto one already-up cluster and registers the
// flowplane network binding (ported to Go from the old install-stack bring-up script's KubeVirt/CDI block).
//
// Sequence per component: apply operator, apply CR, label the operand namespace
// PSA-privileged (Talos's baseline PSA rejects the privileged virt/cdi pods
// otherwise — the operator manifest creates the ns, so apply-then-label ordering is
// fine; labeling is best-effort), wait for the CR to go Available, then (KubeVirt
// only) merge-patch the CR with emulation + the flowplane binding.
func KubeVirtCDI(ctx context.Context, r Runner, kubeconfig string) error {
	r = runnerOf(r)

	// --- KubeVirt ---
	slog.Info("installing KubeVirt", "version", KubeVirtVersion, "kubeconfig", kubeconfig)
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", kubevirtOperatorURL()); err != nil {
		return fmt.Errorf("apply kubevirt operator: %w", err)
	}
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", kubevirtCRURL()); err != nil {
		return fmt.Errorf("apply kubevirt cr: %w", err)
	}
	// Talos baseline PSA rejects the privileged virt-handler/virt-launcher pods unless
	// the kubevirt ns is labeled privileged. The operator manifest creates the ns, so
	// this ordering is fine; best-effort (log at Debug on error).
	if err := labelNamespacePrivileged(ctx, r, kubeconfig, "kubevirt"); err != nil {
		slog.Debug("label kubevirt ns privileged (ns not created yet?)", "err", err)
	}
	// Patch the CR (emulation + flowplane binding + control-plane tolerations) BEFORE
	// waiting for Available: the workloads toleration is what lets the virt-handler DS
	// target the tainted single node, without which the CR never goes Available. Retry
	// briefly — the operator's validating webhook may not be serving the instant the CR
	// is created.
	slog.Info("configuring the KubeVirt CR (emulation, flowplane binding)")
	if err := retryPatch(ctx, r, kubeconfig, "kubevirt", "kubevirt", "kubevirt", kubevirtCRPatch()); err != nil {
		return fmt.Errorf("patch kubevirt cr: %w", err)
	}
	slog.Info("waiting for KubeVirt to become Available (up to 10m)")
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", "kubevirt",
		"wait", "kv/kubevirt", "--for=condition=Available", "--timeout=10m"); err != nil {
		return fmt.Errorf("wait kubevirt Available: %w", err)
	}

	// --- CDI ---
	slog.Info("installing CDI", "version", CDIVersion, "kubeconfig", kubeconfig)
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", cdiOperatorURL()); err != nil {
		return fmt.Errorf("apply cdi operator: %w", err)
	}
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", cdiCRURL()); err != nil {
		return fmt.Errorf("apply cdi cr: %w", err)
	}
	if err := labelNamespacePrivileged(ctx, r, kubeconfig, "cdi"); err != nil {
		slog.Debug("label cdi ns privileged (ns not created yet?)", "err", err)
	}
	slog.Info("waiting for CDI to become Available (up to 10m)")
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", "cdi",
		"wait", "cdi/cdi", "--for=condition=Available", "--timeout=10m"); err != nil {
		return fmt.Errorf("wait cdi Available: %w", err)
	}

	slog.Info("KubeVirt + CDI installed", "kubeconfig", kubeconfig)
	return nil
}

// retryPatch merge-patches a namespaced resource, retrying for up to 2m: an operator's
// validating webhook (KubeVirt/CDI) is often not yet serving the instant its CR is
// created, so the first patch can transiently fail. Returns the last patch error on
// timeout.
func retryPatch(ctx context.Context, r Runner, kubeconfig, ns, resource, name, patch string) error {
	var last error
	werr := wait.WaitFor(ctx, 2*time.Minute, 5*time.Second, func() (bool, error) {
		last = r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", ns,
			"patch", resource, name, "--type=merge", "-p", patch)
		return last == nil, nil
	})
	if werr != nil && last != nil {
		return last
	}
	return werr
}

// labelNamespacePrivileged stamps ns with the PSA enforce=privileged label
// (--overwrite so it is idempotent).
func labelNamespacePrivileged(ctx context.Context, r Runner, kubeconfig, ns string) error {
	return r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "label", "namespace", ns,
		"pod-security.kubernetes.io/enforce=privileged", "--overwrite")
}

// PatchDispatchCSIClusterID sets the ceph cluster fsid on the dispatch controller so
// its ceph-csi NetworkFence actuator targets the right external cluster. The dispatch
// controller is Deployment dispatch-controller in namespace system; its container
// args include an empty `-csi-cluster-id=` element that we replace with
// `-csi-cluster-id=<fsid>`.
//
// It reads the current args, locates the flag index, and applies a JSON6902 replace
// at exactly that index (composed by the pure csiClusterIDPatch helper).
func PatchDispatchCSIClusterID(ctx context.Context, r Runner, dispatchKubeconfig, fsid string) error {
	r = runnerOf(r)
	slog.Info("wiring the ceph fsid into dispatch-controller", "fsid", fsid)

	out, err := r.Output(ctx, "kubectl", "--kubeconfig", dispatchKubeconfig,
		"-n", "system", "get", "deploy", "dispatch-controller",
		"-o", "jsonpath={.spec.template.spec.containers[0].args}")
	if err != nil {
		return fmt.Errorf("get dispatch-controller args: %w", err)
	}
	var args []string
	if err := json.Unmarshal(out, &args); err != nil {
		return fmt.Errorf("parse dispatch-controller args %q: %w", string(out), err)
	}
	_, patch, err := csiClusterIDPatch(args, fsid)
	if err != nil {
		return err
	}
	if err := r.Run(ctx, "kubectl", "--kubeconfig", dispatchKubeconfig,
		"-n", "system", "patch", "deploy", "dispatch-controller", "--type=json", "-p", patch); err != nil {
		return fmt.Errorf("patch dispatch-controller csi-cluster-id: %w", err)
	}
	slog.Info("dispatch-controller csi-cluster-id set", "fsid", fsid)
	return nil
}

// EnableVMMaterializer turns on the vm-materializer (SA + RBAC + Deployment in ectobase-system)
// on a compute cluster by upgrading the ectobase-pool release with vmMaterializer.enabled=true.
// The materializer turns a broker-synced CompiledVM into a KubeVirt VirtualMachine (+ RBD
// DataVolume) — the compute-side half of the Tier-2 VM pipeline. It ships gated-off in the pool
// chart, so `lab tier2` flips it on here. --reuse-values keeps the release's existing values.
func EnableVMMaterializer(ctx context.Context, r Runner, kubeconfig, poolChartPath string) error {
	r = runnerOf(r)
	slog.Info("enabling vm-materializer via ectobase-pool upgrade")
	if err := r.Run(ctx, "helm", "upgrade", "ectobase-pool", poolChartPath,
		"--kubeconfig", kubeconfig, "--namespace", "ectobase-system",
		"--reuse-values", "--set", "vmMaterializer.enabled=true", "--wait", "--timeout", "5m"); err != nil {
		return fmt.Errorf("enable vm-materializer: %w", err)
	}
	return nil
}

// csiClusterIDPatch finds the index of the `-csi-cluster-id=` arg in args and
// composes the JSON6902 patch body that replaces it with `-csi-cluster-id=<fsid>`.
// Pure (no I/O) so PatchDispatchCSIClusterID's index-finding + patch composition is
// unit-tested. Errors if no `-csi-cluster-id=` arg is present.
func csiClusterIDPatch(args []string, fsid string) (index int, patchJSON string, err error) {
	const prefix = "-csi-cluster-id="
	for i, a := range args {
		if strings.HasPrefix(a, prefix) {
			patch := fmt.Sprintf(`[{"op":"replace","path":"/spec/template/spec/containers/0/args/%d","value":"-csi-cluster-id=%s"}]`, i, fsid)
			return i, patch, nil
		}
	}
	return 0, "", fmt.Errorf("no %q arg found in dispatch-controller args %v", prefix, args)
}
