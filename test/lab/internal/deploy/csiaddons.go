package deploy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/wait"
)

// csi-addons pins (csi-addons-up.sh). The version tags both the release assets and
// the k8s-sidecar image.
const (
	CSIAddonsVersion = "v0.12.0"
	CSIAddonsNS      = "csi-addons-system"
	// The ceph-csi RBD provisioner Deployment + its ServiceAccount (the fence
	// actuator the sidecar registers a CSIAddonsNode for).
	CephCSIProv   = "ceph-csi-rbd-provisioner"
	CephCSIProvSA = "ceph-csi-rbd-provisioner"
)

// csiAddonsReleaseURL builds a release-asset URL for the pinned csi-addons version.
func csiAddonsReleaseURL(version, asset string) string {
	return fmt.Sprintf("https://github.com/csi-addons/kubernetes-csi-addons/releases/download/%s/%s", version, asset)
}

// CSIAddons installs the csi-addons controller + NetworkFence CRD (the Tier-2
// storage-fence executor) into the target (central / fence-executor) cluster at
// the pinned release, then wires the k8s-sidecar into the ceph-csi RBD provisioner
// (the actuator the controller dials to run `ceph osd blocklist`). Port of
// hack/csi-addons-up.sh.
//
// csi-addons provides the NetworkFence CRD + controller that the Tier-2 fence gate
// drives to block a partitioned node's ceph RBD access (fence-before-failover). The
// ceph-csi-rbd Helm chart ships the driver's csi-addons socket but NO sidecar, so
// without the sidecar the controller has no CSIAddonsNode to target and
// NetworkFence never leaves Pending.
//
// version defaults to CSIAddonsVersion when empty.
func CSIAddons(ctx context.Context, r Runner, kubeconfig, version string) error {
	r = runnerOf(r)
	if version == "" {
		version = CSIAddonsVersion
	}

	// kubernetes-csi-addons release assets: CRDs (incl. NetworkFence), rbac,
	// controller. The controller runs in namespace csi-addons-system; rbac.yaml
	// references it (ServiceAccount/RoleBindings) but does NOT create it, so create
	// it first (else rbac apply -> "namespaces csi-addons-system not found").
	slog.Info("installing csi-addons (crds, rbac, controller)", "version", version)
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", csiAddonsReleaseURL(version, "crds.yaml")); err != nil {
		return fmt.Errorf("apply csi-addons crds: %w", err)
	}
	// Create csi-addons-system, PSA-privileged (Talos rejects the baseline-violating
	// controller pod otherwise). Idempotent via dry-run|apply of a labeled ns.
	if err := ensureNamespacePrivileged(ctx, r, kubeconfig, CSIAddonsNS); err != nil {
		return fmt.Errorf("create %s namespace: %w", CSIAddonsNS, err)
	}
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", csiAddonsReleaseURL(version, "rbac.yaml")); err != nil {
		return fmt.Errorf("apply csi-addons rbac: %w", err)
	}
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", csiAddonsReleaseURL(version, "setup-controller.yaml")); err != nil {
		return fmt.Errorf("apply csi-addons controller: %w", err)
	}
	slog.Info("csi-addons controller applied (NetworkFence CRD available)")

	// --- csi-addons k8s-sidecar into the ceph-csi RBD provisioner (the fence
	// actuator) --- The sidecar (image tag == the csi-addons release) runs beside the
	// driver, self-registers a CSIAddonsNode, and serves the NetworkFence RPC the
	// controller dials to blocklist a /64 at ceph. Skip if the provisioner isn't here
	// (this cluster didn't get ceph-csi).
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", CephCSINS, "get", "deploy", CephCSIProv); err != nil {
		slog.Warn("ceph-csi provisioner not found — run CephCSI on this cluster first to wire the fence actuator",
			"namespace", CephCSINS, "deploy", CephCSIProv)
		return nil
	}

	slog.Info("wiring csi-addons sidecar into the ceph-csi provisioner", "namespace", CephCSINS, "deploy", CephCSIProv)
	// RBAC for the provisioner SA the sidecar runs as: manage its CSIAddonsNode, read
	// pods + replicasets/deployments (to set the node's owner ref), and
	// system:auth-delegator so it can TokenReview the controller's mTLS identity
	// (csi-addons enables auth by default).
	if err := r.RunStdin(ctx, csiAddonsSidecarRBAC(CephCSIProvSA, CephCSINS),
		"kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"); err != nil {
		return fmt.Errorf("apply csi-addons sidecar rbac: %w", err)
	}

	// Add the sidecar container (strategic-merge: idempotent by container name). It
	// shares the driver's socket-dir emptyDir (/csi) where ceph-csi exposes
	// csi-addons.sock.
	if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", CephCSINS,
		"patch", "deploy", CephCSIProv, "--type=strategic", "-p", csiAddonsSidecarPatch(version)); err != nil {
		return fmt.Errorf("patch ceph-csi provisioner with csi-addons sidecar: %w", err)
	}

	// Wait for the rollout to land the sidecar.
	if err := wait.WaitFor(ctx, 3*time.Minute, 5*time.Second, func() (bool, error) {
		err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", CephCSINS,
			"rollout", "status", "deploy/"+CephCSIProv, "--timeout=10s")
		return err == nil, err
	}); err != nil {
		return fmt.Errorf("ceph-csi provisioner rollout (sidecar): %w", err)
	}
	slog.Info("csi-addons sidecar wired; a CSIAddonsNode should register")
	return nil
}

// ensureNamespacePrivileged idempotently creates ns labeled PSA-privileged
// (dry-run|apply of a plain labeled Namespace). Unlike ensureHelmNamespace it does
// NOT stamp Helm ownership — csi-addons-system is applied by raw manifests, not a
// chart.
func ensureNamespacePrivileged(ctx context.Context, r Runner, kubeconfig, ns string) error {
	m := fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    pod-security.kubernetes.io/enforce: privileged
`, ns)
	return r.RunStdin(ctx, m, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-")
}

// csiAddonsSidecarRBAC renders the ClusterRole + bindings the provisioner SA needs
// to run the sidecar (manage CSIAddonsNodes, read pods + workload owner refs, and
// system:auth-delegator for TokenReview). sa/ns name the provisioner SA subject.
func csiAddonsSidecarRBAC(sa, ns string) string {
	return fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: ceph-csi-addons-sidecar }
rules:
  - apiGroups: ["csiaddons.openshift.io"]
    resources: ["csiaddonsnodes"]
    verbs: ["create","get","list","watch","update","patch","delete"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get","list"]
  - apiGroups: ["apps"]
    resources: ["replicasets","deployments","daemonsets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: ceph-csi-addons-sidecar }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: ceph-csi-addons-sidecar }
subjects:
  - { kind: ServiceAccount, name: %s, namespace: %s }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: ceph-csi-addons-authdelegator }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:auth-delegator }
subjects:
  - { kind: ServiceAccount, name: %s, namespace: %s }
`, sa, ns, sa, ns)
}

// csiAddonsSidecarPatch is the strategic-merge patch that injects the k8s-sidecar
// container into the provisioner pod template. The sidecar image tag == the
// csi-addons release version. It shares the driver's socket-dir emptyDir (/csi)
// where ceph-csi exposes csi-addons.sock, listens on controller-port 9070, and
// takes its identity from the downward-API env.
func csiAddonsSidecarPatch(version string) string {
	image := "quay.io/csiaddons/k8s-sidecar:" + version
	return fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{`+
		`"name":"csi-addons",`+
		`"image":"%s",`+
		`"args":["--node-id=$(NODE_ID)","--csi-addons-address=$(CSIADDONS_ENDPOINT)","--controller-port=9070","--pod=$(POD_NAME)","--namespace=$(POD_NAMESPACE)","--pod-uid=$(POD_UID)"],`+
		`"ports":[{"containerPort":9070}],`+
		`"env":[`+
		`{"name":"NODE_ID","valueFrom":{"fieldRef":{"fieldPath":"spec.nodeName"}}},`+
		`{"name":"POD_NAME","valueFrom":{"fieldRef":{"fieldPath":"metadata.name"}}},`+
		`{"name":"POD_NAMESPACE","valueFrom":{"fieldRef":{"fieldPath":"metadata.namespace"}}},`+
		`{"name":"POD_UID","valueFrom":{"fieldRef":{"fieldPath":"metadata.uid"}}},`+
		`{"name":"CSIADDONS_ENDPOINT","value":"unix:///csi/csi-addons.sock"}`+
		`],`+
		`"volumeMounts":[{"name":"socket-dir","mountPath":"/csi"}]`+
		`}]}}}}`, image)
}
