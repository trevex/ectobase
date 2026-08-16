package deploy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/wait"
)

// CertManagerVersion pins cert-manager. Bumping it is the single place the version
// changes; the URL helper below embeds it. The static install manifest carries the
// controller/webhook/cainjector images from quay.io, which the in-fabric registry
// mirror pulls onto the nodes.
const CertManagerVersion = "v1.21.1"

// certManagerManifestURL is the versioned upstream static install manifest (CRDs +
// namespace + the three deployments + webhook configs, all self-contained).
func certManagerManifestURL() string {
	return "https://github.com/cert-manager/cert-manager/releases/download/" +
		CertManagerVersion + "/cert-manager.yaml"
}

// CertManager installs cert-manager (pinned CertManagerVersion) onto one already-up
// cluster and blocks until its webhook actually admits resources — the route-bus PKI
// charts create Issuer/ClusterIssuer/Certificate objects at helm-install time, which
// the cert-manager webhook must be ready to validate or the install fails.
//
// clusterResourceNamespace (when non-empty) rewrites the controller's
// --cluster-resource-namespace: a CA-type ClusterIssuer reads its CA secret from that
// namespace, and the dispatch chart puts the route-bus root CA secret in `system`
// (the dispatch-controller's namespace), so the DISPATCH cluster installs cert-manager
// with clusterResourceNamespace=system. Compute clusters use a namespaced Issuer, so
// they pass "" (default cert-manager namespace).
//
// Idempotent (kubectl apply). kubectl runs on the HOST (which has internet); image
// pulls happen on the NODES via the registry mirror.
func CertManager(ctx context.Context, r Runner, kubeconfig, clusterResourceNamespace string) error {
	r = runnerOf(r)

	slog.Info("installing cert-manager", "version", CertManagerVersion,
		"clusterResourceNamespace", clusterResourceNamespace, "kubeconfig", kubeconfig)
	raw, err := r.Output(ctx, "curl", "-fsSL", certManagerManifestURL())
	if err != nil {
		return fmt.Errorf("fetch cert-manager manifest: %w", err)
	}
	manifest := string(raw)
	if clusterResourceNamespace != "" {
		// The static manifest defaults the controller to its own namespace via
		// `--cluster-resource-namespace=$(POD_NAMESPACE)`. Point it at the namespace that
		// actually holds the ClusterIssuer's CA secret.
		old := "--cluster-resource-namespace=$(POD_NAMESPACE)"
		repl := "--cluster-resource-namespace=" + clusterResourceNamespace
		if !strings.Contains(manifest, old) {
			return fmt.Errorf("cert-manager manifest %s no longer contains %q — the arg moved; update CertManager",
				CertManagerVersion, old)
		}
		manifest = strings.ReplaceAll(manifest, old, repl)
	}
	if err := r.RunStdin(ctx, manifest, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-"); err != nil {
		return fmt.Errorf("apply cert-manager manifest: %w", err)
	}

	// Wait for the three deployments. A COLD pull of the cert-manager images through the
	// fabric mirror can take several minutes (same fabric-cold-pull reason the dispatch
	// apiserver gets 12m); once the mirror has cached them, restarts are fast.
	for _, deploy := range []string{"cert-manager", "cert-manager-webhook", "cert-manager-cainjector"} {
		slog.Info("waiting for cert-manager deployment to roll out (up to 12m)", "deploy", deploy)
		if err := r.Run(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", "cert-manager",
			"rollout", "status", "deploy/"+deploy, "--timeout=12m"); err != nil {
			return fmt.Errorf("wait cert-manager deployment %s: %w", deploy, err)
		}
	}

	// Rollout-ready is necessary but not sufficient: the webhook's Service endpoints and
	// the apiserver's admission wiring can lag the pod becoming Ready, so a Certificate
	// applied immediately gets "connection refused"/"no endpoints available". Gate on the
	// webhook actually admitting a throwaway Issuer (server dry-run hits the admission path).
	slog.Info("waiting for the cert-manager webhook to admit resources")
	probe := `apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: webhook-readiness-probe
  namespace: cert-manager
spec:
  selfSigned: {}
`
	if err := wait.WaitFor(ctx, 5*time.Minute, 3*time.Second, func() (bool, error) {
		err := r.RunStdin(ctx, probe, "kubectl", "--kubeconfig", kubeconfig,
			"apply", "--dry-run=server", "-f", "-")
		return err == nil, nil
	}); err != nil {
		return fmt.Errorf("cert-manager webhook never became ready: %w", err)
	}

	slog.Info("cert-manager installed", "kubeconfig", kubeconfig)
	return nil
}
