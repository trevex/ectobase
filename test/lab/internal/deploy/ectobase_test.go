package deploy

import (
	"strings"
	"testing"
)

func TestMintKubeconfigCAQuotesBracketedV6Server(t *testing.T) {
	kc := mintKubeconfigCA("fd00:cafe:abcd:1::1", "tok-123", "Y2E=")
	// The bracketed-IPv6 server MUST be double-quoted, else YAML parses [..] as a
	// flow sequence and the kubeconfig breaks.
	if !strings.Contains(kc, `server: "https://[fd00:cafe:abcd:1::1]:6444"`) {
		t.Fatalf("server line not present/quoted:\n%s", kc)
	}
	if !strings.Contains(kc, "certificate-authority-data: Y2E=") {
		t.Fatalf("expected certificate-authority-data: Y2E=:\n%s", kc)
	}
	if !strings.Contains(kc, "token: tok-123") {
		t.Fatalf("token not embedded:\n%s", kc)
	}
}

func TestClusterPoolsManifest(t *testing.T) {
	got := clusterPoolsManifest([]ComputeCluster{{Name: "k02"}, {Name: "k03"}})
	for _, want := range []string{
		"apiVersion: platform.ectobase.dev/v1alpha1",
		"kind: ClusterPool",
		"name: k02",
		"name: k03",
		"region: eu",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("manifest missing %q:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "kind: ClusterPool"); n != 2 {
		t.Fatalf("expected 2 ClusterPools, got %d:\n%s", n, got)
	}
}

// TestClusterPoolsManifestScopesRouteBusPerPool guards the per-pool isolation of the route-bus
// PKI: a pool's RouteBusIdentity carries its intermediate-CA CSR + signed cert, so the grant must
// be resourceNames-scoped to that pool alone. A fleet-wide grant (or a shared bootstrap SA) would
// let any pool obtain any OTHER pool's intermediate CA and mint leaves impersonating its nodes.
func TestClusterPoolsManifestScopesRouteBusPerPool(t *testing.T) {
	got := clusterPoolsManifest([]ComputeCluster{{Name: "k02"}, {Name: "k03"}})

	for _, want := range []string{
		// Pre-created so the grant can omit `create` (resourceNames cannot scope it).
		"kind: RouteBusIdentity",
		// Per-pool bootstrap SA — never a single shared one.
		"name: dispatch-broker-bootstrap-k02",
		"name: dispatch-broker-bootstrap-k03",
		// Scoped to this pool's own object only.
		`resourceNames: ["k02"]`,
		`resourceNames: ["k03"]`,
		// Bound to the steady-state cert identity too, not just the bootstrap SA.
		`name: "ectobase:cluster:k02"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("manifest missing %q:\n%s", want, got)
		}
	}

	// The grant must never include `create` — that verb cannot be resourceNames-scoped, so
	// granting it would re-open cross-pool RouteBusIdentity creation.
	if strings.Contains(got, `"create"`) {
		t.Fatalf("per-pool route-bus grant must not include create:\n%s", got)
	}
	// One identity + one SA + one ClusterRole + one binding per pool. Anchored to line start so
	// the `kind:` entries inside roleRef/subjects don't count as resources.
	for _, kind := range []string{"\nkind: RouteBusIdentity", "\nkind: ServiceAccount", "\nkind: ClusterRole\n", "\nkind: ClusterRoleBinding"} {
		if n := strings.Count(got, kind); n != 2 {
			t.Fatalf("expected 2 of %q, got %d:\n%s", kind, n, got)
		}
	}
}

func TestClusterPoolsManifestEmpty(t *testing.T) {
	if got := clusterPoolsManifest(nil); got != "" {
		t.Fatalf("expected empty manifest for no clusters, got %q", got)
	}
}
