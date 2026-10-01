package deploy

import (
	"context"
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
	got := clusterPoolsManifest([]ComputeCluster{
		{Name: "k02", UnderlayCIDRs: "fd00:cafe:1914::/48"},
		{Name: "k03", UnderlayCIDRs: "fd00:cafe:2a3b::/48"},
	})
	for _, want := range []string{
		"apiVersion: platform.ectobase.dev/v1alpha1",
		"kind: ClusterPool",
		"name: k02",
		"name: k03",
		"region: eu",
		// Each pool's operator-declared underlay aggregate: the signer constrains the pool's
		// route-bus intermediate to it, and denies a pool that has none.
		`underlayPrefix: "fd00:cafe:1914::/48"`,
		`underlayPrefix: "fd00:cafe:2a3b::/48"`,
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
		// The pool namespace must exist before the compiler writes a twin into it —
		// NamespaceLifecycle admission rejects writes to a namespace that does not exist.
		"kind: Namespace",
		"name: pool-k02",
		"name: pool-k03",
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

// The dispatch cluster has no StorageClass until `lab ceph` runs, so the chart's default PVC would
// sit Pending and `lab up` would never see the dispatch come up.
func TestDispatchHelmArgsPersistPostgresOnHostPath(t *testing.T) {
	args := dispatchHelmArgs("/kc", "/chart", "fd00:db8:0:1::1", true, "fd00:db8:0:1::1", "registry:5000", "", nil)
	if !containsSubseq(args, []string{"--set", "postgres.persistence.type=hostPath"}) {
		t.Fatalf("dispatch install does not put postgres on a hostPath:\n%v", args)
	}
}

// The dispatch chart trusts no fleet identity by default, so the lab must name its edge identity, or
// the signer denies it as neither a ClusterPool nor a fleet identity and no edge joins the route bus.
func TestDispatchHelmArgsTrustTheEdgeFleetIdentity(t *testing.T) {
	s := EctobaseSpec{RouteBusMTLS: true, EdgePKIDir: "/build/edge/pki"}
	args := dispatchHelmArgs("/kc", "/chart", "fd00:db8:0:1::1", true, "fd00:db8:0:1::1", "registry:5000", "", fleetIdentities(s))
	if !containsSubseq(args, []string{"--set", "pki.fleetIdentities={edge}"}) {
		t.Fatalf("dispatch install does not trust the edge fleet identity:\n%v", args)
	}
	// No edge provisioned: nothing to trust.
	for _, s := range []EctobaseSpec{{RouteBusMTLS: true}, {EdgePKIDir: "/build/edge/pki"}} {
		if got := fleetIdentities(s); len(got) != 0 {
			t.Errorf("fleetIdentities(%+v) = %v, want none", s, got)
		}
	}
}

// A Deployment first created under RollingUpdate carries an apiserver-defaulted rollingUpdate that
// Helm 4's server-side apply does not own and so never removes; switching it to Recreate then fails.
func TestNeedsRecreateMigration(t *testing.T) {
	for _, tc := range []struct {
		strategyType string // kubectl get -o jsonpath={.spec.strategy.type} output
		want         bool
	}{
		{"", false}, // absent (--ignore-not-found): a fresh install, nothing to migrate
		{"Recreate", false},
		{"Recreate\n", false},
		{"RollingUpdate", true},
	} {
		if got := needsRecreateMigration(tc.strategyType); got != tc.want {
			t.Errorf("needsRecreateMigration(%q) = %v, want %v", tc.strategyType, got, tc.want)
		}
	}
}

func TestRecreateMigrationArgs(t *testing.T) {
	d := recreateDeployment{Namespace: "system", Name: "postgres"}
	get := strategyTypeArgs("/kc", d)
	for _, want := range [][]string{
		{"--kubeconfig", "/kc"},
		{"get", "deploy", "postgres", "-n", "system"},
		{"-o", "jsonpath={.spec.strategy.type}"},
		{"--ignore-not-found"},
	} {
		if !containsSubseq(get, want) {
			t.Errorf("strategy read argv missing %v:\n%v", want, get)
		}
	}
	// One merge patch covers both cases: null deletes rollingUpdate when it is present and is a
	// no-op when it is not.
	patch := recreatePatchArgs("/kc", d)
	want := []string{"--kubeconfig", "/kc", "patch", "deploy", "postgres", "-n", "system",
		"--type=merge", "-p", `{"spec":{"strategy":{"type":"Recreate","rollingUpdate":null}}}`}
	if strings.Join(patch, " ") != strings.Join(want, " ") {
		t.Fatalf("patch argv:\n got %v\nwant %v", patch, want)
	}
}

// The dispatch chart's Deployments that moved to Recreate, in the namespaces the lab installs them into.
func TestRecreateDeploymentsCoverTheChart(t *testing.T) {
	want := map[recreateDeployment]bool{
		{Namespace: "system", Name: "postgres"}:           true,
		{Namespace: "ectobase-system", Name: "reflector"}: true,
	}
	if len(recreateDeployments) != len(want) {
		t.Fatalf("recreateDeployments = %v, want %v", recreateDeployments, want)
	}
	for _, d := range recreateDeployments {
		if !want[d] {
			t.Errorf("unexpected migration target %v", d)
		}
	}
}

// strategyRunner answers each `kubectl get deploy <name>` with a canned strategy type.
type strategyRunner struct {
	fakeRunner
	strategy map[string]string // deployment name -> jsonpath output
}

func (r *strategyRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	r.record(name, args...)
	for dep, out := range r.strategy {
		if containsSubseq(args, []string{"get", "deploy", dep}) {
			return []byte(out), nil
		}
	}
	return nil, nil
}

func TestMigrateRecreateDeployments(t *testing.T) {
	r := &strategyRunner{strategy: map[string]string{
		"postgres":  "RollingUpdate", // a release from before the switch
		"reflector": "Recreate",      // already migrated: the step is idempotent
	}}
	if err := migrateRecreateDeployments(context.Background(), r, "/kc"); err != nil {
		t.Fatalf("migrateRecreateDeployments: %v", err)
	}
	if r.findCall("kubectl", "patch", "deploy", "postgres") == nil {
		t.Errorf("postgres (RollingUpdate) was not patched:\n%v", r.calls)
	}
	if r.findCall("kubectl", "patch", "deploy", "reflector") != nil {
		t.Errorf("reflector (already Recreate) was patched:\n%v", r.calls)
	}

	// A fresh install: nothing exists yet, so nothing is patched.
	fresh := &strategyRunner{}
	if err := migrateRecreateDeployments(context.Background(), fresh, "/kc"); err != nil {
		t.Fatalf("migrateRecreateDeployments (fresh): %v", err)
	}
	if fresh.findCall("kubectl", "patch") != nil {
		t.Errorf("fresh install was patched:\n%v", fresh.calls)
	}
}
