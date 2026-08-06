package deploy

import (
	"strings"
	"testing"
)

func TestMintKubeconfigQuotesBracketedV6Server(t *testing.T) {
	kc := mintKubeconfig("fd00:cafe:abcd:1::1", "tok-123")
	// The bracketed-IPv6 server MUST be double-quoted, else YAML parses [..] as a
	// flow sequence and the kubeconfig breaks.
	if !strings.Contains(kc, `server: "https://[fd00:cafe:abcd:1::1]:6443"`) {
		t.Fatalf("server line not present/quoted:\n%s", kc)
	}
	if !strings.Contains(kc, "insecure-skip-tls-verify: true") {
		t.Fatalf("expected insecure-skip-tls-verify: true:\n%s", kc)
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

func TestClusterPoolsManifestEmpty(t *testing.T) {
	if got := clusterPoolsManifest(nil); got != "" {
		t.Fatalf("expected empty manifest for no clusters, got %q", got)
	}
}
