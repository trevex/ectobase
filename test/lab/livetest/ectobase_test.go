//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/config"
)

// computeClusters returns the non-central clusters (the broker/agent-running
// compute pools, e.g. k02, k03).
func computeClusters(cfg *config.Config) []config.Cluster {
	var out []config.Cluster
	for _, cl := range cfg.Fabric.Clusters {
		if cl.Name == "central" {
			continue
		}
		out = append(out, cl)
	}
	return out
}

// poolField reads a jsonpath field of a compute ClusterPool from central. It uses
// the fully-qualified resource (clusterpools.platform.ectobase.dev): short-name
// discovery on the aggregated API flakes.
func poolField(ctx context.Context, cfg *config.Config, pool, jsonpath string) (string, error) {
	out, err := kubectl(ctx, cfg, "central",
		"get", "clusterpools.platform.ectobase.dev", pool, "-o", "jsonpath="+jsonpath)
	return strings.TrimSpace(out), err
}

// TestClusterPoolsReady asserts every compute pool on central reports
// status.phase == Ready with a non-empty status.nodePrefixes.
func TestClusterPoolsReady(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	for _, cl := range computeClusters(cfg) {
		cl := cl
		t.Run(cl.Name, func(t *testing.T) {
			eventually(t, 2*time.Minute, 5*time.Second, func() error {
				phase, err := poolField(ctx, cfg, cl.Name, "{.status.phase}")
				if err != nil {
					return fmt.Errorf("read %s status.phase: %w", cl.Name, err)
				}
				if phase != "Ready" {
					return fmt.Errorf("pool %s phase=%q, want Ready", cl.Name, phase)
				}
				prefixes, err := poolField(ctx, cfg, cl.Name, "{.status.nodePrefixes}")
				if err != nil {
					return fmt.Errorf("read %s status.nodePrefixes: %w", cl.Name, err)
				}
				if strings.TrimSpace(prefixes) == "" || prefixes == "[]" {
					return fmt.Errorf("pool %s has empty nodePrefixes: %q", cl.Name, prefixes)
				}
				return nil
			})
		})
	}
}

// TestBrokersConnectedToReflector asserts each compute cluster's netplane agent is
// connected to central's shared reflector: recent agent logs carry no
// "connection refused" lines (cross-cluster routebus up).
func TestBrokersConnectedToReflector(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	for _, cl := range computeClusters(cfg) {
		cl := cl
		t.Run(cl.Name, func(t *testing.T) {
			eventually(t, 2*time.Minute, 10*time.Second, func() error {
				out, err := kubectl(ctx, cfg, cl.Name,
					"-n", "ectobase-system", "logs",
					"-l", "app.kubernetes.io/name=netplane-agent", "--since=60s")
				if err != nil {
					return fmt.Errorf("agent logs on %s: %w\n%s", cl.Name, err, out)
				}
				if strings.Contains(out, "connection refused") {
					return fmt.Errorf("agent on %s still logging `connection refused` (reflector not connected)", cl.Name)
				}
				return nil
			})
		})
	}
}

// TestCrossClusterFabricReachability asserts the fabric carries traffic between the
// two compute clusters' node /64s: each compute node can ping every other compute
// node's fabric identity across clusters.
func TestCrossClusterFabricReachability(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) < 2 {
		t.Skip("need >=2 compute nodes across clusters")
	}
	for _, src := range nodes {
		for _, dst := range nodes {
			if src.Cluster == dst.Cluster {
				continue
			}
			src, dst := src, dst
			container := nodeContainer(cfg, src)
			t.Run(src.Cluster+"->"+dst.Cluster, func(t *testing.T) {
				eventually(t, 90*time.Second, 5*time.Second, func() error {
					out, err := nodeNetnsExec(ctx, container,
						"ping", "-6", "-c3", "-W2", dst.IdentityAddr)
					if err != nil {
						return fmt.Errorf("ping %s (%s) from %s: %w\n%s",
							dst.IdentityAddr, dst.Cluster, container, err, out)
					}
					return nil
				})
			})
		}
	}
}

// TestCrossClusterOverlayPing lives in overlay_test.go (the full encap-overlay
// endpoint-attach ping through the real NetworkInterface -> CompiledNIC -> broker
// -> agent -> dataplane pipeline).
