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

// computeNodes returns the nodes of every non-dispatch cluster (k02, k03, …).
func computeNodes(cfg *config.Config) []config.DerivedNode {
	var out []config.DerivedNode
	for _, cl := range cfg.Fabric.Clusters {
		if cl.Name == "dispatch" {
			continue
		}
		out = append(out, cfg.Derived.Clusters[cl.Name].Nodes...)
	}
	return out
}

// nat64Address embeds a v4 literal in the NAT64 prefix, e.g.
// prefix 64:ff9b::/96 + 8.8.8.8 → 64:ff9b::8.8.8.8. The v4-mapped form is a
// valid textual IPv6 literal, so we drop the /96 and append the dotted quad.
func nat64Address(nat64Prefix, v4 string) string {
	base := strings.TrimSuffix(nat64Prefix, "/96")
	base = strings.TrimSuffix(base, "::")
	return base + "::" + v4
}

// TestNAT64Egress asserts a compute node can reach v4 internet through the fabric
// NAT64 path (tayga on the edges): ping the NAT64-embedded 8.8.8.8 over v6.
func TestNAT64Egress(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("no compute nodes")
	}
	node := nodes[0]
	container := nodeContainer(cfg, node)
	target := nat64Address(cfg.Fabric.NAT64Prefix, "8.8.8.8")

	eventually(t, 90*time.Second, 5*time.Second, func() error {
		out, err := nodeNetnsExec(ctx, container, "ping", "-6", "-c2", "-W3", target)
		if err != nil {
			return fmt.Errorf("nat64 ping %s from %s: %w\n%s", target, container, err, out)
		}
		return nil
	})
}

// TestFabricOnlyEgress asserts the fabric BGP default is present on every node
// (P3b). The two node kinds differ in how mgmt attaches:
//   - Fabric routers (edge/switch) are `network-mode: none` clab nodes — no eth0,
//     no mgmt default at all; their only default is the BGP-learned `::/0` via
//     the fabric uplinks.
//   - Compute nodes are kind-created ext-container nodes; clab never attaches
//     them to clab mgmt, but kind's own bridge gives them an eth0 with its own
//     default, which fabric-preboot demotes (high metric) so the fabric BGP
//     default is preferred rather than absent.
//
// So we only assert the positive invariant here: a fabric default via the
// uplinks (eth1/eth2) is present. RA defaults were removed in P3a, so this is
// exclusively the BGP-learned `::/0` from the edges; it may be ECMP'd across
// both uplinks, rendered as a `default proto bgp …` header line followed by
// separate `nexthop … dev ethN` lines. We don't assert a specific metric — the
// BGP-installed kernel metric is implementation-dependent (unlike the old RA
// metric 1024).
//
// TODO(B4): once live route output is known, tighten this to assert the fabric
// default is PREFERRED (lower metric) over kind's demoted eth0 bridge default.
func TestFabricOnlyEgress(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	for _, node := range allNodes(cfg) {
		node := node
		container := nodeContainer(cfg, node)
		t.Run(container, func(t *testing.T) {
			eventually(t, 90*time.Second, 5*time.Second, func() error {
				routes, err := nodeNetnsExec(ctx, container, "ip", "-6", "route", "show", "default")
				if err != nil {
					return fmt.Errorf("ip -6 route show default: %w", err)
				}
				var fabricLane bool
				for _, line := range strings.Split(strings.TrimSpace(routes), "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					// The fabric default is a `default` (or its ECMP `nexthop`)
					// line referencing one of the uplinks eth1/eth2.
					if (strings.HasPrefix(line, "default") || strings.HasPrefix(line, "nexthop")) &&
						(strings.Contains(line, "dev eth1") || strings.Contains(line, "dev eth2")) {
						fabricLane = true
					}
				}
				if !fabricLane {
					return fmt.Errorf("no fabric default via the uplinks (dev eth1/eth2):\n%s", routes)
				}
				return nil
			})
		})
	}
}
