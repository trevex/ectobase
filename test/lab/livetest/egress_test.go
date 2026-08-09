//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

// computeNodes returns the nodes of every non-hub cluster (k02, k03, …).
func computeNodes(cfg *config.Config) []config.DerivedNode {
	var out []config.DerivedNode
	for _, cl := range cfg.Fabric.Clusters {
		if cl.Name == "hub" {
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

// TestFabricOnlyEgress asserts egress prefers the fabric, not the docker mgmt
// side-channel: a fabric default (via the uplinks eth1/eth2 — from RA `proto ra`
// or the node GoBGP's edge `::/0` `proto bgp`) sits at metric 1024, while the mgmt
// default (via MgmtV6Gateway dev eth0) is demoted (not metric 1024, or absent).
// Precisely: no default-route line matches BOTH `dev eth0` AND `metric 1024`.
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
				mgmtGw := "via " + fabric.MgmtV6Gateway
				var faLane bool
				for _, line := range strings.Split(strings.TrimSpace(routes), "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					// The mgmt default (dev eth0, via the docker mgmt gateway) must
					// NOT sit at the fabric-preferred metric 1024 — it should be
					// demoted (metric 4096) or absent, so egress prefers the fabric.
					if strings.Contains(line, "dev eth0") && strings.Contains(line, "metric 1024") {
						return fmt.Errorf("mgmt default is at fabric metric 1024 (egress leaks to docker mgmt): %q", line)
					}
					// Any mgmt default present should route via the demoted gateway.
					if strings.Contains(line, mgmtGw) && strings.Contains(line, "metric 1024") {
						return fmt.Errorf("mgmt-gateway default is at fabric metric 1024: %q", line)
					}
					// A fabric-preferred default is a metric-1024 default that is NOT via
					// the mgmt iface (eth0). It may be installed from RA (`proto ra`, a
					// single nexthop out one uplink) OR from the node's GoBGP learning the
					// edge-originated `::/0` (`proto bgp`, ECMP across both uplinks) — both
					// egress over the fabric. Which appears depends on the uplink's
					// accept_ra vs forwarding: a metric-1024 RA default only installs when
					// accept_ra=2 while forwarding is on, else the BGP default is the fabric
					// lane (non-deterministic across nodes; nothing sets accept_ra). Accept
					// either. (The `default proto bgp … metric 1024` header line carries the
					// metric; its ECMP `nexthop … dev eth1/eth2` lines are separate.)
					if strings.HasPrefix(line, "default") &&
						strings.Contains(line, "metric 1024") &&
						!strings.Contains(line, "dev eth0") {
						faLane = true
					}
				}
				if !faLane {
					return fmt.Errorf("no fabric-preferred metric-1024 default via the uplinks (proto ra or bgp):\n%s", routes)
				}
				return nil
			})
		})
	}
}
