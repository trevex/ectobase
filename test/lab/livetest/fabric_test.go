//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countDefaultRoutes returns, from the lines of `ip -6 route show default` in a
// node's netns, how many default routes carry the given `proto <proto>` marker.
func countRoutesWithProto(routes string, protos ...string) int {
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(routes), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		for _, p := range protos {
			if strings.Contains(line, "proto "+p) {
				n++
				break
			}
		}
	}
	return n
}

// TestBGPAndECMP asserts every node learned the default route from BOTH switches
// (one `proto ra` default via each of sw1/sw2) — i.e. the edges originate ::/0,
// the switches re-advertise it via RA, and the node installs an ECMP pair.
func TestBGPAndECMP(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	for _, node := range allNodes(cfg) {
		node := node
		container := nodeContainer(cfg, node)
		t.Run(container, func(t *testing.T) {
			eventually(t, 2*time.Minute, 5*time.Second, func() error {
				routes, err := nodeNetnsExec(ctx, container, "ip", "-6", "route", "show", "default")
				if err != nil {
					return fmt.Errorf("ip -6 route show default: %w", err)
				}
				if got := countRoutesWithProto(routes, "ra"); got < 2 {
					return fmt.Errorf("want >=2 `proto ra` default routes (ECMP via sw1+sw2), got %d:\n%s", got, routes)
				}
				return nil
			})
		})
	}
}

// TestDefaultOrigination asserts each node has at least one originated default
// route (proto ra from a switch, or proto bgp learned directly) — the edges
// originate ::/0 onto the fabric.
func TestDefaultOrigination(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	for _, node := range allNodes(cfg) {
		node := node
		container := nodeContainer(cfg, node)
		t.Run(container, func(t *testing.T) {
			eventually(t, 2*time.Minute, 5*time.Second, func() error {
				routes, err := nodeNetnsExec(ctx, container, "ip", "-6", "route", "show", "default")
				if err != nil {
					return fmt.Errorf("ip -6 route show default: %w", err)
				}
				if got := countRoutesWithProto(routes, "ra", "bgp"); got < 1 {
					return fmt.Errorf("want >=1 originated (proto ra|bgp) default route, got %d:\n%s", got, routes)
				}
				return nil
			})
		})
	}
}

// TestFabricReachesNodes asserts sw1 can reach every node's fabric identity
// address over the fabric (the node dummy0 identities are advertised + carried).
func TestFabricReachesNodes(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	sw1 := switchContainer(cfg, "sw1")
	for _, node := range allNodes(cfg) {
		node := node
		t.Run(node.IdentityAddr, func(t *testing.T) {
			eventually(t, 90*time.Second, 5*time.Second, func() error {
				out, err := nodeNetnsExec(ctx, sw1, "ping", "-6", "-c2", "-W3", node.IdentityAddr)
				if err != nil {
					return fmt.Errorf("ping %s from sw1: %w\n%s", node.IdentityAddr, err, out)
				}
				return nil
			})
			require.NotEmpty(t, node.IdentityAddr)
			assert.Contains(t, node.IdentityAddr, ":")
		})
	}
}
