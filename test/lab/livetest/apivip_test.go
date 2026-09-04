//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestClusterAPIReady asserts each cluster's API server is reachable and serving
// (/readyz returns ok via the collected kubeconfig) and its node reports Ready.
// (The collected kubeconfig points at the Talos anycast API VIP, which is only
// announced once GoBGP has relayed it into the fabric — so this also proves VIP +
// BGP convergence, not just apiserver health.)
func TestClusterAPIReady(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	for _, cl := range cfg.Fabric.Clusters {
		cl := cl
		t.Run(cl.Name, func(t *testing.T) {
			eventually(t, 2*time.Minute, 5*time.Second, func() error {
				out, err := kubectl(ctx, cfg, cl.Name, "get", "--raw=/readyz")
				if err != nil {
					return fmt.Errorf("get --raw=/readyz on %s (cluster API unreachable?): %w\n%s", cl.Name, err, out)
				}
				if !strings.Contains(out, "ok") {
					return fmt.Errorf("readyz did not report ok on %s: %q", cl.Name, out)
				}
				return nil
			})

			eventually(t, 2*time.Minute, 5*time.Second, func() error {
				out, err := kubectl(ctx, cfg, cl.Name, "get", "nodes", "--no-headers")
				if err != nil {
					return fmt.Errorf("get nodes on %s: %w\n%s", cl.Name, err, out)
				}
				lines := strings.Split(strings.TrimSpace(out), "\n")
				if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
					return fmt.Errorf("no nodes returned on %s", cl.Name)
				}
				for _, line := range lines {
					fields := strings.Fields(line)
					if len(fields) < 2 || fields[1] != "Ready" {
						return fmt.Errorf("node not Ready on %s: %q", cl.Name, line)
					}
				}
				return nil
			})
		})
	}
}
