//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

// registryURL builds an http URL to a path on the in-fabric registry (bracketed
// IPv6 host:port) — the routable address the nodes pull the :dev app images from.
func registryURL(path string) string {
	return "http://[" + fabric.RegistryAddr + "]:" + fabric.RegistryPort + path
}

// curlStatus runs curl in a container's netns and returns the HTTP status code
// string (%{http_code}) for a GET of url.
func curlStatus(ctx context.Context, container, url string) (string, error) {
	out, err := nodeNetnsExec(ctx, container,
		"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url)
	return strings.TrimSpace(out), err
}

// TestRegistryServesAppImages asserts the in-fabric registry is reachable over the
// fabric from a compute node AND serves the pushed :dev app images: /v2/ returns 200,
// and the flowplane:dev manifest is present (200). This exercises the P6 direct-
// registry delivery path end to end — the node reaches [fd00:29::5]:5000 from its
// routable identity (the biasNodeSourceAddresses pod-aggregate addrlabel is what makes
// that source selection correct; without it the pull sources from an unroutable pod
// address and hangs), which is exactly how the pods pull their images (no ghcr.io
// mirror). A regression here resurfaces as cluster-wide ImagePullBackOff at `lab up`.
func TestRegistryServesAppImages(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("no compute nodes")
	}
	container := nodeContainer(cfg, nodes[0])

	t.Run("v2-root", func(t *testing.T) {
		eventually(t, 90*time.Second, 5*time.Second, func() error {
			code, err := curlStatus(ctx, container, registryURL("/v2/"))
			if err != nil {
				return fmt.Errorf("curl registry /v2/ from %s: %w", container, err)
			}
			if code != "200" {
				return fmt.Errorf("registry /v2/ returned %s, want 200", code)
			}
			return nil
		})
	})

	t.Run("flowplane-manifest", func(t *testing.T) {
		eventually(t, 90*time.Second, 5*time.Second, func() error {
			code, err := curlStatus(ctx, container,
				registryURL("/v2/trevex/ectobase/flowplane/manifests/dev"))
			if err != nil {
				return fmt.Errorf("curl flowplane manifest from %s: %w", container, err)
			}
			if code != "200" {
				return fmt.Errorf("flowplane:dev manifest returned %s, want 200", code)
			}
			return nil
		})
	})
}
