//go:build live

package livetest

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

// TestUnderlayInferenceOnFabric asserts a compute node's flowplane infers its underlay
// from the fabric (the dummy0 /128 identity in NodeAggr fd00:cafe::/32), not from the
// docker mgmt side-channel: the underlay /128 returned by AttachInterface must be
// inside fd00:cafe::/32. This is the explicit check behind the underlay that
// TestCrossClusterOverlayPing relies on for cross-cluster routing.
func TestUnderlayInferenceOnFabric(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("no compute nodes")
	}
	node := nodes[0]
	container := nodeContainer(cfg, node)

	ul := attachGuest(t, ctx, cfg, node, "ulinfer", []string{"10.0.0.31"}, "52:54:00:00:00:31")
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, container, "DetachInterface", `{"interface_id":"ulinfer"}`)
	})

	addr, err := netip.ParseAddr(ul)
	require.NoError(t, err, "underlay %q is not a valid IP", ul)

	nodeAggr, err := netip.ParsePrefix(fabric.NodeAggr) // fd00:cafe::/32
	require.NoError(t, err)
	require.True(t, nodeAggr.Contains(addr),
		"inferred underlay %s is NOT in the fabric node-aggregate %s (leaked to mgmt / not fabric-inferred)",
		ul, fabric.NodeAggr)
	t.Logf("underlay inference PASS: %s ∈ %s", ul, fabric.NodeAggr)
}
