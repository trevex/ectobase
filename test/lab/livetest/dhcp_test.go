//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// dhcp guest identity. The overlay v4 and a distinct guest v6; the DHCPv6 responder
// reads PortMeta.guest_ipv6 (set from requested_ips) to fill the IA Address.
const (
	dhcpGuestID  = "dhcpsmoke"
	dhcpGuestIP  = "10.0.0.21"
	dhcpGuestv6  = "2001:db8:1::21"
	dhcpGuestMAC = "52:54:00:00:00:21"
)

// TestDhcpLeaseSmoke attaches a dual-stack guest on a compute node's flowplane and
// drives a real DHCPv4 DISCOVER and a DHCPv6 SOLICIT through the eBPF responder from
// inside the guest netns (AF_PACKET, --iface), asserting lease contents.
//
//	DHCPv4: yiaddr == dhcpGuestIP (MTU/DNS soft — the DS does not set --dhcp-mtu/-dns).
//	DHCPv6: ia_addr == dhcpGuestv6; ClientId echoed; "DHCPv6 OK" (PRIMARY conformance).
func TestDhcpLeaseSmoke(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("no compute nodes")
	}
	node := nodes[0]
	container := nodeContainer(cfg, node)

	// Attach a dual-stack guest (v4 + v6 in requested_ips) and bring the iface up.
	ul := attachGuest(t, ctx, cfg, node, dhcpGuestID, []string{dhcpGuestIP, dhcpGuestv6}, dhcpGuestMAC)
	require.NotEmpty(t, ul, "guest underlay /128")
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, container, "DetachInterface",
			fmt.Sprintf(`{"interface_id":%q}`, dhcpGuestID))
	})

	// Build the static tap-dhcp-probe and copy it to a ROOT path on the node.
	probe := buildStaticBin(t, "tap-dhcp-probe")
	require.NoError(t, copyToNode(ctx, container, probe, "/tap-dhcp-probe"))

	// DHCPv4: FATAL on wrong yiaddr.
	v4Cmd := fmt.Sprintf("/tap-dhcp-probe --client-only --probe dhcp --iface %s --client-mac %s --expect-ip %s --timeout 6 2>&1",
		dhcpGuestID, dhcpGuestMAC, dhcpGuestIP)
	v4Out, v4Err := nodeNetnsProbe(ctx, container, dhcpGuestID, "sh", "-c", v4Cmd)
	t.Logf("DHCPv4 probe output:\n%s", strings.TrimSpace(v4Out))
	require.NoError(t, v4Err, "DHCPv4 probe failed:\n%s", v4Out)
	require.Contains(t, v4Out, "yiaddr="+dhcpGuestIP, "DHCPv4 OFFER missing correct yiaddr")
	t.Logf("DHCPv4 lease smoke PASS: yiaddr=%s", dhcpGuestIP)

	// DHCPv6: PRIMARY CONFORMANCE. FATAL on missing ia_addr / echoed clientid / OK.
	v6Cmd := fmt.Sprintf("/tap-dhcp-probe --client-only --probe dhcpv6 --iface %s --client-mac %s --guest6 %s --timeout 6 2>&1",
		dhcpGuestID, dhcpGuestMAC, dhcpGuestv6)
	v6Out, v6Err := nodeNetnsProbe(ctx, container, dhcpGuestID, "sh", "-c", v6Cmd)
	t.Logf("DHCPv6 probe output:\n%s", strings.TrimSpace(v6Out))
	require.NoError(t, v6Err, "DHCPv6 probe FAILED; guest_ipv6 comes from AttachInterface requested_ips:\n%s", v6Out)
	require.Contains(t, v6Out, "ia_addr="+dhcpGuestv6, "DHCPv6 ADVERTISE missing ia_addr")
	require.Contains(t, v6Out, "echoed_clientid=", "DHCPv6 ADVERTISE missing echoed_clientid")
	require.Contains(t, v6Out, "DHCPv6 OK", "DHCPv6 probe did not print 'DHCPv6 OK'")
	t.Logf("DHCPv6 lease smoke PASS (PRIMARY DHCPv6 CONFORMANCE): guest6=%s", dhcpGuestv6)
}
