//go:build live

package livetest

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	labtexec "github.com/trevex/ectobase/test/lab/internal/exec"
)

const (
	natGuestID  = "natsmoke"
	natGuestIP  = "10.0.0.22"
	natGuestMAC = "52:54:00:00:00:22"
	natPublicIP = "203.0.113.22"
	natPortMin  = 1024
	natPortMax  = 2047
	natExtDst   = "8.8.8.8"
)

// TestNatEgressSmoke attaches a guest, programs egress SNAT (AddNatSource) + an
// external NAT-eligible route (AddRoute external=true, nexthop=edgeNexthop) + an
// egress-allow firewall rule, then injects a raw TCP frame from the guest netns and
// proves SNAT fired by sniffing the IPIP-encapped frame on the node's fabric uplinks
// and asserting the inner TCP source port is in [natPortMin, natPortMax].
//
// The edges are FRR NAT64 routers here, not flowplane, so this asserts the SNAT
// REWRITE AT THE NODE UPLINK — not end-to-end internet (distinct from the node-level
// TestNAT64Egress, which pings a NAT64-embedded v4 via tayga).
func TestNatEgressSmoke(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("no compute nodes")
	}
	node := nodes[0]
	container := nodeContainer(cfg, node)

	ul := attachGuest(t, ctx, cfg, node, natGuestID, []string{natGuestIP}, natGuestMAC)
	require.NotEmpty(t, ul, "guest underlay /128")
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, container, "DetachInterface",
			fmt.Sprintf(`{"interface_id":%q}`, natGuestID))
	})

	natBody := fmt.Sprintf(`{"vni":%d,"source_ip":%q,"nat_ip":%q,"port_min":%d,"port_max":%d}`,
		overlayVNI, natGuestIP, natPublicIP, natPortMin, natPortMax)
	out, err := dataplaneGRPC(t, ctx, container, "AddNatSource", natBody)
	require.NoError(t, err, "AddNatSource: %s", out)

	routeBody := fmt.Sprintf(`{"vni":%d,"prefix":%q,"nexthop_underlay":%q,"external":true}`,
		overlayVNI, natExtDst+"/32", edgeNexthop)
	out, err = dataplaneGRPC(t, ctx, container, "AddRoute", routeBody)
	require.NoError(t, err, "AddRoute(external): %s", out)

	addFwEgressAllow(t, ctx, container, natGuestID)

	netprobe := buildStaticBin(t, "netprobe")
	require.NoError(t, copyToNode(ctx, container, netprobe, "/netprobe"))

	sniff := func(iface string) (string, *exec.Cmd) {
		logPath := "/snifflog-" + iface
		shCmd := fmt.Sprintf(
			"/netprobe send-sniff --count 0 --rx-iface %s --rx-outer-ipv6 --rx-inner-ip-dst %s "+
				"--rx-l4 tcp --want-outer-ipv6-nh 4 --extract inner-tcp-sport --sport-range %d-%d "+
				"--timeout 12 > %s 2>&1",
			iface, natExtDst, natPortMin, natPortMax, logPath)
		c := labtexec.SudoCmd(ctx, "docker", "exec", container, "sh", "-c", shCmd)
		_ = c.Start()
		return logPath, c
	}

	log1, c1 := sniff("eth1")
	log2, c2 := sniff("eth2")
	// Lead-in for the two backgrounded packet sniffers to attach to their interfaces before we
	// generate traffic. netprobe emits no "capturing" signal to poll, so a short fixed wait is
	// the correct primitive here (a missed head-start would lose the first packets).
	time.Sleep(1500 * time.Millisecond)

	sendArgs := []string{"/netprobe", "send", "--iface", natGuestID,
		"--eth-src", natGuestMAC, "--eth-dst", guestGWMAC,
		"--ip-src", natGuestIP, "--ip-dst", natExtDst, "--l4", "tcp",
		"--sport", "12345", "--dport", "80", "--count", "8", "--interval-ms", "200"}
	sendOut, sendErr := nodeNetnsProbe(ctx, container, natGuestID, sendArgs...)
	if sendErr != nil {
		t.Logf("netprobe send (non-fatal if SNAT still fires): %v\n%s", sendErr, sendOut)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = c1.Wait() }()
	go func() { defer wg.Done(); _ = c2.Wait() }()
	wg.Wait()

	l1, _ := nodeExec(ctx, container, "cat", log1)
	l2, _ := nodeExec(ctx, container, "cat", log2)
	t.Logf("send-sniff eth1:\n%s\nsend-sniff eth2:\n%s", strings.TrimSpace(l1), strings.TrimSpace(l2))

	if !strings.Contains(l1, "OK:") && !strings.Contains(l2, "OK:") {
		podLog, _ := kubectl(ctx, cfg, node.Cluster, "-n", "ectobase-system", "logs",
			"-l", "app=flowplane", "--field-selector", "spec.nodeName="+nodeK8sName(node), "--tail=80")
		t.Fatalf("NAT egress SNAT NOT observed on eth1/eth2 (no 'OK:' in send-sniff)\n"+
			"eth1:\n%s\neth2:\n%s\n\nflowplane pod log:\n%s", l1, l2, podLog)
	}
	t.Logf("NAT egress SNAT smoke PASS: guest %s -> %s SNAT'd into %s:[%d-%d], IPIP-encapped on the uplink",
		natGuestIP, natExtDst, natPublicIP, natPortMin, natPortMax)
}
