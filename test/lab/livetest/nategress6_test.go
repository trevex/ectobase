//go:build live

package livetest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	labtexec "github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

const (
	nat6GuestID  = "nat6smoke"
	nat6GuestIP  = "fd00:100::22" // overlay ULA guest v6 (VNI 100)
	nat6GuestMAC = "52:54:00:00:00:26"
	nat6PublicIP = "2001:db8:2b::a" // a hand-picked pick from PublicV6 (2001:db8:2b::/64)
	nat6PortMin  = 1024
	nat6PortMax  = 2047
	nat6ExtDst   = "2001:4860:4860::8888" // external v6 dst (route external=true); not reached, just sniffed
)

// TestNatEgressSmoke6 is the NAT66 sibling of TestNatEgressSmoke: it attaches a v6 overlay guest,
// programs egress SNAT66 (AddNatSource with v6 source_ip + v6 nat_ip) + an external v6 route +
// v6 egress-allow firewall, injects a raw inner-v6 TCP frame from the guest netns, and proves SNAT66
// fired by sniffing the encapped frame on the node's fabric uplinks and asserting the INNER IPv6
// SOURCE was rewritten to the nat_ip (2001:db8:2b::a) — the defining NAT66 behaviour.
//
// snat_egress6 rewrites the INNER v6 packet (src IPv6 -> nat_ipv6, src L4 port -> pooled port) in
// forward_decision_v6 BEFORE the Geneve outer is built, so the on-wire frame is
// Eth·IPv6·UDP(6081)·Geneve·innerEth·innerIPv6·TCP. We sniff the outer Geneve frame and extract the
// INNER IPv6 src (the last IPv6 layer under Geneve) — reaching it at all requires the Geneve decode,
// so an inner match implicitly proves the encap too. This asserts the SNAT66 REWRITE AT THE NODE
// UPLINK (not end-to-end internet — the edges are FRR NAT64 routers here, not flowplane NAT66).
func TestNatEgressSmoke6(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("no compute nodes")
	}
	node := nodes[0]
	container := nodeContainer(cfg, node)

	ul := attachGuest(t, ctx, cfg, node, nat6GuestID, []string{nat6GuestIP}, nat6GuestMAC)
	require.NotEmpty(t, ul, "guest underlay /128")
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, container, "DetachInterface",
			fmt.Sprintf(`{"interface_id":%q}`, nat6GuestID))
	})

	natBody := fmt.Sprintf(`{"vni":%d,"source_ip":%q,"nat_ip":%q,"port_min":%d,"port_max":%d}`,
		overlayVNI, nat6GuestIP, nat6PublicIP, nat6PortMin, nat6PortMax)
	out, err := dataplaneGRPC(t, ctx, container, "AddNatSource", natBody)
	require.NoError(t, err, "AddNatSource(v6): %s", out)

	routeBody := fmt.Sprintf(`{"vni":%d,"prefix":%q,"nexthop_underlay":%q,"external":true}`,
		overlayVNI, nat6ExtDst+"/128", edgeNexthop)
	out, err = dataplaneGRPC(t, ctx, container, "AddRoute", routeBody)
	require.NoError(t, err, "AddRoute(external v6): %s", out)

	// v6 egress-allow (deny-by-default busting): the empty-CIDR proto-0 rule addFwEgressAllow
	// programs is v4; a v6 flow needs its own ::/0 egress allow or forward_decision_v6 drops it.
	fwBody := fmt.Sprintf(
		`{"interface_id":%q,"rule_id":"eg6","src_cidr":"::/0","dst_cidr":"::/0","proto":0,"allow":true,"egress":true}`,
		nat6GuestID)
	out, err = dataplaneGRPC(t, ctx, container, "AddFwRule", fwBody)
	require.NoError(t, err, "AddFwRule egress-allow(v6): %s", out)

	netprobe := buildStaticBin(t, "netprobe")
	pid, err := dockerPID(ctx, container)
	require.NoError(t, err)

	// Sniff each node uplink from the HOST via nsenter -n into the node net ns; --net keeps the host
	// mount ns so the shell redirect writes the capture log to a HOST temp path. Assert the inner v6
	// src == nat_ip (SNAT66 proof), filtered to this flow by the inner v6 dst.
	sniff := func(iface string) (string, *exec.Cmd) {
		logPath := filepath.Join(t.TempDir(), "snifflog6-"+iface)
		shCmd := fmt.Sprintf(
			"%s send-sniff --count 0 --rx-iface %s --rx-outer-ipv6 --rx-inner-ip6-dst %s "+
				"--rx-l4 tcp --extract inner-ip6-src --want-inner-ip6-src %s --timeout 12 > %s 2>&1",
			netprobe, iface, nat6ExtDst, nat6PublicIP, logPath)
		c := labtexec.SudoCmd(ctx, "nsenter", "-t", pid, "-n", "sh", "-c", shCmd)
		_ = c.Start()
		return logPath, c
	}

	log1, c1 := sniff("eth1")
	log2, c2 := sniff("eth2")
	// Lead-in for the backgrounded sniffers to attach before we generate traffic (no "capturing"
	// signal to poll on — a short fixed wait is the correct primitive; a missed head-start loses
	// the first packets).
	time.Sleep(1500 * time.Millisecond)

	sendArgs := []string{netprobe, "send", "--iface", nat6GuestID, "--ipv6",
		"--eth-src", nat6GuestMAC, "--eth-dst", guestGWMAC,
		"--ip-src", nat6GuestIP, "--ip-dst", nat6ExtDst, "--l4", "tcp",
		"--sport", "12345", "--dport", "80", "--count", "8", "--interval-ms", "200"}
	sendOut, sendErr := nodeNetnsProbe(ctx, container, nat6GuestID, sendArgs...)
	if sendErr != nil {
		t.Logf("netprobe send (non-fatal if SNAT still fires): %v\n%s", sendErr, sendOut)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = c1.Wait() }()
	go func() { defer wg.Done(); _ = c2.Wait() }()
	wg.Wait()

	l1b, _ := os.ReadFile(log1)
	l2b, _ := os.ReadFile(log2)
	l1, l2 := string(l1b), string(l2b)
	t.Logf("send-sniff eth1:\n%s\nsend-sniff eth2:\n%s", strings.TrimSpace(l1), strings.TrimSpace(l2))

	if !strings.Contains(l1, "OK:") && !strings.Contains(l2, "OK:") {
		podLog, _ := kubectl(ctx, cfg, node.Cluster, "-n", "ectobase-system", "logs",
			"-l", "app=flowplane", "--field-selector", "spec.nodeName="+nodeK8sName(node), "--tail=80")
		t.Fatalf("NAT66 egress SNAT NOT observed on eth1/eth2 (no 'OK:' in send-sniff)\n"+
			"eth1:\n%s\neth2:\n%s\n\nflowplane pod log:\n%s", l1, l2, podLog)
	}
	t.Logf("NAT66 egress SNAT smoke PASS: guest %s -> %s SNAT'd into src=%s, Geneve-encapped on the uplink",
		nat6GuestIP, nat6ExtDst, nat6PublicIP)
}

const (
	nat6RetGuestID  = "nat6ret"
	nat6RetGuestIP  = "fd00:100::26"
	nat6RetGuestMAC = "52:54:00:00:00:27"
	nat6RetNatIP    = "2001:db8:2b::b" // distinct from the smoke test's ::a
	nat6RetPort     = 20000            // single-port pool [P,P+1) => snat_egress6 deterministically picks P
	nat6RetGSport   = 12345            // guest's original L4 sport; the reverse-DNAT restores it as the reply dport
	nat6RetExtDst   = "2001:4860:4860::8844"
)

// TestNatEgressReturn6 closes the NAT66 loop end-to-end: it proves the RETURN path
// (external reply -> edge neighbor-nat relay -> node reverse-DNAT -> guest), the half the
// egress smoke test does not exercise.
//
// Flow: attach a v6 guest; program egress SNAT66 with a SINGLE-port pool [P,P+1) so the
// allocated nat port is deterministically P (no need to sniff-and-learn it); program the
// NAT66 neighbor-nat on BOTH edges (nat_ip -> the guest's node underlay, so a reply landing
// on either anycast edge relays to the node). Then: (1) the guest egresses one flow
// (guest_ip:GSPORT -> extdst:80), which snat_egress6 SNATs to nat_ip:P and pins the
// peer-independent reverse conntrack (vni,0,nat_ip,0,P)->guest_ip:GSPORT; (2) the WAN sends
// TCP to [nat_ip]:P; it BGP-routes to an edge, whose process_wan_rx neighbor_nat_lookup_any6
// relays it (Geneve) to the node; (3) the node's process_uplink_v6 nat_return_dnat6 reverse-
// DNATs dst nat_ip:P -> guest_ip:GSPORT and delivers to the guest tap. We sniff INSIDE the
// guest netns and assert an inbound frame with dst=guest_ip arrives — proving the whole
// return chain. Requires the edge sidecars to run the NAT66 build (NEIGHBOR_NAT6 relay).
func TestNatEgressReturn6(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("no compute nodes")
	}
	node := nodes[0]
	container := nodeContainer(cfg, node)
	edge := clab.ContainerName(cfg.Name, "flowplane-edge1")
	edge2 := clab.ContainerName(cfg.Name, "flowplane-edge2")
	wan := clab.ContainerName(cfg.Name, "wan")
	edgeUnderlay := fabric.EdgeLoopback + "::e1"

	ul := attachGuest(t, ctx, cfg, node, nat6RetGuestID, []string{nat6RetGuestIP}, nat6RetGuestMAC)
	require.NotEmpty(t, ul, "guest underlay /128")
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, container, "DetachInterface",
			fmt.Sprintf(`{"interface_id":%q}`, nat6RetGuestID))
	})

	// Single-port pool => nat_port is deterministically nat6RetPort.
	mustGRPC(t, ctx, container, "AddNatSource", fmt.Sprintf(
		`{"vni":%d,"source_ip":%q,"nat_ip":%q,"port_min":%d,"port_max":%d}`,
		overlayVNI, nat6RetGuestIP, nat6RetNatIP, nat6RetPort, nat6RetPort+1))
	mustGRPC(t, ctx, container, "AddRoute", fmt.Sprintf(
		`{"vni":%d,"prefix":%q,"nexthop_underlay":%q,"external":true}`,
		overlayVNI, nat6RetExtDst+"/128", edgeUnderlay))
	mustGRPC(t, ctx, container, "AddFwRule", fmt.Sprintf(
		`{"interface_id":%q,"rule_id":"eg6","src_cidr":"::/0","dst_cidr":"::/0","proto":0,"allow":true,"egress":true}`,
		nat6RetGuestID))

	// NAT66 neighbor-nat on BOTH edges: a reply to nat_ip (either anycast edge) relays to the node.
	for _, e := range []string{edge, edge2} {
		ec := e
		mustGRPC(t, ctx, ec, "AddNeighborNat", fmt.Sprintf(
			`{"vni":%d,"nat_ip":%q,"port_min":%d,"port_max":%d,"owner_underlay":%q}`,
			overlayVNI, nat6RetNatIP, nat6RetPort, nat6RetPort+1, ul))
		t.Cleanup(func() {
			_, _ = dataplaneGRPC(t, ctx, ec, "WithdrawNeighborNat", fmt.Sprintf(
				`{"vni":%d,"nat_ip":%q,"port_min":%d,"port_max":%d}`,
				overlayVNI, nat6RetNatIP, nat6RetPort, nat6RetPort+1))
		})
	}

	netprobe := buildStaticBin(t, "netprobe")

	// 1. Egress one flow to create the conntrack (fwd + peer-independent reverse entry).
	egress := []string{netprobe, "send", "--iface", nat6RetGuestID, "--ipv6",
		"--eth-src", nat6RetGuestMAC, "--eth-dst", guestGWMAC,
		"--ip-src", nat6RetGuestIP, "--ip-dst", nat6RetExtDst, "--l4", "tcp",
		"--sport", fmt.Sprintf("%d", nat6RetGSport), "--dport", "80", "--count", "4", "--interval-ms", "150"}
	if out, err := nodeNetnsProbe(ctx, container, nat6RetGuestID, egress...); err != nil {
		t.Logf("egress send (non-fatal): %v\n%s", err, out)
	}

	// 2. Sniff INSIDE the guest netns for the reverse-DNAT'd inbound frame (dst=guest_ip).
	pid, err := dockerPID(ctx, container)
	require.NoError(t, err)
	guestNS := fmt.Sprintf("/proc/%s/root/run/netns/%s", pid, nat6RetGuestID)
	logPath := filepath.Join(t.TempDir(), "guest-return-sniff")
	shCmd := fmt.Sprintf(
		"%s send-sniff --count 0 --rx-iface %s --rx-inner-ip6-dst %s --rx-l4 tcp --timeout 15 > %s 2>&1",
		netprobe, nat6RetGuestID, nat6RetGuestIP, logPath)
	sniff := labtexec.SudoCmd(ctx, "nsenter", "--net="+guestNS, "sh", "-c", shCmd)
	require.NoError(t, sniff.Start())
	time.Sleep(1500 * time.Millisecond) // sniffer attach lead-in

	// 3. From the WAN, drive TCP to [nat_ip]:P repeatedly (each SYN triggers a return). A failed
	//    connect still emits the SYN, which is all the return path needs.
	done := make(chan struct{})
	go func() {
		defer close(done)
		url := fmt.Sprintf("http://[%s]:%d/", nat6RetNatIP, nat6RetPort)
		for i := 0; i < 10; i++ {
			_, _ = labtexec.SudoOutput(ctx, "docker", "run", "--rm", "--network", "container:"+wan,
				"curlimages/curl:latest", "-6", "-s", "--max-time", "2", url)
			time.Sleep(300 * time.Millisecond)
		}
	}()

	_ = sniff.Wait()
	<-done

	lb, _ := os.ReadFile(logPath)
	l := string(lb)
	t.Logf("guest-netns return sniff:\n%s", strings.TrimSpace(l))
	if !strings.Contains(l, "OK:") {
		podLog, _ := kubectl(ctx, cfg, node.Cluster, "-n", "ectobase-system", "logs",
			"-l", "app=flowplane", "--field-selector", "spec.nodeName="+nodeK8sName(node), "--tail=60")
		t.Fatalf("NAT66 RETURN not delivered to the guest netns (no 'OK:' in the sniff)\n%s\n\nflowplane pod log:\n%s", l, podLog)
	}
	t.Logf("NAT66 RETURN PASS: reply to [%s]:%d relayed by an edge + reverse-DNAT'd to the guest %s",
		nat6RetNatIP, nat6RetPort, nat6RetGuestIP)
}
