// Command tap-dhcp-probe is the Go port of test/tap-dhcp-probe.py: it drives the in-XDP
// DHCP/ARP/ND responder and the encap gates over a raw tap fd, with the SAME CLI flags,
// stdout markers, and exit codes as the Python original (consumers grep the output and
// check the exit code). Pure-Go/cgo-free: gopacket for framing, insomniacslk/dhcp for the
// DHCP messages, x/sys/unix for the tap ioctl, afpacket for veth sniffing.
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() { os.Exit(run()) }

func run() int {
	clientOnly := flag.Bool("client-only", false, "drive an already-running datapath on --tap")
	probe := flag.String("probe", "dhcp", "client-only probe: dhcp|arp|nd|dhcpv6")
	egress := flag.Bool("egress", false, "IPv4 egress encap gate: inner IPv4 on --tap, capture on --peer")
	egress6 := flag.Bool("egress6", false, "IPv6 egress encap gate: inner IPv6 on --tap, capture on --peer")
	guest6 := flag.String("guest6", "2001:db8:1::1", "guest overlay IPv6 (egress6/dhcpv6)")
	dst6 := flag.String("dst6", "2001:db8:2::2", "inner IPv6 dst (egress6 probe)")
	nexthop6 := flag.String("nexthop6", "fc00:2::2", "expected outer IPv6 dst (egress6 probe)")
	guestUnderlay := flag.String("guest-underlay", "fc00:1::1", "expected outer IPv6 src (egress6 probe)")
	peer := flag.String("peer", "", "veth peer to capture redirected uplink frames on")
	tap := flag.String("tap", "", "existing tap netdev (client-only/egress mode)")
	clientMAC := flag.String("client-mac", "52:54:00:00:00:01", "client MAC")
	expectIP := flag.String("expect-ip", "10.0.0.1", "expected yiaddr / ARP psrc")
	gateway6 := flag.String("gateway6", "fe80::1", "ND gateway target (nd probe)")
	timeout := flag.Float64("timeout", 3.0, "seconds")
	lbDistribute := flag.Bool("lb-distribute", false, "LB traffic-distribution probe: send N ICMP probes toward lb-underlay, assert both backends appear in outer-dst")
	iface := flag.String("iface", "eth1", "interface for lb-distribute TX+RX")
	lbUnderlay := flag.String("lb-underlay", "", "outer IPv6 dst (LB underlay) for lb-distribute")
	be1 := flag.String("be1", "", "first backend underlay IPv6 for lb-distribute")
	be2 := flag.String("be2", "", "second backend underlay IPv6 for lb-distribute")
	vip := flag.String("vip", "", "inner IPv4 VIP dst for lb-distribute")
	count := flag.Int("count", 10, "number of probe frames to send in lb-distribute")
	flag.Parse()

	to := time.Duration(*timeout * float64(time.Second))

	switch {
	case *lbDistribute:
		if *iface == "" || *lbUnderlay == "" || *be1 == "" || *be2 == "" || *vip == "" {
			fmt.Fprintln(os.Stderr, "ERROR: --lb-distribute requires --iface --lb-underlay --be1 --be2 --vip")
			return 2
		}
		return lbDistributeProbe(*iface, *lbUnderlay, *be1, *be2, *vip, *count, to)
	case *egress:
		if *tap == "" || *peer == "" {
			fmt.Fprintln(os.Stderr, "ERROR: --egress requires --tap and --peer")
			return 2
		}
		return egressProbe(*tap, *peer, to)
	case *egress6:
		if *tap == "" || *peer == "" {
			fmt.Fprintln(os.Stderr, "ERROR: --egress6 requires --tap and --peer")
			return 2
		}
		return egress6Probe(*tap, *peer, *guest6, *dst6, *nexthop6, *guestUnderlay, to)
	case *clientOnly:
		if *tap == "" {
			fmt.Fprintln(os.Stderr, "ERROR: --client-only requires --tap")
			return 2
		}
		switch *probe {
		case "arp":
			return arpProbe(*tap, *clientMAC, *expectIP, to)
		case "nd":
			return ndProbe(*tap, *clientMAC, *gateway6, to)
		case "dhcpv6":
			return dhcpv6Probe(*tap, *clientMAC, *guest6, to)
		default:
			return clientOnlyDHCP(*tap, *clientMAC, *expectIP, to)
		}
	default:
		return selfContained()
	}
}

func selfContained() int {
	// Step 1: resolve the flowplane binary.
	bin := os.Getenv("FLOWPLANE_BIN")
	if bin == "" {
		bin = "./target/debug/flowplane"
	}
	if _, err := os.Stat(bin); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s missing — run: cargo build -p flowplane\n", bin)
		return 2
	}

	// Step 2: create two taps with held fds and bring them up.
	guestFD, err := mkTap("dhg0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: mkTap dhg0: %v\n", err)
		return 2
	}
	uplinkFD, err := mkTap("dhu0")
	if err != nil {
		guestFD.Close()
		fmt.Fprintf(os.Stderr, "ERROR: mkTap dhu0: %v\n", err)
		return 2
	}

	// Read MACs from sysfs.
	readMAC := func(name string) (string, error) {
		b, err := os.ReadFile("/sys/class/net/" + name + "/address")
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	gmac, err := readMAC("dhg0")
	if err != nil {
		guestFD.Close()
		uplinkFD.Close()
		fmt.Fprintf(os.Stderr, "ERROR: read dhg0 MAC: %v\n", err)
		return 2
	}
	umac, err := readMAC("dhu0")
	if err != nil {
		guestFD.Close()
		uplinkFD.Close()
		fmt.Fprintf(os.Stderr, "ERROR: read dhu0 MAC: %v\n", err)
		return 2
	}

	// Step 3: start flowplane bringup in the background.
	logF, err := os.Create("/tmp/dhcp-probe-bringup.log")
	if err != nil {
		guestFD.Close()
		uplinkFD.Close()
		fmt.Fprintf(os.Stderr, "ERROR: open bringup log: %v\n", err)
		return 2
	}
	bringupCmd := exec.Command(bin, "bringup",
		"--uplink", "dhu0",
		"--local-underlay", "fd00::1",
		"--gateway", "10.0.0.1",
		"--gateway-mac", umac,
		"--guest", "dhg0=10.0.0.50="+gmac+"=fd00:a::50=0",
		"--dhcp-mtu", "1337",
		"--dhcp-dns", "8.8.4.4",
		"--dhcp-dns", "8.8.8.8",
	)
	bringupCmd.Stdout = logF
	bringupCmd.Stderr = logF
	if err := bringupCmd.Start(); err != nil {
		logF.Close()
		guestFD.Close()
		uplinkFD.Close()
		fmt.Fprintf(os.Stderr, "ERROR: start bringup: %v\n", err)
		return 2
	}
	time.Sleep(2 * time.Second)

	// Cleanup: terminate bringup, delete taps, close fds. Always runs.
	cleanup := func() {
		if bringupCmd.Process != nil {
			_ = bringupCmd.Process.Signal(syscall.SIGTERM)
			done := make(chan error, 1)
			go func() { done <- bringupCmd.Wait() }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = bringupCmd.Process.Kill()
			}
		}
		logF.Close()
		_ = exec.Command("ip", "link", "del", "dhg0").Run()
		_ = exec.Command("ip", "link", "del", "dhu0").Run()
		guestFD.Close()
		uplinkFD.Close()
	}

	// Step 4: determine attach mode.
	modeOut, _ := exec.Command("ip", "-d", "link", "show", "dhg0").CombinedOutput()
	modeStr := string(modeOut)
	var mode string
	switch {
	case strings.Contains(modeStr, "xdpgeneric"):
		mode = "skb/generic"
	case strings.Contains(modeStr, "xdp"):
		mode = "native/driver"
	default:
		mode = "NONE"
	}
	fmt.Printf("guest_tx attach mode on dhg0: %s\n", mode)

	// Step 5: build and write a DISCOVER.
	clientMAC, err := net.ParseMAC("02:aa:bb:cc:dd:ee")
	if err != nil {
		cleanup()
		fmt.Fprintf(os.Stderr, "ERROR: parse client MAC: %v\n", err)
		return 2
	}
	discFrame, err := buildDHCPDiscover(clientMAC, 0x1234)
	if err != nil {
		cleanup()
		fmt.Fprintf(os.Stderr, "ERROR: buildDHCPDiscover: %v\n", err)
		return 2
	}
	if _, err := guestFD.Write(discFrame); err != nil {
		cleanup()
		fmt.Fprintf(os.Stderr, "ERROR: write DISCOVER: %v\n", err)
		return 2
	}
	fmt.Printf("sent DHCP DISCOVER (%d bytes) to the dhg0 fd\n", len(discFrame))

	// Step 6: read the dhg0 fd for up to 3s for an OFFER (msgType==2).
	var (
		gotYiaddr net.IP
		gotMTU    uint16
		gotDNS    []net.IP
		offerLen  int
	)
	found := readFrames(guestFD, 3*time.Second, func(b []byte) bool {
		mt, yi, mtu, dns, ok := parseDHCPReply(b)
		if !ok || mt != 2 {
			return false
		}
		gotYiaddr = yi
		gotMTU = mtu
		gotDNS = dns
		offerLen = len(b)
		return true
	})

	// Step 7: cleanup (always).
	cleanup()

	// Step 8: print result.
	if !found {
		fmt.Printf("RESULT: NO OFFER received in %s mode\n", mode)
		fmt.Println("  -> native tap CANNOT grow the frame (bpf_xdp_adjust_tail fails) — a real")
		fmt.Println("     production concern: the responder needs a no-grow redesign or SKB in prod.")
		return 1
	}

	fmt.Printf("RESULT: OFFER received in %s mode\n", mode)
	fmt.Printf("  reply %d bytes (grown from the %d-byte DISCOVER)\n", offerLen, len(discFrame))
	fmt.Printf("  yiaddr=%s  interface-mtu=%d  dns=%v\n", gotYiaddr, gotMTU, gotDNS)

	ok := gotYiaddr.String() == "10.0.0.50" && gotMTU == 1337 && offerLen > len(discFrame)
	if ok && mode == "native/driver" {
		fmt.Println("  -> PROVEN: real taps support native-mode adjust_tail growth. The SKB workaround")
		fmt.Println("     is a pure veth-harness artifact; production runs DHCP on the native fast path.")
		return 0
	}
	fmt.Println("  -> OFFER returned but check the mode/values above.")
	if ok {
		return 0
	}
	return 1
}

// egressProbe injects one inner IPv4 ICMP frame on `tap`, sniffs `peer` for an
// encapsulated outer IPv6 frame (NextHeader==4, IPIP), and reports the result.
func egressProbe(tap, peer string, to time.Duration) int {
	f, err := openTapQueue(tap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: openTapQueue %s: %v\n", tap, err)
		return 2
	}
	defer f.Close()

	inner, err := buildInnerIPv4ICMP()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: buildInnerIPv4ICMP: %v\n", err)
		return 2
	}

	wantSrc := net.ParseIP("fc00:1::1")
	wantDst := net.ParseIP("fc00:2::2")

	matched := false
	want := func(pkt gopacket.Packet) bool {
		var v6s []*layers.IPv6
		for _, l := range pkt.Layers() {
			if v, ok := l.(*layers.IPv6); ok {
				v6s = append(v6s, v)
			}
		}
		if len(v6s) == 0 {
			return false
		}
		outer := v6s[0]
		if outer.NextHeader == layers.IPProtocolIPv4 &&
			outer.SrcIP.Equal(wantSrc) &&
			outer.DstIP.Equal(wantDst) {
			innerIP, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if innerIP != nil &&
				innerIP.SrcIP.Equal(net.IPv4(10, 0, 0, 1)) &&
				innerIP.DstIP.Equal(net.IPv4(10, 0, 0, 2)) {
				matched = true
				return true
			}
		}
		return false
	}

	inject := func() error {
		if _, err := f.Write(inner); err != nil {
			return fmt.Errorf("write inner: %w", err)
		}
		fmt.Printf("sent inner IPv4 ICMP (%d bytes) 10.0.0.1->10.0.0.2 on %s\n", len(inner), tap)
		return nil
	}

	pkts, err := sniffIPv6(peer, to, inject, want)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: sniffIPv6 on %s: %v\n", peer, err)
		return 1
	}

	if len(pkts) == 0 {
		fmt.Printf("RESULT: NO IPv6 frame captured on %s within %.0fs\n", peer, to.Seconds())
		return 1
	}

	for _, p := range pkts {
		fmt.Printf("captured %d bytes on %s: %s\n", len(p.Data()), peer, hex.EncodeToString(p.Data()))
		var v6s []*layers.IPv6
		for _, l := range p.Layers() {
			if v, ok := l.(*layers.IPv6); ok {
				v6s = append(v6s, v)
			}
		}
		if len(v6s) > 0 {
			outer := v6s[0]
			innerIPLayer := p.Layer(layers.LayerTypeIPv4)
			innerIP, _ := innerIPLayer.(*layers.IPv4)
			var innerSrc, innerDst string
			if innerIP != nil {
				innerSrc = innerIP.SrcIP.String()
				innerDst = innerIP.DstIP.String()
			} else {
				innerSrc = "?"
				innerDst = "?"
			}
			fmt.Printf("  outer IPv6: nh=%d src=%s dst=%s (want nh=4 src=fc00:1::1 dst=fc00:2::2)\n",
				outer.NextHeader, outer.SrcIP, outer.DstIP)
			fmt.Printf("  inner IP: src=%s dst=%s (want 10.0.0.1->10.0.0.2)\n", innerSrc, innerDst)
		}
	}

	if matched {
		fmt.Println("ENCAP OK")
		return 0
	}
	fmt.Printf("RESULT: captured frame(s) not correctly encapsulated (see hex above)\n")
	return 1
}

// egress6Probe injects one inner IPv6 ICMPv6 frame on `tap`, sniffs `peer` for an
// encapsulated outer IPv6 frame (NextHeader==41, IPv6-in-IPv6), and reports the result.
func egress6Probe(tap, peer, g6, d6, nh6, gul string, to time.Duration) int {
	f, err := openTapQueue(tap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: openTapQueue %s: %v\n", tap, err)
		return 2
	}
	defer f.Close()

	inner, err := buildInnerIPv6ICMP6(g6, d6)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: buildInnerIPv6ICMP6: %v\n", err)
		return 2
	}

	wantSrc := net.ParseIP(gul)
	wantDst := net.ParseIP(nh6)
	wantInnerDst := net.ParseIP(d6)

	if wantSrc == nil || wantDst == nil || wantInnerDst == nil {
		fmt.Fprintf(os.Stderr, "ERROR: invalid IP arg (guest-underlay=%s nexthop6=%s dst6=%s)\n", gul, nh6, d6)
		return 2
	}

	matched := false
	want := func(pkt gopacket.Packet) bool {
		var v6s []*layers.IPv6
		for _, l := range pkt.Layers() {
			if v, ok := l.(*layers.IPv6); ok {
				v6s = append(v6s, v)
			}
		}
		if len(v6s) < 2 {
			return false
		}
		outer := v6s[0]
		innerV6 := v6s[1]
		if outer.NextHeader == layers.IPProtocolIPv6 &&
			outer.SrcIP.Equal(wantSrc) &&
			outer.DstIP.Equal(wantDst) &&
			innerV6.DstIP.Equal(wantInnerDst) {
			matched = true
			return true
		}
		return false
	}

	inject := func() error {
		if _, err := f.Write(inner); err != nil {
			return fmt.Errorf("write inner: %w", err)
		}
		fmt.Printf("sent inner IPv6 ICMPv6 (%d bytes) %s->%s on %s\n", len(inner), g6, d6, tap)
		return nil
	}

	pkts, err := sniffIPv6(peer, to, inject, want)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: sniffIPv6 on %s: %v\n", peer, err)
		return 1
	}

	if len(pkts) == 0 {
		fmt.Printf("RESULT: NO IPv6 frame captured on %s within %.0fs\n", peer, to.Seconds())
		return 1
	}

	for _, p := range pkts {
		fmt.Printf("captured %d bytes on %s: %s\n", len(p.Data()), peer, hex.EncodeToString(p.Data()))
		var v6s []*layers.IPv6
		for _, l := range p.Layers() {
			if v, ok := l.(*layers.IPv6); ok {
				v6s = append(v6s, v)
			}
		}
		if len(v6s) > 0 {
			outer := v6s[0]
			var innerDst string
			if len(v6s) > 1 {
				innerDst = v6s[1].DstIP.String()
			} else {
				innerDst = "?"
			}
			fmt.Printf("  outer IPv6: nh=%d src=%s dst=%s (want nh=41 src=%s dst=%s)\n",
				outer.NextHeader, outer.SrcIP, outer.DstIP, gul, nh6)
			fmt.Printf("  inner IPv6 dst=%s (want %s)\n", innerDst, d6)
		}
	}

	if matched {
		fmt.Println("ENCAP6 OK")
		return 0
	}
	fmt.Printf("RESULT: captured frame(s) not correctly v6-encapsulated (see hex above)\n")
	return 1
}

func clientOnlyDHCP(tap, mac, expectIP string, to time.Duration) int {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: invalid MAC %q: %v\n", mac, err)
		return 2
	}
	f, err := openTapQueue(tap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: openTapQueue %s: %v\n", tap, err)
		return 2
	}
	defer f.Close()

	frame, err := buildDHCPDiscover(hw, 0x1234)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: buildDHCPDiscover: %v\n", err)
		return 2
	}
	if _, err := f.Write(frame); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: write discover: %v\n", err)
		return 2
	}
	fmt.Printf("sent DHCP DISCOVER (%d bytes) from %s to tap %s\n", len(frame), mac, tap)

	var (
		gotYiaddr net.IP
		gotMTU    uint16
		gotDNS    []net.IP
		gotLen    int
	)
	found := readFrames(f, to, func(b []byte) bool {
		mt, yi, mtu, dns, ok := parseDHCPReply(b)
		if !ok || mt != 2 {
			return false
		}
		gotYiaddr = yi
		gotMTU = mtu
		gotDNS = dns
		gotLen = len(b)
		return true
	})
	if !found {
		fmt.Printf("RESULT: NO OFFER received on %s within %.0fs\n", tap, to.Seconds())
		return 1
	}
	fmt.Printf("RESULT: OFFER received — yiaddr=%s dns=%v mtu=%d (%d bytes)\n",
		gotYiaddr, gotDNS, gotMTU, gotLen)
	if gotYiaddr.String() != expectIP {
		fmt.Printf("  but expected yiaddr %s, got %s\n", expectIP, gotYiaddr)
		return 1
	}
	return 0
}

func arpProbe(tap, mac, expectIP string, to time.Duration) int {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: invalid MAC %q: %v\n", mac, err)
		return 2
	}
	f, err := openTapQueue(tap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: openTapQueue %s: %v\n", tap, err)
		return 2
	}
	defer f.Close()

	frame, err := buildARPRequest(hw, net.IPv4(10, 0, 0, 2), net.ParseIP(expectIP))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: buildARPRequest: %v\n", err)
		return 2
	}
	if _, err := f.Write(frame); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: write arp: %v\n", err)
		return 2
	}
	fmt.Printf("sent ARP who-has %s (%d bytes) from %s on %s\n", expectIP, len(frame), mac, tap)

	var (
		gotOp   uint16
		gotPsrc net.IP
		gotHW   net.HardwareAddr
	)
	found := readFrames(f, to, func(b []byte) bool {
		op, psrc, hwsrc, ok := parseARP(b)
		if !ok || op != 2 {
			return false
		}
		gotOp = op
		gotPsrc = psrc
		gotHW = hwsrc
		return true
	})
	if !found {
		fmt.Printf("RESULT: NO ARP reply on %s within %.0fs\n", tap, to.Seconds())
		return 1
	}
	fmt.Printf("got ARP reply: op=%d psrc=%s hwsrc=%s\n", gotOp, gotPsrc, gotHW)
	if gotPsrc.String() != expectIP || gotHW.String() != mac {
		fmt.Printf("  but expected psrc=%s hwsrc=%s, got psrc=%s hwsrc=%s\n",
			expectIP, mac, gotPsrc, gotHW)
		return 1
	}
	fmt.Println("ARP reply OK")
	return 0
}

func ndProbe(tap, mac, gw6 string, to time.Duration) int {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: invalid MAC %q: %v\n", mac, err)
		return 2
	}
	f, err := openTapQueue(tap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: openTapQueue %s: %v\n", tap, err)
		return 2
	}
	defer f.Close()

	frame, err := buildNS(hw, net.ParseIP(gw6))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: buildNS: %v\n", err)
		return 2
	}
	if _, err := f.Write(frame); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: write ns: %v\n", err)
		return 2
	}
	fmt.Printf("sent ICMPv6 NS for %s (%d bytes) from %s on %s\n", gw6, len(frame), mac, tap)

	var (
		gotTgt   net.IP
		gotDstLL net.HardwareAddr
	)
	found := readFrames(f, to, func(b []byte) bool {
		tgt, dstLL, ok := parseNA(b)
		if !ok {
			return false
		}
		gotTgt = tgt
		gotDstLL = dstLL
		return true
	})
	if !found {
		fmt.Printf("RESULT: NO ICMPv6 NA on %s within %.0fs\n", tap, to.Seconds())
		return 1
	}
	fmt.Printf("got ICMPv6 NA: tgt=%s dst-lladdr=%s\n", gotTgt, gotDstLL)
	if gotDstLL.String() != mac {
		fmt.Printf("  but expected dst-lladdr %s, got %s\n", mac, gotDstLL)
		return 1
	}
	fmt.Println("ND NA OK")
	return 0
}

// lbDistributeProbe sends count IPv6-encapsulated ICMP probe frames toward lbUnderlay (varying
// the outer IPv6 src to vary the Maglev hash), sniffs re-encapped frames on the same iface, and
// asserts that BOTH backend underlays (be1, be2) appear as captured outer-dst.
// Prints DISTRIBUTION_OK or DISTRIBUTION_FAIL and returns 0/1 accordingly.
func lbDistributeProbe(iface, lbUnderlay, be1, be2, vip string, count int, to time.Duration) int {
	be1IP, be2IP := net.ParseIP(be1), net.ParseIP(be2)
	seen := map[string]bool{}
	inject := func() error {
		for i := range count {
			frame, err := buildLbProbeFrame(i, lbUnderlay, vip)
			if err != nil {
				return err
			}
			if err := injectAF(iface, frame); err != nil {
				return err
			}
		}
		return nil
	}
	want := func(p gopacket.Packet) bool {
		ip6, _ := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if ip6 == nil {
			return false
		}
		if ip6.DstIP.Equal(be1IP) || ip6.DstIP.Equal(be2IP) {
			seen[ip6.DstIP.String()] = true
		}
		return seen[be1IP.String()] && seen[be2IP.String()]
	}
	if _, err := sniffIPv6(iface, to, inject, want); err != nil {
		fmt.Fprintln(os.Stderr, "sniff error:", err)
		return 2
	}
	if seen[be1IP.String()] && seen[be2IP.String()] {
		fmt.Printf("DISTRIBUTION_OK: both backends seen in captured outer-dst: %v\n", keysOf(seen))
		return 0
	}
	fmt.Printf("DISTRIBUTION_FAIL: backends not all seen; seen: %v (want %s,%s)\n", keysOf(seen), be1, be2)
	return 1
}

// keysOf returns the sorted keys of a map[string]bool.
func keysOf(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func dhcpv6Probe(tap, mac, expectIP string, to time.Duration) int {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: invalid MAC %q: %v\n", mac, err)
		return 2
	}
	f, err := openTapQueue(tap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: openTapQueue %s: %v\n", tap, err)
		return 2
	}
	defer f.Close()

	sol, duid, err := buildDHCPv6Solicit(hw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: buildDHCPv6Solicit: %v\n", err)
		return 2
	}
	if _, err := f.Write(sol); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: write solicit: %v\n", err)
		return 2
	}
	fmt.Printf("sent DHCPv6 SOLICIT (%d bytes) from %s on %s, DUID=%s\n",
		len(sol), mac, tap, hex.EncodeToString(duid))

	wantDUID := duid
	if len(wantDUID) > 10 {
		wantDUID = wantDUID[:10]
	}

	var (
		gotIA     net.IP
		gotEchoed []byte
	)
	found := readFrames(f, to, func(b []byte) bool {
		ia, echoed, ok := parseDHCPv6Reply(b)
		if !ok {
			return false
		}
		gotIA = ia
		gotEchoed = echoed
		return true
	})
	if !found {
		fmt.Printf("RESULT: NO DHCP6 ADVERTISE/REPLY on %s within %.0fs\n", tap, to.Seconds())
		return 1
	}
	fmt.Printf("got DHCP6 reply: ia_addr=%s echoed_clientid=%s\n",
		gotIA, hex.EncodeToString(gotEchoed))

	wantIP := net.ParseIP(expectIP)
	if !wantIP.Equal(gotIA) {
		fmt.Printf("  but expected IA addr %s, got %s\n", expectIP, gotIA)
		return 1
	}
	if len(gotEchoed) == 0 {
		fmt.Println("  but ClientId was not echoed")
		return 1
	}
	if !bytes.Equal(gotEchoed, wantDUID) {
		fmt.Printf("  but echoed ClientId mismatch: %s vs expected (sent DUID capped to 10B) %s\n",
			hex.EncodeToString(gotEchoed), hex.EncodeToString(wantDUID))
		return 1
	}
	fmt.Println("DHCPv6 OK")
	return 0
}
