package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trevex/ectobase/test/e2e/internal/netpkt"
)

// sendSniff implements the "send-sniff" subcommand. It optionally injects frames on
// --tx-iface while sniffing --rx-iface, then applies RX filters and assertions to
// the collected candidates.
//
// Cross-netns usage (tx and rx are in different network namespaces):
//
//	Pass --count 0 (sniff-only) to skip TX entirely; background this in the RX netns
//	while a separate "netprobe send" runs in the TX netns.
//
//	Pass --no-rx (tx-only) to skip sniffing; use this when you just want the TX side
//	without any assertion (equivalent to "send" but with the same flag set).
//
// Encap support (--encap ipip):
//
//	Builds an outer IPv6 / inner IPv4 IP-in-IPv6 frame. Outer addrs are taken from
//	--outer-ipv6-src and --outer-ipv6-dst; inner addrs from --ip-src/--ip-dst.
//	--eth-src/--eth-dst apply to the outer Ethernet header.
func sendSniff(args []string) int {
	fs := flag.NewFlagSet("send-sniff", flag.ContinueOnError)

	// TX craft flags.
	txIface := fs.String("tx-iface", "", "TX interface (required unless --count 0 or --no-rx)")
	ethSrc := fs.String("eth-src", "52:54:00:00:00:01", "Ethernet source MAC")
	ethDst := fs.String("eth-dst", "aa:aa:aa:aa:aa:aa", "Ethernet destination MAC")
	ipSrc := fs.String("ip-src", "", "IP (inner) source address")
	ipDst := fs.String("ip-dst", "", "IP (inner) destination address")
	ipv6 := fs.Bool("ipv6", false, "build an IPv6 L3 layer instead of IPv4 (plain, not encap)")
	l4 := fs.String("l4", "tcp", "L4 protocol: tcp, udp, or none")
	sport := fs.Int("sport", 0, "source port")
	dport := fs.Int("dport", 0, "destination port")
	payload := fs.String("payload", "", "payload string")
	count := fs.Int("count", 1, "number of TX frames (0 = sniff-only, no TX)")
	intervalMs := fs.Int("interval-ms", 0, "milliseconds between TX sends")

	// Encap flag: build an outer IPv6 / inner IPv4 IP-in-IPv6 frame.
	encap := fs.String("encap", "", "encap mode: 'ipip' = outer IPv6(nh=4)/inner IPv4; outer addrs from --outer-ipv6-src/--outer-ipv6-dst")
	outerIPv6Src := fs.String("outer-ipv6-src", "", "outer IPv6 source (--encap ipip)")
	outerIPv6Dst := fs.String("outer-ipv6-dst", "", "outer IPv6 destination (--encap ipip)")

	// Flags (skips RX entirely; useful for tx-only in cross-netns patterns).
	noRX := fs.Bool("no-rx", false, "skip RX/sniff entirely (tx-only mode)")

	// RX flags.
	rxIface := fs.String("rx-iface", "", "RX interface (default = tx-iface)")
	timeoutSec := fs.Float64("timeout", 5.0, "sniff timeout in seconds")

	// RX filter flags (candidates must match ALL set filters).
	rxInnerIPSrc := fs.String("rx-inner-ip-src", "", "candidate filter: inner IPv4 src must match")
	rxInnerIPDst := fs.String("rx-inner-ip-dst", "", "candidate filter: inner IPv4 dst must match")
	rxL4 := fs.String("rx-l4", "", "candidate filter: require this L4 (tcp or udp)")
	rxOuterIPv6 := fs.Bool("rx-outer-ipv6", false, "candidate filter: require an outer IPv6 layer")

	// Assertion / extraction flags.
	wantOuterIPv6NH := fs.Int("want-outer-ipv6-nh", -1, "assert outer IPv6 NextHeader == n (-1 = unset)")
	extract := fs.String("extract", "", "field to extract from first candidate (e.g. inner-tcp-sport)")
	sportRange := fs.String("sport-range", "", "if --extract inner-tcp-sport, assert value is in <min>-<max>")
	countMin := fs.Int("count-min", 1, "PASS requires >= n candidate frames")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	// ── TX setup ──────────────────────────────────────────────────────────────
	sniffOnly := *count == 0
	if !sniffOnly && !*noRX && *txIface == "" {
		fmt.Fprintln(os.Stderr, "send-sniff: --tx-iface is required (or pass --count 0 for sniff-only)")
		return 2
	}

	// Resolve RX iface.
	rxIfaceName := *rxIface
	if rxIfaceName == "" {
		rxIfaceName = *txIface
	}
	if !*noRX && rxIfaceName == "" {
		fmt.Fprintln(os.Stderr, "send-sniff: --rx-iface is required when --tx-iface is not set")
		return 2
	}

	// Build TX frame (only if we will actually transmit).
	var txFrame []byte
	if !sniffOnly && !*noRX || (*noRX && !sniffOnly) {
		var err error
		txFrame, err = craftFrame(*ethSrc, *ethDst, *ipSrc, *ipDst, *ipv6, *l4, *sport, *dport, *payload, *encap, *outerIPv6Src, *outerIPv6Dst)
		if err != nil {
			fmt.Fprintf(os.Stderr, "send-sniff: craft frame: %v\n", err)
			return 2
		}
	}

	// ── TX-only mode (--no-rx) ────────────────────────────────────────────────
	if *noRX {
		if sniffOnly {
			fmt.Fprintln(os.Stderr, "send-sniff: --no-rx and --count 0 both set — nothing to do")
			return 2
		}
		for i := 0; i < *count; i++ {
			if err := netpkt.Send(*txIface, txFrame); err != nil {
				fmt.Fprintf(os.Stderr, "send-sniff: send: %v\n", err)
				return 1
			}
			if *intervalMs > 0 && i < *count-1 {
				time.Sleep(time.Duration(*intervalMs) * time.Millisecond)
			}
		}
		fmt.Printf("sent %d frame(s) on %s\n", *count, *txIface)
		return 0
	}

	// ── RX filter parse ───────────────────────────────────────────────────────
	var rxInnerSrcIP, rxInnerDstIP net.IP
	if *rxInnerIPSrc != "" {
		rxInnerSrcIP = net.ParseIP(*rxInnerIPSrc)
		if rxInnerSrcIP == nil {
			fmt.Fprintf(os.Stderr, "send-sniff: invalid --rx-inner-ip-src %q\n", *rxInnerIPSrc)
			return 2
		}
	}
	if *rxInnerIPDst != "" {
		rxInnerDstIP = net.ParseIP(*rxInnerIPDst)
		if rxInnerDstIP == nil {
			fmt.Fprintf(os.Stderr, "send-sniff: invalid --rx-inner-ip-dst %q\n", *rxInnerIPDst)
			return 2
		}
	}

	// ── sport range parse ─────────────────────────────────────────────────────
	var sportMin, sportMax int
	hasSportRange := false
	if *sportRange != "" {
		parts := strings.SplitN(*sportRange, "-", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "send-sniff: --sport-range must be <min>-<max>, got %q\n", *sportRange)
			return 2
		}
		var err1, err2 error
		sportMin, err1 = strconv.Atoi(parts[0])
		sportMax, err2 = strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			fmt.Fprintf(os.Stderr, "send-sniff: --sport-range parse error: %q\n", *sportRange)
			return 2
		}
		hasSportRange = true
	}

	// ── candidate matcher ─────────────────────────────────────────────────────
	var collected []gopacket.Packet // candidates that passed all RX filters

	isCandidate := func(pkt gopacket.Packet) bool {
		if *rxOuterIPv6 {
			if pkt.Layer(layers.LayerTypeIPv6) == nil {
				return false
			}
		}
		if rxInnerSrcIP != nil {
			v4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if v4 == nil || !v4.SrcIP.Equal(rxInnerSrcIP) {
				return false
			}
		}
		if rxInnerDstIP != nil {
			v4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if v4 == nil || !v4.DstIP.Equal(rxInnerDstIP) {
				return false
			}
		}
		if *rxL4 != "" {
			switch *rxL4 {
			case "tcp":
				if pkt.Layer(layers.LayerTypeTCP) == nil {
					return false
				}
			case "udp":
				if pkt.Layer(layers.LayerTypeUDP) == nil {
					return false
				}
			}
		}
		return true
	}

	matchFn := func(pkt gopacket.Packet) bool {
		if isCandidate(pkt) {
			collected = append(collected, pkt)
			if len(collected) >= *countMin {
				return true // signal Sniff to return early
			}
		}
		return false
	}

	// ── arm (inject) closure ──────────────────────────────────────────────────
	var armFn func() error
	if !sniffOnly {
		armFn = func() error {
			for i := 0; i < *count; i++ {
				if err := netpkt.Send(*txIface, txFrame); err != nil {
					return err
				}
				if *intervalMs > 0 && i < *count-1 {
					time.Sleep(time.Duration(*intervalMs) * time.Millisecond)
				}
			}
			return nil
		}
	}

	// ── sniff ─────────────────────────────────────────────────────────────────
	timeout := time.Duration(float64(time.Second) * *timeoutSec)
	_, err := netpkt.Sniff(rxIfaceName, timeout, armFn, matchFn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send-sniff: sniff: %v\n", err)
		return 1
	}

	// After Sniff returns, collected holds everything accumulated during the
	// match loop (Sniff may have returned early on match=true). If Sniff timed
	// out before enough candidates the slice is short.
	if len(collected) < *countMin {
		fmt.Fprintf(os.Stderr, "FAIL: captured %d candidate(s), want >= %d\n", len(collected), *countMin)
		return 1
	}

	// ── assertions on first candidate ─────────────────────────────────────────
	first := collected[0]

	if *wantOuterIPv6NH >= 0 {
		outerV6, _ := first.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if outerV6 == nil {
			fmt.Fprintf(os.Stderr, "FAIL: --want-outer-ipv6-nh set but first candidate has no IPv6 layer\n")
			return 1
		}
		if int(outerV6.NextHeader) != *wantOuterIPv6NH {
			fmt.Fprintf(os.Stderr, "FAIL: outer IPv6 NextHeader=%d, want %d\n", int(outerV6.NextHeader), *wantOuterIPv6NH)
			return 1
		}
	}

	// ── extraction ────────────────────────────────────────────────────────────
	if *extract != "" {
		switch *extract {
		case "inner-tcp-sport":
			tcp, _ := first.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if tcp == nil {
				fmt.Fprintf(os.Stderr, "FAIL: --extract inner-tcp-sport but first candidate has no TCP layer\n")
				return 1
			}
			val := int(tcp.SrcPort)
			if hasSportRange {
				if val < sportMin || val > sportMax {
					fmt.Fprintf(os.Stderr, "FAIL: inner-tcp-sport=%d outside range [%d,%d]\n", val, sportMin, sportMax)
					return 1
				}
			}
			fmt.Printf("OK: captured %d frame(s); inner-tcp-sport=%d\n", len(collected), val)
		default:
			fmt.Fprintf(os.Stderr, "send-sniff: unknown --extract value %q\n", *extract)
			return 2
		}
		return 0
	}

	fmt.Printf("OK: captured %d candidate frame(s) on %s\n", len(collected), rxIfaceName)
	return 0
}

// craftFrame builds a serialized Ethernet frame from the given parameters.
// It is shared between TX-only and send+sniff paths.
func craftFrame(ethSrcStr, ethDstStr, ipSrcStr, ipDstStr string, isIPv6 bool, l4Proto string, sport, dport int, payload string, encapMode, outerIPv6SrcStr, outerIPv6DstStr string) ([]byte, error) {
	srcMAC, err := net.ParseMAC(ethSrcStr)
	if err != nil {
		return nil, fmt.Errorf("invalid --eth-src %q: %w", ethSrcStr, err)
	}
	dstMAC, err := net.ParseMAC(ethDstStr)
	if err != nil {
		return nil, fmt.Errorf("invalid --eth-dst %q: %w", ethDstStr, err)
	}

	// ── IP-in-IPv6 encap (outer IPv6, nh=4, inner IPv4) ──────────────────────
	if encapMode == "ipip" {
		outerSrc := net.ParseIP(outerIPv6SrcStr)
		if outerSrc == nil {
			return nil, fmt.Errorf("invalid --outer-ipv6-src %q", outerIPv6SrcStr)
		}
		outerDst := net.ParseIP(outerIPv6DstStr)
		if outerDst == nil {
			return nil, fmt.Errorf("invalid --outer-ipv6-dst %q", outerIPv6DstStr)
		}

		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		}
		outerV6 := &layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocol(4), // IPIP
			HopLimit:   64,
			SrcIP:      outerSrc,
			DstIP:      outerDst,
		}
		innerV4 := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		if ipSrcStr != "" {
			innerV4.SrcIP = net.ParseIP(ipSrcStr)
			if innerV4.SrcIP == nil {
				return nil, fmt.Errorf("invalid --ip-src %q", ipSrcStr)
			}
		}
		if ipDstStr != "" {
			innerV4.DstIP = net.ParseIP(ipDstStr)
			if innerV4.DstIP == nil {
				return nil, fmt.Errorf("invalid --ip-dst %q", ipDstStr)
			}
		}

		var serialLayers []gopacket.SerializableLayer
		serialLayers = append(serialLayers, eth, outerV6, innerV4)

		switch l4Proto {
		case "tcp":
			tcp := &layers.TCP{
				SrcPort: layers.TCPPort(sport),
				DstPort: layers.TCPPort(dport),
				Seq:     1,
				ACK:     true,
				Window:  65535,
			}
			if err := tcp.SetNetworkLayerForChecksum(innerV4); err != nil {
				return nil, fmt.Errorf("SetNetworkLayerForChecksum: %w", err)
			}
			serialLayers = append(serialLayers, tcp, gopacket.Payload([]byte(payload)))
		case "udp":
			udp := &layers.UDP{
				SrcPort: layers.UDPPort(sport),
				DstPort: layers.UDPPort(dport),
			}
			if err := udp.SetNetworkLayerForChecksum(innerV4); err != nil {
				return nil, fmt.Errorf("SetNetworkLayerForChecksum: %w", err)
			}
			serialLayers = append(serialLayers, udp, gopacket.Payload([]byte(payload)))
		case "none":
			serialLayers = append(serialLayers, gopacket.Payload([]byte(payload)))
		default:
			return nil, fmt.Errorf("unknown --l4 %q (want tcp, udp, or none)", l4Proto)
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, serialLayers...); err != nil {
			return nil, fmt.Errorf("serialize: %w", err)
		}
		return buf.Bytes(), nil
	}

	// ── Plain IPv4 or IPv6 frame ──────────────────────────────────────────────
	eth := &layers.Ethernet{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
	}

	var ipLayer gopacket.NetworkLayer
	if isIPv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 := &layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolUDP,
			HopLimit:   64,
		}
		if ipSrcStr != "" {
			ip6.SrcIP = net.ParseIP(ipSrcStr)
			if ip6.SrcIP == nil {
				return nil, fmt.Errorf("invalid --ip-src %q", ipSrcStr)
			}
		}
		if ipDstStr != "" {
			ip6.DstIP = net.ParseIP(ipDstStr)
			if ip6.DstIP == nil {
				return nil, fmt.Errorf("invalid --ip-dst %q", ipDstStr)
			}
		}
		ipLayer = ip6
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
		}
		if ipSrcStr != "" {
			ip4.SrcIP = net.ParseIP(ipSrcStr)
			if ip4.SrcIP == nil {
				return nil, fmt.Errorf("invalid --ip-src %q", ipSrcStr)
			}
		}
		if ipDstStr != "" {
			ip4.DstIP = net.ParseIP(ipDstStr)
			if ip4.DstIP == nil {
				return nil, fmt.Errorf("invalid --ip-dst %q", ipDstStr)
			}
		}
		ipLayer = ip4
	}

	var serialLayers []gopacket.SerializableLayer
	serialLayers = append(serialLayers, eth, ipLayer.(gopacket.SerializableLayer))

	switch l4Proto {
	case "udp":
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(sport),
			DstPort: layers.UDPPort(dport),
		}
		if err := udp.SetNetworkLayerForChecksum(ipLayer); err != nil {
			return nil, fmt.Errorf("SetNetworkLayerForChecksum: %w", err)
		}
		if isIPv6 {
			ipLayer.(*layers.IPv6).NextHeader = layers.IPProtocolUDP
		} else {
			ipLayer.(*layers.IPv4).Protocol = layers.IPProtocolUDP
		}
		serialLayers = append(serialLayers, udp, gopacket.Payload([]byte(payload)))
	case "tcp":
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(sport),
			DstPort: layers.TCPPort(dport),
			Seq:     1,
			SYN:     true,
			Window:  65535,
		}
		if err := tcp.SetNetworkLayerForChecksum(ipLayer); err != nil {
			return nil, fmt.Errorf("SetNetworkLayerForChecksum: %w", err)
		}
		if isIPv6 {
			ipLayer.(*layers.IPv6).NextHeader = layers.IPProtocolTCP
		} else {
			ipLayer.(*layers.IPv4).Protocol = layers.IPProtocolTCP
		}
		serialLayers = append(serialLayers, tcp, gopacket.Payload([]byte(payload)))
	case "none":
		serialLayers = append(serialLayers, gopacket.Payload([]byte(payload)))
	default:
		return nil, fmt.Errorf("unknown --l4 %q (want tcp, udp, or none)", l4Proto)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, serialLayers...); err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}
	return buf.Bytes(), nil
}
