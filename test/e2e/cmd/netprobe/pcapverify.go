package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trevex/ectobase/test/e2e/internal/netpkt"
)

// pcapVerify implements the pcap-verify subcommand. It supports two modes:
//
// Mode A – MAC-swap check (--in + --out + --mac-swap + --count N):
//
//	Reads both pcap files, asserts len(in)==len(out)==count, and for each
//	packet i verifies that out[i].eth.dst==in[i].eth.src and
//	out[i].eth.src==in[i].eth.dst.
//
// Mode B – predicate check (--pcap + predicate flags):
//
//	Reads --pcap; passes (exit 0) if AT LEAST ONE packet satisfies ALL set
//	predicates. Unset predicates (default sentinel values) are not checked.
//	Predicate flags: --want-outer-ipv6-nh, --want-outer-ipv6-dst,
//	--want-inner-ip-src, --want-inner-ip-dst, --want-no-ipv6.
func pcapVerify(args []string) int {
	fs := flag.NewFlagSet("pcap-verify", flag.ContinueOnError)

	// Mode A flags.
	inPath := fs.String("in", "", "input pcap file (mode A)")
	outPath := fs.String("out", "", "output pcap file (mode A)")
	macSwap := fs.Bool("mac-swap", false, "assert dst/src are swapped between --in and --out (mode A)")
	count := fs.Int("count", -1, "expected packet count in both pcap files (mode A, -1 = unset)")

	// Mode B flags.
	pcapPath := fs.String("pcap", "", "pcap file to check predicates against (mode B)")
	wantOuterIPv6NH := fs.Int("want-outer-ipv6-nh", -1, "outer IPv6 NextHeader value to match (-1 = unset)")
	wantOuterIPv6Dst := fs.String("want-outer-ipv6-dst", "", "outer IPv6 dst IP to match (empty = unset)")
	wantInnerIPSrc := fs.String("want-inner-ip-src", "", "inner IPv4 src IP to match (empty = unset)")
	wantInnerIPDst := fs.String("want-inner-ip-dst", "", "inner IPv4 dst IP to match (empty = unset)")
	wantNoIPv6 := fs.Bool("want-no-ipv6", false, "require NO IPv6 layer in every packet")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	// Determine mode.
	if *macSwap || *inPath != "" || *outPath != "" {
		return pcapVerifyModeA(*inPath, *outPath, *macSwap, *count)
	}
	if *pcapPath != "" {
		return pcapVerifyModeB(*pcapPath, *wantOuterIPv6NH, *wantOuterIPv6Dst, *wantInnerIPSrc, *wantInnerIPDst, *wantNoIPv6)
	}

	fmt.Fprintln(os.Stderr, "pcap-verify: specify either --in/--out/--mac-swap (mode A) or --pcap (mode B)")
	fs.Usage()
	return 2
}

// pcapVerifyModeA implements the MAC-swap assertion.
func pcapVerifyModeA(inPath, outPath string, macSwap bool, count int) int {
	if inPath == "" || outPath == "" {
		fmt.Fprintln(os.Stderr, "pcap-verify: --in and --out are required in mode A")
		return 2
	}

	inPkts, err := netpkt.ReadPcap(inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcap-verify: read --in %q: %v\n", inPath, err)
		return 1
	}
	outPkts, err := netpkt.ReadPcap(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcap-verify: read --out %q: %v\n", outPath, err)
		return 1
	}

	if count >= 0 {
		if len(inPkts) != count {
			fmt.Fprintf(os.Stderr, "pcap-verify: --in has %d packets, want %d\n", len(inPkts), count)
			return 1
		}
		if len(outPkts) != count {
			fmt.Fprintf(os.Stderr, "pcap-verify: --out has %d packets, want %d\n", len(outPkts), count)
			return 1
		}
	} else if len(inPkts) != len(outPkts) {
		fmt.Fprintf(os.Stderr, "pcap-verify: packet count mismatch: --in=%d --out=%d\n", len(inPkts), len(outPkts))
		return 1
	}

	if macSwap {
		for i := range inPkts {
			inEth, _ := inPkts[i].Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
			outEth, _ := outPkts[i].Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
			if inEth == nil || outEth == nil {
				fmt.Fprintf(os.Stderr, "pcap-verify: packet %d has no Ethernet layer\n", i)
				return 1
			}
			if outEth.DstMAC.String() != inEth.SrcMAC.String() {
				fmt.Fprintf(os.Stderr, "pcap-verify: packet %d: out.eth.dst=%s != in.eth.src=%s\n",
					i, outEth.DstMAC, inEth.SrcMAC)
				return 1
			}
			if outEth.SrcMAC.String() != inEth.DstMAC.String() {
				fmt.Fprintf(os.Stderr, "pcap-verify: packet %d: out.eth.src=%s != in.eth.dst=%s\n",
					i, outEth.SrcMAC, inEth.DstMAC)
				return 1
			}
		}
	}

	fmt.Println("OK")
	return 0
}

// pcapVerifyModeB implements predicate-based packet matching.
func pcapVerifyModeB(pcapPath string, wantNH int, wantDst, wantInSrc, wantInDst string, wantNoIPv6 bool) int {
	pkts, err := netpkt.ReadPcap(pcapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcap-verify: read --pcap %q: %v\n", pcapPath, err)
		return 1
	}

	var wantDstIP, wantInSrcIP, wantInDstIP net.IP
	if wantDst != "" {
		wantDstIP = net.ParseIP(wantDst)
		if wantDstIP == nil {
			fmt.Fprintf(os.Stderr, "pcap-verify: invalid --want-outer-ipv6-dst %q\n", wantDst)
			return 2
		}
	}
	if wantInSrc != "" {
		wantInSrcIP = net.ParseIP(wantInSrc)
		if wantInSrcIP == nil {
			fmt.Fprintf(os.Stderr, "pcap-verify: invalid --want-inner-ip-src %q\n", wantInSrc)
			return 2
		}
	}
	if wantInDst != "" {
		wantInDstIP = net.ParseIP(wantInDst)
		if wantInDstIP == nil {
			fmt.Fprintf(os.Stderr, "pcap-verify: invalid --want-inner-ip-dst %q\n", wantInDst)
			return 2
		}
	}

	for _, pkt := range pkts {
		if pktMatchesPredicate(pkt, wantNH, wantDstIP, wantInSrcIP, wantInDstIP, wantNoIPv6) {
			fmt.Printf("PASS: pcap-verify matched (%s)\n", pcapPath)
			return 0
		}
	}

	fmt.Fprintf(os.Stderr, "no matching pkt in %d captured\n", len(pkts))
	for _, pkt := range pkts {
		fmt.Fprintf(os.Stderr, "  %s\n", pkt.String())
	}
	return 1
}

// pktMatchesPredicate returns true if pkt satisfies all set predicates.
//
//   - wantNH >= 0: outer IPv6 (first *layers.IPv6) NextHeader must equal wantNH.
//   - wantDstIP != nil: outer IPv6 DstIP must equal wantDstIP.
//   - wantInSrcIP != nil: inner IPv4 SrcIP must equal wantInSrcIP.
//   - wantInDstIP != nil: inner IPv4 DstIP must equal wantInDstIP.
//   - wantNoIPv6: the packet must have NO IPv6 layer at all.
func pktMatchesPredicate(pkt gopacket.Packet, wantNH int, wantDstIP, wantInSrcIP, wantInDstIP net.IP, wantNoIPv6 bool) bool {
	hasIPv6 := pkt.Layer(layers.LayerTypeIPv6) != nil

	if wantNoIPv6 {
		// Fail immediately if an IPv6 layer is present.
		return !hasIPv6
	}

	// Outer IPv6 predicates.
	if wantNH >= 0 || wantDstIP != nil {
		outerV6, _ := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if outerV6 == nil {
			return false
		}
		if wantNH >= 0 && int(outerV6.NextHeader) != wantNH {
			return false
		}
		if wantDstIP != nil && !outerV6.DstIP.Equal(wantDstIP) {
			return false
		}
	}

	// Inner IPv4 predicates.
	if wantInSrcIP != nil || wantInDstIP != nil {
		innerV4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if innerV4 == nil {
			return false
		}
		if wantInSrcIP != nil && !innerV4.SrcIP.Equal(wantInSrcIP) {
			return false
		}
		if wantInDstIP != nil && !innerV4.DstIP.Equal(wantInDstIP) {
			return false
		}
	}

	return true
}
