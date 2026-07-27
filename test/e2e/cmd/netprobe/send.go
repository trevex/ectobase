package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/trevex/ectobase/test/e2e/internal/netpkt"
)

// sendCmd implements the "send" subcommand: craft one Ethernet/IPv4|IPv6/UDP|TCP frame
// and transmit it --count times on --iface, optionally writing the crafted frame to a
// pcap file (--write-pcap) before sending.
//
// Encap support (--encap ipip):
//
//	Builds an outer IPv6 (nh=4) / inner IPv4 IP-in-IPv6 frame. Outer addresses are
//	taken from --outer-ipv6-src and --outer-ipv6-dst; inner addresses from
//	--ip-src/--ip-dst. --eth-src/--eth-dst apply to the outer Ethernet header.
func sendCmd(args []string) int {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)

	iface := fs.String("iface", "", "network interface to send on (required)")
	ethSrc := fs.String("eth-src", "52:54:00:00:00:01", "Ethernet source MAC")
	ethDst := fs.String("eth-dst", "aa:aa:aa:aa:aa:aa", "Ethernet destination MAC")
	ipSrc := fs.String("ip-src", "", "IP (inner) source address")
	ipDst := fs.String("ip-dst", "", "IP (inner) destination address")
	ipv6 := fs.Bool("ipv6", false, "build an IPv6 L3 layer instead of IPv4 (plain, not encap)")
	l4 := fs.String("l4", "udp", "L4 protocol: udp, tcp, or none")
	sport := fs.Int("sport", 0, "source port (0 = let gopacket default)")
	dport := fs.Int("dport", 0, "destination port (0 = let gopacket default)")
	payload := fs.String("payload", "", "payload string")
	count := fs.Int("count", 1, "number of frames to send (0 = craft only, no send)")
	intervalMs := fs.Int("interval-ms", 0, "milliseconds to sleep between sends")
	writePcap := fs.String("write-pcap", "", "if non-empty, write the crafted frame to this pcap file before sending")

	// Encap flags: build outer IPv6 / inner IPv4 IP-in-IPv6 frame.
	encap := fs.String("encap", "", "encap mode: 'ipip' = outer IPv6(nh=4)/inner IPv4")
	outerIPv6Src := fs.String("outer-ipv6-src", "", "outer IPv6 source (--encap ipip)")
	outerIPv6Dst := fs.String("outer-ipv6-dst", "", "outer IPv6 destination (--encap ipip)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "send: --iface is required")
		return 2
	}

	frame, err := craftFrame(*ethSrc, *ethDst, *ipSrc, *ipDst, *ipv6, *l4, *sport, *dport, *payload, *encap, *outerIPv6Src, *outerIPv6Dst)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send: %v\n", err)
		return 2
	}

	// Optionally save the crafted frame to a pcap before sending.
	if *writePcap != "" {
		if err := netpkt.WritePcap(*writePcap, [][]byte{frame}); err != nil {
			fmt.Fprintf(os.Stderr, "send: write-pcap %q: %v\n", *writePcap, err)
			return 1
		}
	}

	// Send --count times (0 means craft only, no transmission).
	for i := 0; i < *count; i++ {
		if err := netpkt.Send(*iface, frame); err != nil {
			fmt.Fprintf(os.Stderr, "send: %v\n", err)
			return 1
		}
		if *intervalMs > 0 && i < *count-1 {
			time.Sleep(time.Duration(*intervalMs) * time.Millisecond)
		}
	}

	fmt.Printf("sent %d frame(s) on %s\n", *count, *iface)
	return 0
}
