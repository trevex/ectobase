// Command tap-dhcp-probe is the Go port of test/tap-dhcp-probe.py: it drives the in-XDP
// DHCP/ARP/ND responder and the encap gates over a raw tap fd, with the SAME CLI flags,
// stdout markers, and exit codes as the Python original (consumers grep the output and
// check the exit code). Pure-Go/cgo-free: gopacket for framing, insomniacslk/dhcp for the
// DHCP messages, x/sys/unix for the tap ioctl, afpacket for veth sniffing.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
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
	flag.Parse()

	to := time.Duration(*timeout * float64(time.Second))

	switch {
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

// Stubs — replaced in later tasks. Each returns 2 (usage/not-implemented) for now.
func egressProbe(tap, peer string, to time.Duration) int { return notImpl("egress") }
func egress6Probe(tap, peer, g6, d6, nh6, gul string, to time.Duration) int {
	return notImpl("egress6")
}
func clientOnlyDHCP(tap, mac, expectIP string, to time.Duration) int { return notImpl("dhcp") }
func arpProbe(tap, mac, expectIP string, to time.Duration) int       { return notImpl("arp") }
func ndProbe(tap, mac, gw6 string, to time.Duration) int             { return notImpl("nd") }
func dhcpv6Probe(tap, mac, expectIP string, to time.Duration) int    { return notImpl("dhcpv6") }
func selfContained() int                                             { return notImpl("default") }

func notImpl(mode string) int { fmt.Fprintf(os.Stderr, "not implemented yet: %s\n", mode); return 2 }
