package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trevex/ectobase/test/e2e/internal/netpkt"
)

// sendCmd implements the "send" subcommand: craft one Ethernet/IPv4|IPv6/UDP|TCP frame
// and transmit it --count times on --iface, optionally writing the crafted frame to a
// pcap file (--write-pcap) before sending.
func sendCmd(args []string) int {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)

	iface := fs.String("iface", "", "network interface to send on (required)")
	ethSrc := fs.String("eth-src", "52:54:00:00:00:01", "Ethernet source MAC")
	ethDst := fs.String("eth-dst", "aa:aa:aa:aa:aa:aa", "Ethernet destination MAC")
	ipSrc := fs.String("ip-src", "", "IP source address")
	ipDst := fs.String("ip-dst", "", "IP destination address")
	ipv6 := fs.Bool("ipv6", false, "build an IPv6 L3 layer instead of IPv4")
	l4 := fs.String("l4", "udp", "L4 protocol: udp, tcp, or none")
	sport := fs.Int("sport", 0, "source port (0 = let gopacket default)")
	dport := fs.Int("dport", 0, "destination port (0 = let gopacket default)")
	payload := fs.String("payload", "", "payload string")
	count := fs.Int("count", 1, "number of frames to send (0 = craft only, no send)")
	intervalMs := fs.Int("interval-ms", 0, "milliseconds to sleep between sends")
	writePcap := fs.String("write-pcap", "", "if non-empty, write the crafted frame to this pcap file before sending")

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

	// Parse MACs.
	srcMAC, err := net.ParseMAC(*ethSrc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send: invalid --eth-src %q: %v\n", *ethSrc, err)
		return 2
	}
	dstMAC, err := net.ParseMAC(*ethDst)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send: invalid --eth-dst %q: %v\n", *ethDst, err)
		return 2
	}

	// Build Ethernet layer.
	eth := &layers.Ethernet{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
	}

	// Build IP layer.
	var ipLayer gopacket.NetworkLayer
	if *ipv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 := &layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolUDP,
			HopLimit:   64,
		}
		if *ipSrc != "" {
			ip6.SrcIP = net.ParseIP(*ipSrc)
			if ip6.SrcIP == nil {
				fmt.Fprintf(os.Stderr, "send: invalid --ip-src %q\n", *ipSrc)
				return 2
			}
		}
		if *ipDst != "" {
			ip6.DstIP = net.ParseIP(*ipDst)
			if ip6.DstIP == nil {
				fmt.Fprintf(os.Stderr, "send: invalid --ip-dst %q\n", *ipDst)
				return 2
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
		if *ipSrc != "" {
			ip4.SrcIP = net.ParseIP(*ipSrc)
			if ip4.SrcIP == nil {
				fmt.Fprintf(os.Stderr, "send: invalid --ip-src %q\n", *ipSrc)
				return 2
			}
		}
		if *ipDst != "" {
			ip4.DstIP = net.ParseIP(*ipDst)
			if ip4.DstIP == nil {
				fmt.Fprintf(os.Stderr, "send: invalid --ip-dst %q\n", *ipDst)
				return 2
			}
		}
		ipLayer = ip4
	}

	// Build L4 + payload layers.
	var serialLayers []gopacket.SerializableLayer
	serialLayers = append(serialLayers, eth, ipLayer.(gopacket.SerializableLayer))

	switch *l4 {
	case "udp":
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(*sport),
			DstPort: layers.UDPPort(*dport),
		}
		if err := udp.SetNetworkLayerForChecksum(ipLayer); err != nil {
			fmt.Fprintf(os.Stderr, "send: SetNetworkLayerForChecksum: %v\n", err)
			return 1
		}
		if *ipv6 {
			ipLayer.(*layers.IPv6).NextHeader = layers.IPProtocolUDP
		} else {
			ipLayer.(*layers.IPv4).Protocol = layers.IPProtocolUDP
		}
		serialLayers = append(serialLayers, udp, gopacket.Payload([]byte(*payload)))
	case "tcp":
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(*sport),
			DstPort: layers.TCPPort(*dport),
			Seq:     1,
			SYN:     true,
			Window:  65535,
		}
		if err := tcp.SetNetworkLayerForChecksum(ipLayer); err != nil {
			fmt.Fprintf(os.Stderr, "send: SetNetworkLayerForChecksum: %v\n", err)
			return 1
		}
		if *ipv6 {
			ipLayer.(*layers.IPv6).NextHeader = layers.IPProtocolTCP
		} else {
			ipLayer.(*layers.IPv4).Protocol = layers.IPProtocolTCP
		}
		serialLayers = append(serialLayers, tcp, gopacket.Payload([]byte(*payload)))
	case "none":
		serialLayers = append(serialLayers, gopacket.Payload([]byte(*payload)))
	default:
		fmt.Fprintf(os.Stderr, "send: unknown --l4 %q (want udp, tcp, or none)\n", *l4)
		return 2
	}

	// Serialize the frame.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, serialLayers...); err != nil {
		fmt.Fprintf(os.Stderr, "send: serialize: %v\n", err)
		return 1
	}
	frame := buf.Bytes()

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
