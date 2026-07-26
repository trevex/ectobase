package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

var (
	broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zeroMAC      = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// All DHCP relay agents and servers (ff02::1:2)
	allDHCPv6 = net.ParseIP("ff02::1:2")
	// All-nodes multicast
	allNodes = net.ParseIP("ff02::1")
)

// eui64LinkLocal derives the fe80::/64 link-local address for mac using EUI-64.
// For 52:54:00:00:00:01 this produces fe80::5054:ff:fe00:1.
func eui64LinkLocal(mac net.HardwareAddr) net.IP {
	// Expand 6-byte MAC to 8-byte EUI-64:
	// flip Universal/Local bit (bit 6 of byte 0), insert 0xff 0xfe in the middle.
	eui := make([]byte, 8)
	copy(eui[0:3], mac[0:3])
	eui[0] ^= 0x02 // flip U/L bit
	eui[3] = 0xff
	eui[4] = 0xfe
	copy(eui[5:8], mac[3:6])

	ip := make(net.IP, 16)
	ip[0] = 0xfe
	ip[1] = 0x80
	// bytes 2-7 are zero (fe80::/64 prefix has 64 bits of zeros after fe80)
	copy(ip[8:16], eui)
	return ip
}

// serializeOpts used for all gopacket SerializeLayers calls.
var serializeOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

// padTo pads a byte slice to at least minLen by appending zero bytes.
func padTo(b []byte, minLen int) []byte {
	if len(b) >= minLen {
		return b
	}
	out := make([]byte, minLen)
	copy(out, b)
	return out
}

// buildDHCPDiscover builds an Ethernet/IPv4/UDP/DHCPv4 DISCOVER frame.
func buildDHCPDiscover(clientMAC net.HardwareAddr, xid uint32) ([]byte, error) {
	// Build the DHCPv4 payload using insomniacslk/dhcp.
	var tid dhcpv4.TransactionID
	binary.BigEndian.PutUint32(tid[:], xid)

	msg, err := dhcpv4.New(
		dhcpv4.WithHWType(iana.HWTypeEthernet),
		dhcpv4.WithTransactionID(tid),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
	)
	if err != nil {
		return nil, fmt.Errorf("dhcpv4 new discover: %w", err)
	}
	msg.OpCode = dhcpv4.OpcodeBootRequest
	msg.ClientHWAddr = clientMAC

	dhcpPayload := msg.ToBytes()

	eth := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       broadcastMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(0, 0, 0, 0),
		DstIP:    net.IPv4(255, 255, 255, 255),
	}
	udp := &layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("udp checksum setup: %w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts,
		eth, ip, udp, gopacket.Payload(dhcpPayload),
	); err != nil {
		return nil, fmt.Errorf("serialize discover: %w", err)
	}
	return buf.Bytes(), nil
}

// buildDHCPOffer builds a test-helper OFFER frame (server→client direction).
func buildDHCPOffer(clientMAC net.HardwareAddr, yiaddr net.IP, mtu uint16, dns []net.IP) ([]byte, error) {
	mtuBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(mtuBytes, mtu)

	msg, err := dhcpv4.New(
		dhcpv4.WithHWType(iana.HWTypeEthernet),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithYourIP(yiaddr),
		dhcpv4.WithDNS(dns...),
		dhcpv4.WithGeneric(dhcpv4.OptionInterfaceMTU, mtuBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("dhcpv4 new offer: %w", err)
	}
	msg.OpCode = dhcpv4.OpcodeBootReply
	msg.ClientHWAddr = clientMAC

	dhcpPayload := msg.ToBytes()

	eth := &layers.Ethernet{
		SrcMAC:       broadcastMAC,
		DstMAC:       clientMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(0, 0, 0, 0),
		DstIP:    net.IPv4(255, 255, 255, 255),
	}
	udp := &layers.UDP{
		SrcPort: 67,
		DstPort: 68,
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("udp checksum setup: %w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts,
		eth, ip, udp, gopacket.Payload(dhcpPayload),
	); err != nil {
		return nil, fmt.Errorf("serialize offer: %w", err)
	}
	return buf.Bytes(), nil
}

// parseDHCPReply decodes an Ethernet/IPv4/UDP/DHCPv4 frame and extracts DHCP fields.
// ok=false if the frame is not a valid DHCPv4 UDP frame.
func parseDHCPReply(frame []byte) (msgType uint8, yiaddr net.IP, mtu uint16, dns []net.IP, ok bool) {
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	msg, err := dhcpv4.FromBytes(udp.Payload)
	if err != nil {
		return
	}

	msgType = uint8(msg.MessageType())
	yiaddr = msg.YourIPAddr

	// Parse MTU option (code 26): 2-byte big-endian uint16.
	raw := msg.GetOneOption(dhcpv4.OptionInterfaceMTU)
	if len(raw) >= 2 {
		mtu = binary.BigEndian.Uint16(raw[:2])
	}

	dns = msg.DNS()
	ok = true
	return
}

// buildARPRequest builds an Ethernet/ARP request frame.
// The frame is padded to at least 60 bytes (before FCS).
func buildARPRequest(srcMAC net.HardwareAddr, srcIP, targetIP net.IP) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       broadcastMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      zeroMAC,
		DstProtAddress:    targetIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, arp); err != nil {
		return nil, fmt.Errorf("serialize arp request: %w", err)
	}
	return padTo(buf.Bytes(), 60), nil
}

// buildARPReply builds a test-helper ARP reply frame.
func buildARPReply(hwsrc net.HardwareAddr, psrc net.IP) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       hwsrc,
		DstMAC:       broadcastMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   hwsrc,
		SourceProtAddress: psrc.To4(),
		DstHwAddress:      zeroMAC,
		DstProtAddress:    net.IPv4(0, 0, 0, 0).To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, arp); err != nil {
		return nil, fmt.Errorf("serialize arp reply: %w", err)
	}
	return padTo(buf.Bytes(), 60), nil
}

// parseARP decodes an Ethernet/ARP frame and extracts operation, source protocol address,
// and source hardware address.
func parseARP(frame []byte) (op uint16, psrc net.IP, hwsrc net.HardwareAddr, ok bool) {
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	arpLayer := pkt.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return
	}
	arp, _ := arpLayer.(*layers.ARP)
	op = arp.Operation
	psrc = net.IP(arp.SourceProtAddress)
	hwsrc = net.HardwareAddr(arp.SourceHwAddress)
	ok = true
	return
}

// buildNS builds an Ethernet/IPv6/ICMPv6 Neighbor Solicitation frame.
// The frame is padded to at least 60 bytes.
func buildNS(clientMAC net.HardwareAddr, target net.IP) ([]byte, error) {
	src := eui64LinkLocal(clientMAC)

	eth := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      src,
		DstIP:      target,
	}
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
	}
	if err := icmp.SetNetworkLayerForChecksum(ip6); err != nil {
		return nil, fmt.Errorf("icmpv6 checksum setup: %w", err)
	}
	ns := &layers.ICMPv6NeighborSolicitation{
		TargetAddress: target,
		Options: layers.ICMPv6Options{
			{
				Type: layers.ICMPv6OptSourceAddress,
				Data: []byte(clientMAC),
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip6, icmp, ns); err != nil {
		return nil, fmt.Errorf("serialize ns: %w", err)
	}
	return padTo(buf.Bytes(), 60), nil
}

// buildNA builds a test-helper Ethernet/IPv6/ICMPv6 Neighbor Advertisement frame.
func buildNA(clientMAC net.HardwareAddr, target net.IP) ([]byte, error) {
	src := eui64LinkLocal(clientMAC)

	eth := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      src,
		DstIP:      allNodes,
	}
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
	}
	if err := icmp.SetNetworkLayerForChecksum(ip6); err != nil {
		return nil, fmt.Errorf("icmpv6 checksum setup: %w", err)
	}
	na := &layers.ICMPv6NeighborAdvertisement{
		Flags:         0x20, // Override bit (RFC 4861)
		TargetAddress: target,
		Options: layers.ICMPv6Options{
			{
				Type: layers.ICMPv6OptTargetAddress,
				Data: []byte(clientMAC),
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip6, icmp, na); err != nil {
		return nil, fmt.Errorf("serialize na: %w", err)
	}
	return padTo(buf.Bytes(), 60), nil
}

// parseNA decodes an Ethernet/IPv6/ICMPv6 Neighbor Advertisement and extracts
// the target address and the target link-layer address option (type 2).
func parseNA(frame []byte) (target net.IP, dstLLAddr net.HardwareAddr, ok bool) {
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	naLayer := pkt.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
	if naLayer == nil {
		return
	}
	na, _ := naLayer.(*layers.ICMPv6NeighborAdvertisement)
	target = na.TargetAddress

	for _, opt := range na.Options {
		if opt.Type == layers.ICMPv6OptTargetAddress {
			dstLLAddr = net.HardwareAddr(opt.Data)
			ok = true
			return
		}
	}
	return
}

// buildDHCPv6Solicit builds an Ethernet/IPv6/UDP/DHCPv6 SOLICIT frame.
// Returns the serialized frame, the raw client DUID bytes, and any error.
func buildDHCPv6Solicit(clientMAC net.HardwareAddr) (frame []byte, duid []byte, err error) {
	clientDUID := &dhcpv6.DUIDLLT{
		HWType:        iana.HWTypeEthernet,
		Time:          0,
		LinkLayerAddr: clientMAC,
	}

	sol, e := dhcpv6.NewSolicit(clientMAC,
		dhcpv6.WithClientID(clientDUID),
	)
	if e != nil {
		err = fmt.Errorf("dhcpv6 new solicit: %w", e)
		return
	}

	duid = clientDUID.ToBytes()

	dhcpPayload := sol.ToBytes()

	src := eui64LinkLocal(clientMAC)

	eth := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       net.HardwareAddr{0x33, 0x33, 0x00, 0x01, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      src,
		DstIP:      allDHCPv6,
	}
	udp := &layers.UDP{
		SrcPort: 546,
		DstPort: 547,
	}
	if e := udp.SetNetworkLayerForChecksum(ip6); e != nil {
		err = fmt.Errorf("udp checksum setup: %w", e)
		return
	}

	buf := gopacket.NewSerializeBuffer()
	if e := gopacket.SerializeLayers(buf, serializeOpts,
		eth, ip6, udp, gopacket.Payload(dhcpPayload),
	); e != nil {
		err = fmt.Errorf("serialize solicit: %w", e)
		return
	}
	frame = buf.Bytes()
	return
}

// buildDHCPv6Advertise builds a test-helper DHCPv6 ADVERTISE frame.
// echoDUID is the raw client DUID bytes to echo back.
func buildDHCPv6Advertise(clientMAC net.HardwareAddr, ia net.IP, echoDUID []byte) ([]byte, error) {
	// Parse the echoDUID bytes back into a DUID interface.
	clientDUID, err := dhcpv6.DUIDFromBytes(echoDUID)
	if err != nil {
		// Fallback: wrap as opaque DUID.
		clientDUID = &dhcpv6.DUIDOpaque{Type: 0xff, Data: echoDUID}
	}

	// Build an IA_NA option with one IAAddress.
	iaNA := &dhcpv6.OptIANA{
		IaId: [4]byte{0, 0, 0, 1},
		T1:   3600 * time.Second,
		T2:   5400 * time.Second,
	}
	iaNA.Options.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          ia,
		PreferredLifetime: 7200 * time.Second,
		ValidLifetime:     7200 * time.Second,
	})

	adv, err := dhcpv6.NewMessage(
		dhcpv6.WithClientID(clientDUID),
	)
	if err != nil {
		return nil, fmt.Errorf("dhcpv6 new advertise: %w", err)
	}
	adv.MessageType = dhcpv6.MessageTypeAdvertise
	adv.AddOption(iaNA)

	dhcpPayload := adv.ToBytes()

	src := eui64LinkLocal(clientMAC)

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x33, 0x33, 0x00, 0x01, 0x00, 0x02},
		DstMAC:       clientMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      allDHCPv6,
		DstIP:      src,
	}
	udp := &layers.UDP{
		SrcPort: 547,
		DstPort: 546,
	}
	if err := udp.SetNetworkLayerForChecksum(ip6); err != nil {
		return nil, fmt.Errorf("udp checksum setup: %w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts,
		eth, ip6, udp, gopacket.Payload(dhcpPayload),
	); err != nil {
		return nil, fmt.Errorf("serialize advertise: %w", err)
	}
	return buf.Bytes(), nil
}

// buildInnerIPv4ICMP builds an Ethernet/IPv4/ICMPv4 echo-request frame
// representing a guest egress packet: 10.0.0.1 → 10.0.0.2.
func buildInnerIPv4ICMP() ([]byte, error) {
	srcMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip, icmp); err != nil {
		return nil, fmt.Errorf("serialize inner ipv4 icmp: %w", err)
	}
	return buf.Bytes(), nil
}

// buildInnerIPv6ICMP6 builds an Ethernet/IPv6/ICMPv6 echo-request frame
// representing a guest egress IPv6 packet: src → dst.
func buildInnerIPv6ICMP6(src, dst string) ([]byte, error) {
	srcMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x00, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}

	srcIP := net.ParseIP(src)
	dstIP := net.ParseIP(dst)
	if srcIP == nil || dstIP == nil {
		return nil, fmt.Errorf("invalid src/dst IP: %q %q", src, dst)
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}
	if err := icmp.SetNetworkLayerForChecksum(ip6); err != nil {
		return nil, fmt.Errorf("icmpv6 checksum setup: %w", err)
	}
	echo := &layers.ICMPv6Echo{
		Identifier: 1,
		SeqNumber:  1,
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts, eth, ip6, icmp, echo); err != nil {
		return nil, fmt.Errorf("serialize inner ipv6 icmpv6: %w", err)
	}
	return buf.Bytes(), nil
}

// parseDHCPv6Reply decodes an Ethernet/IPv6/UDP/DHCPv6 frame.
// Returns the IA_NA address, echoed client ID bytes, and ok=true for Advertise or Reply.
func parseDHCPv6Reply(frame []byte) (iaAddr net.IP, echoedClientID []byte, ok bool) {
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	msg, err := dhcpv6.MessageFromBytes(udp.Payload)
	if err != nil {
		return
	}

	if msg.MessageType != dhcpv6.MessageTypeAdvertise && msg.MessageType != dhcpv6.MessageTypeReply {
		return
	}

	// Extract IA_NA address.
	iana := msg.Options.OneIANA()
	if iana == nil {
		return
	}
	addrs := iana.Options.Addresses()
	if len(addrs) == 0 {
		return
	}
	iaAddr = addrs[0].IPv6Addr

	// Extract echoed client ID.
	clientID := msg.Options.ClientID()
	if clientID != nil {
		echoedClientID = clientID.ToBytes()
	}

	ok = true
	return
}
