package main

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("parse mac %q: %v", s, err)
	}
	return m
}

func TestBuildDHCPDiscoverParsesBack(t *testing.T) {
	mac := mustMAC(t, "02:aa:bb:cc:dd:ee")
	frame, err := buildDHCPDiscover(mac, 0x1234)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(frame) < 300 {
		t.Fatalf("DISCOVER too small: %d bytes", len(frame))
	}
	mt, _, _, _, ok := parseDHCPReply(frame)
	if ok && mt == 2 {
		t.Fatal("our DISCOVER must not parse as an OFFER")
	}
}

func TestParseDHCPOfferFields(t *testing.T) {
	yi := net.IPv4(10, 1, 0, 7)
	dns := []net.IP{net.IPv4(8, 8, 8, 8), net.IPv4(8, 8, 4, 4)}
	frame, err := buildDHCPOffer(mustMAC(t, "02:aa:bb:cc:dd:ee"), yi, 1450, dns)
	if err != nil {
		t.Fatalf("build offer: %v", err)
	}
	mt, gotYi, mtu, gotDNS, ok := parseDHCPReply(frame)
	if !ok || mt != 2 {
		t.Fatalf("parse: ok=%v mt=%d", ok, mt)
	}
	if !gotYi.Equal(yi) {
		t.Fatalf("yiaddr: got %v want %v", gotYi, yi)
	}
	if mtu != 1450 {
		t.Fatalf("mtu: got %d want 1450", mtu)
	}
	if len(gotDNS) == 0 {
		t.Fatal("dns servers missing")
	}
}

func TestARPRequestReplyRoundTrip(t *testing.T) {
	mac := mustMAC(t, "52:54:00:00:00:01")
	req, err := buildARPRequest(mac, net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 1))
	if err != nil {
		t.Fatalf("build arp: %v", err)
	}
	if len(req) < 42 {
		t.Fatalf("arp too small: %d", len(req))
	}
	reply, _ := buildARPReply(mac, net.IPv4(10, 0, 0, 1))
	op, psrc, hwsrc, ok := parseARP(reply)
	if !ok || op != 2 || !psrc.Equal(net.IPv4(10, 0, 0, 1)) || hwsrc.String() != mac.String() {
		t.Fatalf("parse arp reply: op=%d psrc=%v hwsrc=%v ok=%v", op, psrc, hwsrc, ok)
	}
}

func TestNSNARoundTrip(t *testing.T) {
	mac := mustMAC(t, "52:54:00:00:00:01")
	ns, err := buildNS(mac, net.ParseIP("fe80::1"))
	if err != nil {
		t.Fatalf("build ns: %v", err)
	}
	if len(ns) < 60 {
		t.Fatalf("ns too small: %d", len(ns))
	}
	na, err := buildNA(mac, net.ParseIP("fe80::1"))
	if err != nil {
		t.Fatalf("build na: %v", err)
	}
	tgt, dstLL, ok := parseNA(na)
	if !ok || !tgt.Equal(net.ParseIP("fe80::1")) || dstLL.String() != mac.String() {
		t.Fatalf("parse na: tgt=%v dstll=%v ok=%v", tgt, dstLL, ok)
	}
}

func TestEUI64LinkLocal(t *testing.T) {
	got := eui64LinkLocal(mustMAC(t, "52:54:00:00:00:01"))
	want := "fe80::5054:ff:fe00:1"
	if got.String() != want {
		t.Fatalf("eui64: got %s want %s", got, want)
	}
}

func TestInnerIPv4Parses(t *testing.T) {
	f, err := buildInnerIPv4ICMP()
	if err != nil {
		t.Fatal(err)
	}
	p := gopacket.NewPacket(f, layers.LayerTypeEthernet, gopacket.Default)
	ip, _ := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip == nil || !ip.SrcIP.Equal(net.IPv4(10, 0, 0, 1)) || !ip.DstIP.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Fatalf("inner v4 wrong: %v", ip)
	}
}

func TestInnerIPv6Parses(t *testing.T) {
	f, err := buildInnerIPv6ICMP6("2001:db8:1::1", "2001:db8:2::2")
	if err != nil {
		t.Fatal(err)
	}
	p := gopacket.NewPacket(f, layers.LayerTypeEthernet, gopacket.Default)
	ip, _ := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if ip == nil || !ip.DstIP.Equal(net.ParseIP("2001:db8:2::2")) {
		t.Fatalf("inner v6 wrong: %v", ip)
	}
}

func TestDHCPv6SolicitAdvertiseRoundTrip(t *testing.T) {
	mac := mustMAC(t, "52:54:00:00:00:01")
	sol, duid, err := buildDHCPv6Solicit(mac)
	if err != nil {
		t.Fatalf("build solicit: %v", err)
	}
	if len(sol) < 60 || len(duid) == 0 {
		t.Fatalf("solicit=%d duid=%d", len(sol), len(duid))
	}
	cap := duid
	if len(cap) > 10 {
		cap = cap[:10]
	}
	adv, err := buildDHCPv6Advertise(mac, net.ParseIP("2001:db8:1::7"), cap)
	if err != nil {
		t.Fatalf("build advertise: %v", err)
	}
	iaAddr, echoed, ok := parseDHCPv6Reply(adv)
	if !ok || iaAddr == nil || !iaAddr.Equal(net.ParseIP("2001:db8:1::7")) {
		t.Fatalf("parse advertise: ok=%v ia=%v", ok, iaAddr)
	}
	if len(echoed) == 0 {
		t.Fatal("clientid not echoed")
	}
}
