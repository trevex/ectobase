package netpkt

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildEth(t *testing.T, src, dst string) []byte {
	t.Helper()
	sm, _ := net.ParseMAC(src)
	dm, _ := net.ParseMAC(dst)
	eth := &layers.Ethernet{SrcMAC: sm, DstMAC: dm, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2)}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPcapRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.pcap")
	f1 := buildEth(t, "02:00:00:00:00:01", "02:00:00:00:00:02")
	f2 := buildEth(t, "02:00:00:00:00:03", "02:00:00:00:00:04")
	if err := WritePcap(p, [][]byte{f1, f2}); err != nil {
		t.Fatal(err)
	}
	pkts, err := ReadPcap(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 2 {
		t.Fatalf("want 2 got %d", len(pkts))
	}
	eth, _ := pkts[0].Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth == nil || eth.SrcMAC.String() != "02:00:00:00:00:01" {
		t.Fatalf("first frame eth wrong: %v", eth)
	}
}
