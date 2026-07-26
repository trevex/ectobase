package main

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

// sniffIPv6 opens an afpacket handle on iface, pre-arms (the caller injects AFTER this returns,
// via the inject callback which runs after a short settle), and collects frames that decode to an
// outer IPv6 layer until want(pkt) is satisfied or timeout. Returns all IPv6-bearing frames seen.
// The pre-arm + 500ms settle mirror the Python AsyncSniffer.start()+sleep(0.5) so the injected
// frame is not missed.
func sniffIPv6(iface string, timeout time.Duration, inject func() error, want func(pkt gopacket.Packet) bool) ([]gopacket.Packet, error) {
	h, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptPollTimeout(200*time.Millisecond),
	)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	time.Sleep(500 * time.Millisecond) // let the ring arm
	if err := inject(); err != nil {
		return nil, err
	}
	var got []gopacket.Packet
	deadline := time.Now().Add(timeout)
	src := gopacket.NewPacketSource(h, layers.LayerTypeEthernet)
	src.NoCopy = true
	packets := src.Packets()
	for time.Now().Before(deadline) {
		select {
		case p := <-packets:
			if p == nil {
				continue
			}
			if p.Layer(layers.LayerTypeIPv6) != nil {
				got = append(got, p)
				if want(p) {
					return got, nil
				}
			}
		case <-time.After(200 * time.Millisecond):
		}
	}
	return got, nil
}
