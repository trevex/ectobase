// Package netpkt provides cgo-free AF_PACKET send/sniff primitives and pure-Go
// pcap read/write helpers. It uses golang.org/x/sys/unix for raw sockets and
// github.com/google/gopacket/pcapgo (pure Go) for pcap I/O.
package netpkt

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

// htons converts a uint16 from host byte order to network (big-endian) byte order.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Send transmits one raw Ethernet frame on iface via an AF_PACKET raw socket (cgo-free).
func Send(iface string, frame []byte) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("iface %s: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)
	return unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: ifi.Index})
}

// Sniff binds an AF_PACKET RX socket on iface, waits 500ms to arm, calls arm() (if non-nil) to
// inject, then collects packets that decode to Ethernet until match(pkt) is true or timeout.
// Returns all packets seen. cgo-free; mirrors cmd/tap-dhcp-probe/sniff.go.
func Sniff(iface string, timeout time.Duration, arm func() error, match func(gopacket.Packet) bool) ([]gopacket.Packet, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("iface %s: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	// Set a 200ms receive timeout so the read loop wakes up periodically to
	// re-check the deadline rather than blocking indefinitely.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 200000})

	// Allow the kernel to arm the socket before we inject.
	time.Sleep(500 * time.Millisecond)

	if arm != nil {
		if err := arm(); err != nil {
			return nil, fmt.Errorf("arm/inject: %w", err)
		}
	}

	var got []gopacket.Packet
	buf := make([]byte, 65536)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			// EAGAIN / EWOULDBLOCK = SO_RCVTIMEO expired with no packet; keep looping.
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			continue
		}
		if n <= 0 {
			continue
		}
		pkt := gopacket.NewPacket(append([]byte(nil), buf[:n]...), layers.LayerTypeEthernet, gopacket.Default)
		got = append(got, pkt)
		if match != nil && match(pkt) {
			return got, nil
		}
	}
	return got, nil
}

// ReadPcap reads all packets from a pcap file (pure-Go pcapgo).
func ReadPcap(path string) ([]gopacket.Packet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, err
	}

	var out []gopacket.Packet
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		out = append(out, gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default))
	}
	return out, nil
}

// WritePcap writes raw frames to a pcap file (Ethernet link type).
func WritePcap(path string, frames [][]byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return err
	}
	for _, fr := range frames {
		ci := gopacket.CaptureInfo{CaptureLength: len(fr), Length: len(fr)}
		if err := w.WritePacket(ci, fr); err != nil {
			return err
		}
	}
	return nil
}
