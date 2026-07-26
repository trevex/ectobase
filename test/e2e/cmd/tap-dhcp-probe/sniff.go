package main

// Pure-Go AF_PACKET raw socket implementation for sniffing and injecting Ethernet frames.
// This replaces the gopacket/afpacket import (which requires cgo) with direct
// golang.org/x/sys/unix syscalls, making the binary fully cgo-free so that
// CGO_ENABLED=0 go build produces a static binary that runs inside kind nodes
// (Ubuntu-based) without a /nix/store glibc interpreter.
//
// gopacket and gopacket/layers are still used — they are pure Go — only for
// parsing frames, not for capture/inject.

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

// htons converts a uint16 from host byte order to network (big-endian) byte order.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// injectAF sends frame on iface using a fresh AF_PACKET raw socket.
// Opening a new socket per call is acceptable for the low frame counts used in probes.
func injectAF(iface string, frame []byte) error {
	iff, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	addr := &unix.SockaddrLinklayer{
		Ifindex: iff.Index,
	}
	return unix.Sendto(fd, frame, 0, addr)
}

// sniffIPv6 opens an AF_PACKET raw socket on iface, waits 500ms for the socket to arm,
// calls inject() to send probe frames, then reads frames until want(pkt) is satisfied or
// timeout elapses. Returns all captured frames that carry an outer IPv6 layer.
//
// The 500ms settle mirrors the Python AsyncSniffer.start()+sleep(0.5) pattern so injected
// frames are not missed due to a race between socket open and packet arrival.
func sniffIPv6(iface string, timeout time.Duration, inject func() error, want func(pkt gopacket.Packet) bool) ([]gopacket.Packet, error) {
	iff, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	// Open a raw socket for all Ethernet frames on the given interface.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iff.Index,
	}); err != nil {
		return nil, err
	}

	// Set a 200ms receive timeout so the read loop wakes up periodically to
	// re-check the deadline rather than blocking indefinitely.
	tv := &unix.Timeval{Sec: 0, Usec: 200000}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, tv); err != nil {
		return nil, err
	}

	// Allow the kernel to arm the socket before we inject.
	time.Sleep(500 * time.Millisecond)

	if err := inject(); err != nil {
		return nil, err
	}

	buf := make([]byte, 65536)
	var got []gopacket.Packet
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			// EAGAIN / EWOULDBLOCK = SO_RCVTIMEO expired with no packet; keep looping.
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			// Any other recv error is fatal.
			return got, err
		}
		if n == 0 {
			continue
		}
		pkt := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
		if pkt.Layer(layers.LayerTypeIPv6) == nil {
			continue
		}
		got = append(got, pkt)
		if want(pkt) {
			return got, nil
		}
	}
	return got, nil
}
