package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunSetIff = 0x400454CA
	iffTap    = 0x0002
	iffNoPI   = 0x1000
)

// openTapQueue attaches a NEW queue fd to an EXISTING tap netdev `name` (does not create it or
// set it up — the caller/datapath already did). Writing injects toward the host RX (tc/XDP
// ingress fires); reading drains the tap egress (where the responder's redirect-to-self delivers
// the reply). Mirrors the Python open_tap_queue: TUNSETIFF with IFF_TAP|IFF_NO_PI (raw ethernet).
func openTapQueue(name string) (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:unix.IFNAMSIZ-1], name)
	flags := uint16(iffTap | iffNoPI)
	ifr[unix.IFNAMSIZ] = byte(flags)
	ifr[unix.IFNAMSIZ+1] = byte(flags >> 8)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(tunSetIff), uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF %s: %v", name, e)
	}
	return f, nil
}

// readFrames reads raw frames off the tap fd, invoking match(frame) until it returns true or the
// deadline passes. Uses a per-read deadline so the loop wakes to re-check the overall deadline.
func readFrames(f *os.File, timeout time.Duration, match func([]byte) bool) bool {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		_ = f.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := f.Read(buf)
		if err != nil {
			continue // per-read timeout; loop until overall deadline
		}
		if n > 0 && match(buf[:n]) {
			return true
		}
	}
	return false
}
