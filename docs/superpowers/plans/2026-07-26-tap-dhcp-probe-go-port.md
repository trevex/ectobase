# Port the scapy DHCP/packet probe to Go (gopacket + insomniacslk/dhcp) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (fresh subagent per task + two-stage review). Steps use `- [ ]` checkboxes.

**Goal:** Replace `test/tap-dhcp-probe.py` (scapy) with a pure-Go, cgo-free CLI binary that is a literal drop-in for all five consumers, then drop `scapy`+`pytest` from the flake.

**Architecture:** A new Go CLI at `test/e2e/cmd/tap-dhcp-probe/` (in the existing `test/e2e` Go module). Packet framing/ARP/ND/encap parsing via `github.com/google/gopacket`; DHCPv4/DHCPv6 message build+parse via `github.com/insomniacslk/dhcp` (gopacket's `layers.DHCPv6` does not decode IA_NA→IAAddress sub-options, which the DHCPv6 conformance needs). Raw tap-fd I/O via `golang.org/x/sys/unix` (`TUNSETIFF`); veth sniffing via `gopacket/afpacket` (pure-Go AF_PACKET, no libpcap). Same CLI flags, stdout markers, and exit codes as the Python probe so consumers change only the interpreter+path.

**Tech Stack:** Go 1.26 (`test/e2e` module, in `go.work`), gopacket, insomniacslk/dhcp, x/sys/unix, afpacket. Rust `flowplane` binary is the datapath under test (unchanged).

**Grounding — the exact behavior to preserve (from `test/tap-dhcp-probe.py`):**
- CLI flags: `--client-only`, `--probe {dhcp,arp,nd,dhcpv6}`, `--egress`, `--egress6`, `--tap`, `--peer`, `--client-mac` (default `52:54:00:00:00:01`), `--expect-ip` (default `10.0.0.1`), `--guest6` (default `2001:db8:1::1`), `--dst6` (default `2001:db8:2::2`), `--nexthop6` (default `fc00:2::2`), `--guest-underlay` (default `fc00:1::1`), `--gateway6` (default `fe80::1`), `--timeout` (float seconds, default 3.0), and default (no-flag) self-contained mode.
- **Exact stdout markers consumers grep for** (case-sensitive):
  - client-only dhcp: `RESULT: OFFER received — yiaddr=<ip> dns=<..> mtu=<..> (<n> bytes)` — the Go smoke greps `yiaddr=<ip>`, `mtu=<ip>` (from `--dhcp-mtu`), `dns=`.
  - arp: `ARP reply OK`; nd: `ND NA OK`.
  - dhcpv6: a line containing `ia_addr=<addr>` and `echoed_clientid=<hex>`, then `DHCPv6 OK`.
  - egress: `ENCAP OK`; egress6: `ENCAP6 OK`.
  - failures: a line beginning `RESULT: NO ` (and generally a non-zero exit).
- **Exit codes:** 0 = success/assert-pass, 1 = assertion failed / no reply, 2 = usage error.
- Tap fd: open `/dev/net/tun`, `ioctl(TUNSETIFF, IFF_TAP|IFF_NO_PI)`, raw Ethernet frames (no PI header). `TUNSETIFF=0x400454CA`, `IFF_TAP=0x0002`, `IFF_NO_PI=0x1000`.
- DHCPv6 DUID cap: the datapath echoes the SOLICIT client DUID truncated to **10 bytes** (`D6_MAX_DUID`); the probe asserts `echoed == sent_duid[:10]`.

**Consumers to rewire (Tasks 7–8):** `test/tap-dhcp-probe.sh` (`make tap-dhcp-probe`), `test/tc-dhcp-netns.sh` (4×), `test/tc-egress-netns.sh` (2×), `test/e2e/smoke_lb_dhcp_test.go` (`TestDhcpLeaseSmoke` copies+runs the probe; `TestLbDistributeSmoke` inline scapy).

**Env note:** commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Work happens in the `test/e2e` module (`cd test/e2e` for `go` commands, or `go -C test/e2e`). The `go.work` at repo root ties the modules; run `go build`/`go test` from inside `test/e2e`. No merge/push per task.

---

## Task 1: Scaffold the Go CLI — flag parity + mode dispatch (no packet logic yet)

**Goal:** A buildable `tap-dhcp-probe` binary that parses every flag the Python probe accepts, dispatches to stub mode functions (each returns exit 2 "not implemented yet"), and matches the usage-error exit code (2). Add the deps.

**Files:**
- Create: `test/e2e/cmd/tap-dhcp-probe/main.go`
- Modify: `test/e2e/go.mod`, `test/e2e/go.sum`

- [ ] **Step 1: Add deps.** From the repo root:
```bash
cd test/e2e
go get github.com/google/gopacket@v1.1.19
go get github.com/insomniacslk/dhcp@latest
go get golang.org/x/sys/unix
```
Expected: `go.mod` gains `github.com/google/gopacket`, `github.com/insomniacslk/dhcp`, and `golang.org/x/sys` becomes a direct require.

- [ ] **Step 2: Write `main.go` with full flag parity + stub dispatch.**
```go
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
func egressProbe(tap, peer string, to time.Duration) int                          { return notImpl("egress") }
func egress6Probe(tap, peer, g6, d6, nh6, gul string, to time.Duration) int        { return notImpl("egress6") }
func clientOnlyDHCP(tap, mac, expectIP string, to time.Duration) int               { return notImpl("dhcp") }
func arpProbe(tap, mac, expectIP string, to time.Duration) int                     { return notImpl("arp") }
func ndProbe(tap, mac, gw6 string, to time.Duration) int                           { return notImpl("nd") }
func dhcpv6Probe(tap, mac, expectIP string, to time.Duration) int                  { return notImpl("dhcpv6") }
func selfContained() int                                                           { return notImpl("default") }

func notImpl(mode string) int { fmt.Fprintf(os.Stderr, "not implemented yet: %s\n", mode); return 2 }
```

- [ ] **Step 3: Build.**
```bash
cd test/e2e && go build ./cmd/tap-dhcp-probe && go vet ./cmd/tap-dhcp-probe
```
Expected: builds clean, `go vet` clean. `./tap-dhcp-probe --client-only` (no `--tap`) prints the usage error and exits 2 (`echo $?` → 2). Remove the built binary (`rm -f tap-dhcp-probe`) — it is gitignored/artifact.

- [ ] **Step 4: Commit.**
```bash
git add test/e2e/cmd/tap-dhcp-probe/main.go test/e2e/go.mod test/e2e/go.sum
git commit -m "feat(test): scaffold Go tap-dhcp-probe CLI (flag parity + gopacket/dhcp deps)"
```

---

## Task 2: Packet build/parse pure functions + Go unit tests (TDD)

**Goal:** Pure functions (no I/O) that build and parse every frame the probe needs, with table unit tests doing craft→parse round-trips. This is the byte-logic core; later tasks only add I/O around it.

**Files:**
- Create: `test/e2e/cmd/tap-dhcp-probe/frames.go`, `test/e2e/cmd/tap-dhcp-probe/frames_test.go`

- [ ] **Step 1: Write the failing tests** in `frames_test.go`:
```go
package main

import (
	"net"
	"testing"
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
	// A DISCOVER we built must be recognizable as a BOOTP/DHCP request (message-type 1).
	mt, _, _, _, ok := parseDHCPReply(frame)
	if ok && mt == 2 {
		t.Fatal("our DISCOVER must not parse as an OFFER")
	}
}

func TestParseDHCPOfferFields(t *testing.T) {
	// Build a synthetic OFFER (message-type 2) with yiaddr, MTU (opt 26), DNS (opt 6) and
	// assert parseDHCPReply extracts them. buildDHCPOffer is a TEST helper in frames.go.
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
	// A reply we synthesize (op=2, hwsrc=mac, psrc=gw) must parse as such.
	reply, _ := buildARPReply(mac, net.IPv4(10, 0, 0, 1))
	op, psrc, hwsrc, ok := parseARP(reply)
	if !ok || op != 2 || !psrc.Equal(net.IPv4(10, 0, 0, 1)) || hwsrc.String() != mac.String() {
		t.Fatalf("parse arp reply: op=%d psrc=%v hwsrc=%v ok=%v", op, psrc, hwsrc, ok)
	}
}

func TestEUI64LinkLocal(t *testing.T) {
	got := eui64LinkLocal(mustMAC(t, "52:54:00:00:00:01"))
	want := "fe80::5054:ff:fe00:1"
	if got.String() != want {
		t.Fatalf("eui64: got %s want %s", got, want)
	}
}

func TestDHCPv6SolicitAdvertiseRoundTrip(t *testing.T) {
	mac := mustMAC(t, "52:54:00:00:00:01")
	sol, duid, err := buildDHCPv6Solicit(mac)
	if err != nil {
		t.Fatalf("build solicit: %v", err)
	}
	if len(duid) == 0 {
		t.Fatal("empty duid")
	}
	// Synthesize an ADVERTISE echoing the DUID (capped to 10B) with an IA address, parse it.
	adv, err := buildDHCPv6Advertise(mac, net.ParseIP("2001:db8:1::7"), duid[:min(len(duid), 10)])
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
	_ = sol
}
```
Run: `cd test/e2e && go test ./cmd/tap-dhcp-probe/ 2>&1 | tail` → FAIL (undefined functions).

- [ ] **Step 2: Implement `frames.go`.** Provide these functions (real signatures the tests use):
  - `buildDHCPDiscover(clientMAC net.HardwareAddr, xid uint32) ([]byte, error)` — Ethernet(src=mac,dst=bcast)/IPv4(0.0.0.0→255.255.255.255)/UDP(68→67)/DHCPv4 DISCOVER. Build the DHCPv4 message with `github.com/insomniacslk/dhcp/dhcpv4` (`dhcpv4.New(...)`, set `OpcodeBootRequest`, `MessageTypeDiscover`, ClientHWAddr=mac, xid), `msg.ToBytes()` for the UDP payload; serialize L2–L4 with `gopacket` (`gopacket.SerializeLayers` + `layers.Ethernet/IPv4/UDP`, set `udp.SetNetworkLayerForChecksum(ip)`, `ComputeChecksums: true`).
  - `buildDHCPOffer(clientMAC net.HardwareAddr, yiaddr net.IP, mtu uint16, dns []net.IP) ([]byte, error)` — TEST helper: DHCPv4 OFFER (`MessageTypeOffer`, YourIPAddr=yiaddr, `OptGeneric(OptionInterfaceMTU, mtuBytes)`, `OptDNS(dns...)`), wrapped like the DISCOVER.
  - `parseDHCPReply(frame []byte) (msgType uint8, yiaddr net.IP, mtu uint16, dns []net.IP, ok bool)` — gopacket-decode Ethernet→IPv4→UDP, then `dhcpv4.FromBytes(udp.Payload)`; return `uint8(msg.MessageType())`, `msg.YourIPAddr`, MTU from `OptionInterfaceMTU`, `msg.DNS()`. `ok=false` if not a DHCPv4 packet.
  - `buildARPRequest(srcMAC net.HardwareAddr, srcIP, targetIP net.IP) ([]byte, error)` — Ethernet(src,bcast, EthernetTypeARP)/ARP(op=1, sender=srcMAC/srcIP, target=zeros/targetIP). Pad to 60 bytes (`gopacket.SerializeOptions{FixLengths:true}` then right-pad with zeros to 60).
  - `buildARPReply(hwsrc net.HardwareAddr, psrc net.IP) ([]byte, error)` — TEST helper: ARP op=2 sender=hwsrc/psrc.
  - `parseARP(frame []byte) (op uint16, psrc net.IP, hwsrc net.HardwareAddr, ok bool)`.
  - `buildNS(clientMAC net.HardwareAddr, target net.IP) ([]byte, error)` — Ethernet(src=mac, dst=33:33:00:00:00:01, EthernetTypeIPv6)/IPv6(src=eui64LinkLocal(mac), dst=target, hopLimit 255)/ICMPv6(TypeNeighborSolicitation)/`ICMPv6NeighborSolicitation{TargetAddress:target, Options:[SrcLLAddr=mac]}`. Set `icmp6.SetNetworkLayerForChecksum(ip6)`.
  - `parseNA(frame []byte) (target net.IP, dstLLAddr net.HardwareAddr, ok bool)` — decode to `ICMPv6NeighborAdvertisement`, read Target + the DstLLAddr option (opt type 2).
  - `buildDHCPv6Solicit(clientMAC net.HardwareAddr) (frame []byte, duid []byte, err error)` — Ethernet(src=mac, dst=33:33:00:01:00:02)/IPv6(src=eui64LinkLocal, dst=ff02::1:2, hop 255)/UDP(546→547)/DHCPv6 SOLICIT built with `github.com/insomniacslk/dhcp/dhcpv6` (`dhcpv6.NewSolicit(mac, ...)` or construct: ClientID = `Duid{Type:DUID_LLT, HwType:1, LinkLayerAddr:mac}`, add `OptIANA{IaId:...}`). Return the raw ClientID DUID bytes (for the echoed-DUID compare) via `duid = clientDuid.ToBytes()`.
  - `buildDHCPv6Advertise(clientMAC net.HardwareAddr, ia net.IP, echoDUID []byte) ([]byte, error)` — TEST helper: ADVERTISE with `OptIANA` containing `OptIAAddress{IPv6Addr: ia}`, ClientID DUID = echoDUID (raw), wrapped UDP(547→546)/IPv6/Ether.
  - `parseDHCPv6Reply(frame []byte) (iaAddr net.IP, echoedClientID []byte, ok bool)` — decode Ethernet→IPv6→UDP, `dhcpv6.FromBytes(udp.Payload)`; require msg type Advertise or Reply; `msg.Options.OneIANA().Options.OneAddress().IPv6Addr` for iaAddr; `msg.Options.ClientID().ToBytes()` for echoedClientID.
  - `eui64LinkLocal(mac net.HardwareAddr) net.IP` — flip U/L bit of byte 0, insert `ff:fe`, prefix `fe80::`.
  - `min(a, b int) int` helper if not using Go 1.21 builtin (Go 1.26 has builtin `min` — use it; drop this).

  Constraint: DHCPv6 uses insomniacslk/dhcp/dhcpv6 (models IA_NA→IAAddress and DUID), NOT gopacket's `layers.DHCPv6` (which leaves IANA opaque). Keep all encoding well-formed; byte-parity with scapy is NOT required (the datapath asserts field values + frame growth, not byte-identity).

- [ ] **Step 3: Run — PASS.** `cd test/e2e && go test ./cmd/tap-dhcp-probe/ -v 2>&1 | tail -30`. All round-trip tests pass. `go vet ./cmd/tap-dhcp-probe`.

- [ ] **Step 4: Commit.**
```bash
git add test/e2e/cmd/tap-dhcp-probe/frames.go test/e2e/cmd/tap-dhcp-probe/frames_test.go test/e2e/go.sum
git commit -m "feat(test): tap-dhcp-probe frame build/parse (gopacket + insomniacslk/dhcp) + unit tests"
```

---

## Task 3: Tap-fd I/O + the client-only probes (dhcp/arp/nd/dhcpv6)

**Goal:** Wire the pure functions to a real tap fd and implement the four `--client-only` modes with the exact stdout markers + exit codes. Validated end-to-end by the tc netns gate in Task 7 and the live smoke in Task 10; here the gate is build/vet (I/O needs root + a datapath).

**Files:**
- Create: `test/e2e/cmd/tap-dhcp-probe/tap.go`
- Modify: `test/e2e/cmd/tap-dhcp-probe/main.go` (replace the 4 client-only stubs)

- [ ] **Step 1: Implement `tap.go`** — the tap queue + read loop:
```go
package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	tunSetIff = 0x400454CA
	iffTap    = 0x0002
	iffNoPI   = 0x1000
)

// openTapQueue attaches a NEW queue fd to an EXISTING tap netdev `name` (does not create or
// set it up). Writing injects toward the host RX (tc/XDP ingress fires); reading drains the
// tap egress (where the responder's redirect-to-self delivers the reply). Mirrors the Python
// open_tap_queue via TUNSETIFF with IFF_TAP|IFF_NO_PI (raw ethernet, no packet-info header).
func openTapQueue(name string) (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:unix.IFNAMSIZ], name)
	// flags at offset IFNAMSIZ (little-endian uint16)
	flags := uint16(iffTap | iffNoPI)
	ifr[unix.IFNAMSIZ] = byte(flags)
	ifr[unix.IFNAMSIZ+1] = byte(flags >> 8)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(tunSetIff), uintptr(unsafePtr(&ifr[0]))); e != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF %s: %v", name, e)
	}
	return f, nil
}

// readFrames reads raw frames off the tap fd, invoking match(frame) until it returns true or
// the deadline passes. Uses a read deadline via SetReadDeadline on the *os.File.
func readFrames(f *os.File, timeout time.Duration, match func([]byte) bool) bool {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		_ = f.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := f.Read(buf)
		if err != nil {
			continue // timeout on this slice; loop until overall deadline
		}
		if n > 0 && match(buf[:n]) {
			return true
		}
	}
	return false
}
```
Note: `unsafePtr` is `unsafe.Pointer` — add `import "unsafe"` and a tiny `func unsafePtr(p *byte) unsafe.Pointer { return unsafe.Pointer(p) }`, or inline `unsafe.Pointer(&ifr[0])`. `SetReadDeadline` on `/dev/net/tun` works because the tun fd is pollable; if a platform quirk makes it not, fall back to `unix.SetNonblock(int(f.Fd()), true)` + a `unix.Poll` loop (document if used).

- [ ] **Step 2: Replace the client-only stubs in `main.go`** with real implementations that print the exact markers. Example for dhcp (mirror the Python `client_only`):
```go
func clientOnlyDHCP(tap, mac, expectIP string, to time.Duration) int {
	hw, err := net.ParseMAC(mac)
	if err != nil { fmt.Fprintln(os.Stderr, "bad --client-mac:", err); return 2 }
	f, err := openTapQueue(tap)
	if err != nil { fmt.Fprintln(os.Stderr, err); return 2 }
	defer f.Close()
	disc, err := buildDHCPDiscover(hw, 0x1234)
	if err != nil { fmt.Fprintln(os.Stderr, err); return 2 }
	if _, err := f.Write(disc); err != nil { fmt.Fprintln(os.Stderr, err); return 2 }
	fmt.Printf("sent DHCP DISCOVER (%d bytes) from %s to tap %s\n", len(disc), mac, tap)
	var yi net.IP; var mtu uint16; var dns []net.IP
	got := readFrames(f, to, func(b []byte) bool {
		mt, y, m, d, ok := parseDHCPReply(b)
		if ok && mt == 2 { yi, mtu, dns = y, m, d; return true }
		return false
	})
	if !got { fmt.Printf("RESULT: NO OFFER received on %s within %.0fs\n", tap, to.Seconds()); return 1 }
	fmt.Printf("RESULT: OFFER received — yiaddr=%s dns=%v mtu=%d (%d bytes)\n", yi, dns, mtu, 0)
	if yi.String() != expectIP {
		fmt.Printf("  but expected yiaddr %s, got %s\n", expectIP, yi)
		return 1
	}
	return 0
}
```
Implement `arpProbe` (send `buildARPRequest`, await `parseARP` op==2 with psrc==expectIP && hwsrc==mac → `ARP reply OK` / `RESULT: NO ARP reply …`), `ndProbe` (send `buildNS`, await `parseNA` with dstLLAddr==mac → `ND NA OK` / `RESULT: NO ICMPv6 NA …`), and `dhcpv6Probe` (send `buildDHCPv6Solicit`, await `parseDHCPv6Reply`, assert `iaAddr==expectIP` normalized and `echoedClientID == sentDUID[:min(len,10)]`; print a line with `ia_addr=<addr>` and `echoed_clientid=<hex>` then `DHCPv6 OK`, else `RESULT: NO DHCP6 ADVERTISE/REPLY …`). Use the SAME marker strings the Go smoke greps (`yiaddr=`, `mtu=`, `dns=`, `ia_addr=`, `echoed_clientid=`, `DHCPv6 OK`). Add `import "net"` to main.go.

- [ ] **Step 3: Build + vet.** `cd test/e2e && go build ./cmd/tap-dhcp-probe && go vet ./cmd/tap-dhcp-probe && go test ./cmd/tap-dhcp-probe 2>&1 | tail`. Expected: builds, vets, unit tests still pass. `rm -f tap-dhcp-probe`.

- [ ] **Step 4: Commit.**
```bash
git add test/e2e/cmd/tap-dhcp-probe/tap.go test/e2e/cmd/tap-dhcp-probe/main.go
git commit -m "feat(test): tap-dhcp-probe client-only modes (dhcp/arp/nd/dhcpv6) over a raw tap fd"
```

---

## Task 4: afpacket sniff + the egress / egress6 encap gates

**Goal:** Implement `--egress` and `--egress6`: write an inner frame to the tap, sniff the veth `--peer` with `gopacket/afpacket`, and assert the captured outer IPv6 is correctly encapsulated. Markers `ENCAP OK` / `ENCAP6 OK`.

**Files:**
- Create: `test/e2e/cmd/tap-dhcp-probe/sniff.go`
- Modify: `test/e2e/cmd/tap-dhcp-probe/main.go` (replace the 2 egress stubs)

- [ ] **Step 1: Add the afpacket dep.** `cd test/e2e && go get github.com/google/gopacket/afpacket` (part of the gopacket module; ensures it's pulled).

- [ ] **Step 2: Implement `sniff.go`** — an AF_PACKET sniffer that pre-arms before injection:
```go
package main

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

// sniffIPv6 opens an afpacket handle on iface, pre-arms (the caller injects AFTER this returns),
// and collects raw frames that decode to an OUTER IPv6 until `want` is satisfied or timeout.
// Returns the raw frames captured. The pre-arm + a short settle mirror the Python AsyncSniffer
// start + 0.5s sleep so the injected frame is not missed.
func sniffIPv6(iface string, timeout time.Duration, inject func() error, want func(pkt gopacket.Packet) bool) ([]gopacket.Packet, error) {
	h, err := afpacket.NewTPacket(afpacket.OptInterface(iface))
	if err != nil {
		return nil, err
	}
	defer h.Close()
	time.Sleep(500 * time.Millisecond) // settle so the ring is armed
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
```

- [ ] **Step 3: Implement `egressProbe` / `egress6Probe` in `main.go`.**
  - `egressProbe(tap, peer, to)`: open tap queue; `inject` writes `buildInnerIPv4ICMP()` (Ethernet 52:54:00:00:00:01→aa:aa:aa:aa:aa:aa / IPv4 10.0.0.1→10.0.0.2 / ICMP echo) to the tap; `want` checks the captured packet's outer IPv6 has `NextHeader==4` (IPIP), `SrcIP==fc00:1::1`, `DstIP==fc00:2::2`, and the inner (second) IPv4 layer is `10.0.0.1→10.0.0.2`. Print `captured %d bytes …`, `ENCAP OK` on success, else `RESULT: NO IPv6 frame captured …` / `RESULT: captured frame(s) not correctly encapsulated …`.
  - `egress6Probe(tap, peer, guest6, dst6, nexthop6, guestUnderlay, to)`: inject `buildInnerIPv6ICMP6(guest6, dst6)`; `want` checks outer IPv6 `NextHeader==41` (IPv6-in-IPv6), `SrcIP==guestUnderlay`, `DstIP==nexthop6`, inner IPv6 `dst==dst6`. Compare IPs with `net.IP.Equal` (handles compressed forms). Print `ENCAP6 OK` / the `RESULT: …` failures.
  - Add `buildInnerIPv4ICMP()` and `buildInnerIPv6ICMP6(src, dst string)` to `frames.go` (gopacket serialize; ICMP/ICMPv6 echo request). For nested-IPv6 parse, use `gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)` and walk `Layers()` for the two IPv6 layers.

- [ ] **Step 4: Build + vet + unit-test the inner builders.** Add a `frames_test.go` case asserting `buildInnerIPv4ICMP()`/`buildInnerIPv6ICMP6` parse back to the expected inner addresses. `cd test/e2e && go test ./cmd/tap-dhcp-probe && go vet ./cmd/tap-dhcp-probe`. `rm -f tap-dhcp-probe`.

- [ ] **Step 5: Commit.**
```bash
git add test/e2e/cmd/tap-dhcp-probe/sniff.go test/e2e/cmd/tap-dhcp-probe/main.go test/e2e/cmd/tap-dhcp-probe/frames.go test/e2e/cmd/tap-dhcp-probe/frames_test.go
git commit -m "feat(test): tap-dhcp-probe egress/egress6 encap gates via afpacket sniff"
```

---

## Task 5: Default self-contained native-mode DHCP probe

**Goal:** Implement the no-flag mode: create `dhg0`/`dhu0` taps, run `flowplane bringup` (NATIVE), write a DISCOVER, assert a grown OFFER (`yiaddr=10.0.0.50`, `interface-mtu=1337`, len>DISCOVER) — the native `adjust_tail` fidelity proof. Reports the attach mode (native/driver vs skb/generic).

**Files:**
- Modify: `test/e2e/cmd/tap-dhcp-probe/main.go` (replace `selfContained`), `test/e2e/cmd/tap-dhcp-probe/tap.go` (add `mkTap`)

- [ ] **Step 1: Add `mkTap(name)`** to `tap.go` — like `openTapQueue` but then `ip link set <name> up` (via `os/exec`) and best-effort `ethtool -K <name> gro off tso off gso off` (ignore if ethtool absent). Return the `*os.File`.

- [ ] **Step 2: Implement `selfContained()` in main.go** mirroring the Python `main()` default path:
  - `BIN := "target/debug/flowplane"` relative to repo root (resolve: the probe runs from repo root under sudo in `tap-dhcp-probe.sh`; accept an env override `FLOWPLANE_BIN` else default `./target/debug/flowplane`). If missing → `fmt.Fprintln(os.Stderr, "ERROR: <bin> missing — run: cargo build -p flowplane")`, return 2.
  - `mkTap("dhg0")`, `mkTap("dhu0")`; read the MACs from `/sys/class/net/<n>/address`.
  - Start `flowplane bringup --uplink dhu0 --local-underlay fd00::1 --gateway 10.0.0.1 --gateway-mac <umac> --guest dhg0=10.0.0.50=<gmac>=fd00:a::50=0 --dhcp-mtu 1337 --dhcp-dns 8.8.4.4 --dhcp-dns 8.8.8.8` via `exec.Command`, stdout/stderr → `/tmp/dhcp-probe-bringup.log`. `time.Sleep(2s)`.
  - `ip -d link show dhg0` → mode = `skb/generic` if output contains `xdpgeneric`, else `native/driver` if contains `xdp`, else `NONE`. Print `guest_tx attach mode on dhg0: <mode>`.
  - Write DISCOVER from `02:aa:bb:cc:dd:ee` to the dhg0 fd; read OFFER (msg-type 2) within 3s using `parseDHCPReply`.
  - Terminate bringup (`cmd.Process.Signal(SIGTERM)`, wait, kill on timeout); `ip link del dhg0`, `ip link del dhu0`.
  - Print the RESULT block: on no OFFER → `RESULT: NO OFFER received in <mode> mode` + the two guidance lines, return 1. On OFFER → `RESULT: OFFER received in <mode> mode`, the size/yiaddr/mtu lines, then if `yiaddr==10.0.0.50 && mtu==1337 && len(offer)>len(disc) && mode=="native/driver"` print the PROVEN lines and return 0; else return 0 if the values are ok else 1. Keep the exact `RESULT:`/`->` marker text from the Python so behavior is recognizable.

- [ ] **Step 3: Build + vet.** `cd test/e2e && go build ./cmd/tap-dhcp-probe && go vet ./cmd/tap-dhcp-probe && go test ./cmd/tap-dhcp-probe 2>&1 | tail`. `rm -f tap-dhcp-probe`.

- [ ] **Step 4: Commit.**
```bash
git add test/e2e/cmd/tap-dhcp-probe/main.go test/e2e/cmd/tap-dhcp-probe/tap.go
git commit -m "feat(test): tap-dhcp-probe default self-contained native-mode DHCP fidelity probe"
```

---

## Task 6: LB traffic-distribution sniff subcommand

**Goal:** A mode for `TestLbDistributeSmoke`: send N ICMP frames with varying outer-src to an iface, sniff re-encapped frames, and assert both backend underlays appear as outer-dst. Marker `DISTRIBUTION_OK` / `DISTRIBUTION_FAIL`.

**Files:**
- Modify: `test/e2e/cmd/tap-dhcp-probe/main.go` (add `--lb-distribute` flag + handler), `test/e2e/cmd/tap-dhcp-probe/frames.go` (frame builder)

- [ ] **Step 1: Add flags + dispatch** to `main.go`: `--lb-distribute` (bool), `--iface` (default `eth1`), `--lb-underlay`, `--be1`, `--be2`, `--vip`, `--count` (default 10). Dispatch before the other modes.
- [ ] **Step 2: Implement `lbDistribute(iface, lbUnderlay, be1, be2, vip string, count int, to time.Duration) int`.** Pre-arm `sniffIPv6` on `iface` filtering to outer-dst ∈ {be1, be2}; inject `count` frames `Ether()/IPv6(src=fd00:db8:9::<i+1>, dst=lbUnderlay)/IPv4(dst=vip, src=198.51.100.1)/ICMP(id=i,seq=i)` via `buildLbProbeFrame(i, lbUnderlay, vip)`; collect the set of captured outer-dst IPs; if `{be1,be2} ⊆ seen` → `DISTRIBUTION_OK: …` return 0 else `DISTRIBUTION_FAIL: …` return 1. Reuse `sniffIPv6` (generalize its `want` to "both backends seen").
- [ ] **Step 3: Build + vet + a unit test** for `buildLbProbeFrame` (parses back to outer IPv6 dst=lbUnderlay, inner IPv4 dst=vip). `cd test/e2e && go test ./cmd/tap-dhcp-probe && go vet ./cmd/tap-dhcp-probe`. `rm -f tap-dhcp-probe`.
- [ ] **Step 4: Commit.**
```bash
git add test/e2e/cmd/tap-dhcp-probe/main.go test/e2e/cmd/tap-dhcp-probe/frames.go test/e2e/cmd/tap-dhcp-probe/frames_test.go
git commit -m "feat(test): tap-dhcp-probe LB traffic-distribution sniff mode"
```

---

## Task 7: Rewire the bash consumers (build + run the Go binary)

**Goal:** `tap-dhcp-probe.sh`, `tc-dhcp-netns.sh`, `tc-egress-netns.sh` build and invoke the Go binary instead of `python3 …py`. Same flags.

**Files:** `test/tap-dhcp-probe.sh`, `test/tc-dhcp-netns.sh`, `test/tc-egress-netns.sh`.

- [ ] **Step 1: Add a shared build helper** — in each script, replace the `PYBIN=…python3` resolution with building the Go binary once:
```bash
# Build the Go probe (pure-Go, cgo-free) once; PROBE is the binary consumers invoke.
PROBE="${ROOT}/test/e2e/tap-dhcp-probe.bin"
( cd "${ROOT}/test/e2e" && CGO_ENABLED=0 go build -o "$PROBE" ./cmd/tap-dhcp-probe )
```
(For `tc-*-netns.sh`, `$ROOT` is already computed; ensure `$PROBE` is built before the netns invocations.)
- [ ] **Step 2: `tap-dhcp-probe.sh`** — replace `sudo "$PYBIN" "$ROOT/test/tap-dhcp-probe.py"` with `sudo "$PROBE"` (default self-contained mode). Keep the `cargo build -p flowplane` + the dhg0/dhu0 pre-clean. Update the header comment (no scapy; Go probe).
- [ ] **Step 3: `tc-dhcp-netns.sh`** — replace each of the 4 `sudo ip netns exec "$NS" "$PYBIN" "$ROOT/test/tap-dhcp-probe.py" <flags>` with `sudo ip netns exec "$NS" "$PROBE" <same flags>`. Flags unchanged (`--client-only [--probe arp|nd|dhcpv6] --tap … --client-mac … --expect-ip/--gateway6/--guest6 … --timeout 4`).
- [ ] **Step 4: `tc-egress-netns.sh`** — replace the 2 invocations (`--egress …`, `--egress6 …`) with `"$PROBE"`, flags unchanged.
- [ ] **Step 5: Gitignore the built binary.** Add `test/e2e/tap-dhcp-probe.bin` to `.gitignore` (or `test/e2e/.gitignore`). Verify `bash -n` on all three scripts.
- [ ] **Step 6: Commit.**
```bash
git add test/tap-dhcp-probe.sh test/tc-dhcp-netns.sh test/tc-egress-netns.sh .gitignore
git commit -m "refactor(test): bash probe consumers build+run the Go tap-dhcp-probe (drop python)"
```

---

## Task 8: Rewire the Go smoke tests (drop scapy-in-node)

**Goal:** `TestDhcpLeaseSmoke` builds the Go binary, `docker cp`s it into the node, and runs it (no python3/scapy, no skip). `TestLbDistributeSmoke` uses the binary's `--lb-distribute` mode.

**Files:** `test/e2e/smoke_lb_dhcp_test.go`.

- [ ] **Step 1: Add a build helper** in the test file (or a shared `test/e2e` helper): build a static linux binary the node can run:
```go
// buildProbeBinary compiles the tap-dhcp-probe CLI to a static binary for the node arch and
// returns its host path. The kind node is linux/amd64 = the host here, so a plain CGO_ENABLED=0
// build is node-runnable.
func buildProbeBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "tap-dhcp-probe")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/tap-dhcp-probe")
	cmd.Dir = "." // test working dir is the test/e2e module root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if o, err := runWithTimeout(cmd, 2*time.Minute); err != nil {
		t.Fatalf("build tap-dhcp-probe: %v\n%s", err, o)
	}
	return out
}
```
- [ ] **Step 2: `TestDhcpLeaseSmoke`** — replace step 6 (`docker cp probeScriptPath …tap-dhcp-probe.py`) with: `probeBin := buildProbeBinary(t)` then `docker cp probeBin node:/tmp/tap-dhcp-probe`. Replace the two `python3 /tmp/tap-dhcp-probe.py <flags>` invocations (dhcpv4Cmd, dhcpv6Cmd) with `/tmp/tap-dhcp-probe <same flags>`. The grep markers (`yiaddr=`, `mtu=`, `dns=`, `ia_addr=`, `echoed_clientid=`, `DHCPv6 OK`/`OK`) are already produced by the Go binary (Task 3). Keep all assertions.
- [ ] **Step 3: `TestLbDistributeSmoke`** — remove the `scapyCheck`/skip block (lines ~166–180) and the inline `distScript` python heredoc (~186–229). Replace with: `docker cp buildProbeBinary(t) node:/tmp/tap-dhcp-probe` (or reuse a binary already copied) and run `/tmp/tap-dhcp-probe --lb-distribute --iface eth1 --lb-underlay <..> --be1 <..> --be2 <..> --vip <..> --count 10`; parse `DISTRIBUTION_OK`. Keep the existing best-effort semantics (soft-fail/log on no traffic; the gRPC round-trip is the hard assertion). Update the doc comment (no scapy).
- [ ] **Step 4: Build + vet.** `cd test/e2e && go build ./... && go vet ./...`. (Do NOT run the live test here — that's Task 10.) Ensure no lingering references to `tap-dhcp-probe.py` in the file.
- [ ] **Step 5: Commit.**
```bash
git add test/e2e/smoke_lb_dhcp_test.go
git commit -m "refactor(test): smoke tests build+cp the Go probe into the node (drop scapy-in-node + skip)"
```

---

## Task 9: Delete the Python, drop scapy+pytest from the flake, de-stale docs

**Goal:** Remove `test/tap-dhcp-probe.py`, drop `pythonEnv` (scapy+pytest) from the flake (python3 remains via pyelftools), and fix stale docs.

**Files:** delete `test/tap-dhcp-probe.py`; `flake.nix`; `README.md`; `Makefile`; `docs/src/architecture/layout.md`, `docs/src/contributing/dev.md`, `docs/src/ops/getting-started.md`, `docs/src/testing/*`, `test/conformance-map.md`, `docs/src/testing/conformance-map.md`.

- [ ] **Step 1: Delete the Python probe.** `git rm test/tap-dhcp-probe.py`.
- [ ] **Step 2: flake.nix** — remove the `pythonEnv = pkgs.python3.withPackages (ps: with ps; [ scapy pytest ]);` binding (lines ~27–29) and its `pythonEnv` entry in `buildInputs` (~line 113). Leave `pkgs.python3Packages.pyelftools` (DPDK build) untouched. Update the comment near pyelftools to note it's the only python left (DPDK meson build dep).
- [ ] **Step 3: Verify the flake still evaluates + scapy is gone.**
```bash
nix develop --command bash -c 'python3 -c "import scapy" 2>&1; echo scapy_rc=$?; command -v python3 >/dev/null && echo python3_present'
```
Expected: `import scapy` fails (`ModuleNotFoundError`, non-zero rc) but `python3_present` prints (pyelftools keeps python3). If the whole devShell fails to build, fix the flake edit.
- [ ] **Step 4: De-stale docs + Makefile.** Replace "python3 + scapy + pytest" phrasings with "Go (gopacket) packet probe; python3 only for the DPDK build (pyelftools)":
  - `README.md:60`, `docs/src/architecture/layout.md:20`, `docs/src/contributing/dev.md:13`, `docs/src/ops/getting-started.md:26`.
  - `Makefile:4` toolchain comment; the `tap-dhcp-probe` target help text if it mentions scapy.
  - `test/conformance-map.md` + `docs/src/testing/conformance-map.md` (~lines 214, 218) and `docs/src/testing/strategy.md:55`: the "goscapy smoke / Python DHCPv6 test must remain" gating note — update to "the Go tap-dhcp-probe (`test/e2e/cmd/tap-dhcp-probe`) is the DHCPv6 conformance; the Python probe is removed."
- [ ] **Step 5: Grep clean.** `git grep -nIE 'scapy|pytest|tap-dhcp-probe\.py' -- ':!docs/superpowers'` returns only intentional/historical mentions (superpowers plans are historical — leave them). No live script/flake/Makefile/test references remain.
- [ ] **Step 6: Commit.**
```bash
git add -A
git commit -m "chore: drop scapy+pytest (Go probe replaces the Python) + de-stale docs; python3 stays for DPDK pyelftools"
```

---

## Task 10: Full validation + finish

**Goal:** Prove the Go probe replaces scapy across every gate, then finish the branch.

- [ ] **Step 1: Unit + build.** `cd test/e2e && go test ./cmd/tap-dhcp-probe -v && go build ./... && go vet ./...` → all green.
- [ ] **Step 2: Native fidelity gate (local, sudo).** `make tap-dhcp-probe` → prints `guest_tx attach mode on dhg0: native/driver` and `RESULT: OFFER received in native/driver mode` with `yiaddr=10.0.0.50`, `interface-mtu=1337`. Chown any root-owned `target/` artifacts back if needed.
- [ ] **Step 3: tc netns gates (local, sudo, in nix develop).** `nix develop -c ./test/tc-dhcp-netns.sh` → `DHCP OFFER OK`, `ARP reply OK`, `ND NA OK`, DHCPv6 ADVERTISE OK (final `PASS`). `nix develop -c ./test/tc-egress-netns.sh` → `ENCAP OK` + `ENCAP6 OK`. (If a gate was already red on main before this change for unrelated reasons, note it — do not block on pre-existing datapath issues, only on probe-mechanism regressions.)
- [ ] **Step 4: Live fabric — primary DHCPv6 conformance.** From a plain `nix develop` as the user: bring the fabric up if down (`hack/clab-up.sh`), then `go test ./test/e2e/... -run 'TestDhcpLeaseSmoke|TestLbDistributeSmoke' -v -timeout 30m`. Expected: `TestDhcpLeaseSmoke` PASS (DHCPv4 yiaddr/MTU/DNS + **DHCPv6** ia_addr/echoed ClientId, with NO scapy in the node); `TestLbDistributeSmoke` PASS or the documented best-effort soft-pass. Tear down with `hack/clab-down.sh` after (or leave up per preference).
- [ ] **Step 5: Flake proof.** `nix develop -c bash -c 'python3 -c "import scapy" 2>&1 | tail -1; echo rc=$?'` → ModuleNotFoundError / non-zero. DPDK still builds: `nix develop -c bash -c 'cd flowplane && cargo build -p flowplane-dpdk 2>&1 | tail -3'` → builds (pyelftools present).
- [ ] **Step 6: Finish the branch** (superpowers:finishing-a-development-branch) — merge `--no-ff` to main + push per the usual pattern; update memory (the `python leftover` finding → resolved: scapy/pytest dropped, python3 kept for DPDK).

## Notes / risks
- **DHCPv6 (Task 2) is the maturity-sensitive part** — insomniacslk/dhcp fully models DUID/IA_NA/IAAddress, so this should be robust, but Step 4's live DHCPv6 conformance is the real gate; if the echoed-DUID 10-byte cap or IA address parse is off, fix in `frames.go` and re-run Step 4.
- **afpacket** needs `CAP_NET_RAW` (the gates already run under sudo / the node is privileged).
- Keep the Python probe until Task 9 — every task 1–8 leaves the old probe in place so the harness is never broken mid-port (the consumers only switch to the Go binary in Tasks 7–8, and the `.py` is deleted only in Task 9).
- The tc-*-netns.sh gates are manual (not make/CI wired); run them in Step 3 but treat pre-existing datapath failures (unrelated to the probe) as out-of-scope.
