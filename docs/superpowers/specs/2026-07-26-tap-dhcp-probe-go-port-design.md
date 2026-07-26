# Port the scapy DHCP/packet probe to Go (gopacket) — drop the scapy+pytest deps

**Date:** 2026-07-26
**Status:** Approved (brainstorming)
**Context:** `test/tap-dhcp-probe.py` (scapy) is the last Python in the repo we own. It drives the
in-XDP DHCP responder + ARP/ND + encap gates over a raw tap fd, and is the PRIMARY DHCPv6
conformance path (the eBPF DHCPv6 responder can't be covered by the sim — verifier instruction
limit). It has five consumers. `scapy` + `pytest` sit in the flake's `pythonEnv` for it; `pytest`
already has zero test files (dead leftover). Porting the probe to Go lets us drop `scapy`+`pytest`
and gives an all-Go test harness that needs no python/scapy inside the kind node.

**Not achievable / out of scope:** removing `python3` entirely. `flowplane/dpdk-sys/build.rs`
builds DPDK locally with meson, which requires `python3Packages.pyelftools` — a hard DPDK build
dep that transitively keeps `python3`. This port drops `scapy`+`pytest` only; `python3` survives
via `pyelftools`.

## Goal

Replace `test/tap-dhcp-probe.py` with a pure-Go, cgo-free CLI binary that is a **literal drop-in**
(same flags, same stdout markers, same exit codes) for all five consumers, then remove `scapy` +
`pytest` from the flake and de-stale the docs. No datapath change; no change to what is validated.

## Current consumers (all must be ported — any remaining scapy user keeps scapy in the flake)

1. `make tap-dhcp-probe` → `test/tap-dhcp-probe.sh` — default **self-contained** mode: creates two
   taps (`dhg0`/`dhu0`), runs `flowplane bringup` in NATIVE mode, writes a DHCP DISCOVER to the tap
   fd, asserts a grown OFFER (`yiaddr=10.0.0.50`, `interface-mtu=1337`, len>DISCOVER) comes back —
   the native-mode `bpf_xdp_adjust_tail` fidelity proof.
2. `test/tc-dhcp-netns.sh` — `--client-only --probe {dhcp,arp,nd,dhcpv6}` (4 invocations): the
   tc-BPF guest-edge Phase-1/2 gate (DISCOVER→OFFER, ARP who-has→reply, NS→NA, SOLICIT→ADVERTISE).
3. `test/tc-egress-netns.sh` — `--egress` (inner IPv4 → assert IPIP-encapped on `--peer`) and
   `--egress6` (inner IPv6 → assert IPv6-in-IPv6 encapped), sniffing the veth peer.
4. `test/e2e/smoke_lb_dhcp_test.go::TestDhcpLeaseSmoke` — `docker cp`s the probe into the kind node
   and runs `--client-only` dhcp + dhcpv6. **Primary DHCPv6 conformance.** Today needs python3+scapy
   in the node and skips if scapy is absent — the Go binary removes that fragility.
5. `test/e2e/smoke_lb_dhcp_test.go::TestLbDistributeSmoke` — a separate inline-scapy block that
   sniffs LB traffic distribution across backends. Best-effort today; **ported to Go** (not dropped).

## Design

### 1. Component & placement
New Go CLI at `test/e2e/cmd/tap-dhcp-probe/` in the existing `test/e2e` module (Go 1.26, in the
`go.work`) — the same module as its Go-test consumers (4 & 5). Built to a **static, cgo-free**
binary. It replicates the Python CLI exactly:
`--client-only`, `--probe {dhcp,arp,nd,dhcpv6}`, `--egress`, `--egress6`, `--tap`, `--peer`,
`--client-mac`, `--expect-ip`, `--guest6`, `--dst6`, `--nexthop6`, `--guest-underlay`,
`--gateway6`, `--timeout`, and the default (no-flag) self-contained mode. Same stdout markers
(`OFFER received…`, `ARP reply OK`, `ND NA OK`, `DHCPv6 OK`, `ENCAP OK`, `ENCAP6 OK`,
`RESULT: NO …`) and same exit codes (0 ok, 1 assertion fail, 2 usage), because the bash gates
grep the output and check `$?`.

### 2. Packet mechanics — single dep: `gopacket`
- **tap fd I/O** — open `/dev/net/tun`, `ioctl(TUNSETIFF, IFF_TAP|IFF_NO_PI)` via
  `golang.org/x/sys/unix` (already an indirect dep), then `Read`/`Write` raw Ethernet frames
  (mirrors the Python `os.read`/`os.write` on the held fd). `select`→`SetReadDeadline` on the fd
  for the timeout loops. This is the native-mode path — no socket in the way.
- **craft/parse** — `github.com/google/gopacket` + `gopacket/layers`: Ethernet, IPv4, IPv6, UDP,
  ARP, ICMPv6 + `ICMPv6NeighborSolicitation`/`Advertisement` + NDP options (SrcLLAddr/DstLLAddr),
  DHCPv4 (BOOTP/options), DHCPv6 (Solicit/Advertise/Reply, DUID-LLT ClientId, IA_NA, IAAddress).
  Frame growth/length assertions compare raw byte lengths as the Python does.
- **sniff on veth peer** (`--egress`, `--egress6`, LB distribution) — `gopacket/afpacket`
  (pure-Go AF_PACKET, no libpcap): open on `--peer`, filter to IPv6 frames, parse the outer
  IPv6 (nh=4 IPIP / nh=41 IPv6-in-IPv6, src/dst underlay) and inner IP(v6).
- **EUI-64 link-local** derivation, IPv6 normalization for compares, and the DUID 10-byte cap
  (`D6_MAX_DUID`) assertion are ported 1:1.
- `github.com/insomniacslk/dhcp` is a **documented fallback** used ONLY if gopacket's DHCPv6
  option build/parse proves insufficient during implementation — the goal is a single new dep.

### 3. Consumer rewiring (drop-in)
- `test/tap-dhcp-probe.sh` — build the binary (`go build` in `test/e2e`, or a prebuilt path) and
  run it under sudo instead of `python3 …py`. Still builds `flowplane` first.
- `test/tc-dhcp-netns.sh`, `test/tc-egress-netns.sh` — replace `"$PYBIN" "$ROOT/…py"` with the
  built binary path; flags unchanged.
- `TestDhcpLeaseSmoke` — build the binary for the node arch, `docker cp` it in, run it; drop the
  python3/scapy-presence check and the associated skip. DHCPv6 conformance no longer optional.
- `TestLbDistributeSmoke` — replace the inline `python3 - <<PYEOF` scapy block with the binary's
  sniff mode (or a small helper subcommand); keep the existing best-effort semantics
  (skip/soft-fail if no traffic) but with no scapy dependency.
- Delete `test/tap-dhcp-probe.py`.

### 4. flake + docs
- `flake.nix` — remove the `pythonEnv = python3.withPackages ([ scapy pytest ])` binding and its
  `buildInputs` entry. Keep `pkgs.python3Packages.pyelftools` (DPDK build; it pulls its own
  python3). Net: `scapy`+`pytest` gone, `python3` remains via pyelftools.
- `test/e2e/go.mod` — add `github.com/google/gopacket` (+ `insomniacslk/dhcp` only if used);
  `go mod tidy`.
- De-stale mentions of "python3 + scapy + pytest" in `README.md`, `docs/src/**`, and the
  `Makefile` comment → "Go (gopacket) packet probe; python3 only for the DPDK build (pyelftools)".
  Update `test/conformance-map.md` / `docs/src/testing/*` notes that gate deletion on a "goscapy
  smoke" — that smoke is now this Go probe.

### 5. Testing / validation
- **Build/vet:** `go build ./... && go vet ./...` in `test/e2e` clean; binary builds static.
- **Native gate:** `make tap-dhcp-probe` (under sudo) → `OFFER received in native/driver mode`,
  yiaddr/mtu correct — the same green as the Python probe.
- **tc gates:** `nix develop -c ./test/tc-dhcp-netns.sh` → DHCP+ARP+ND+DHCPv6 PASS;
  `./test/tc-egress-netns.sh` → ENCAP + ENCAP6 OK.
- **Live fabric (primary DHCPv6 conformance):** `TestDhcpLeaseSmoke` on the clab fabric → DHCPv4
  (yiaddr, MTU, DNS) and DHCPv6 (IA addr, echoed ClientId) assertions green with NO scapy in the
  node. `TestLbDistributeSmoke` runs its Go sniff.
- **Flake:** `nix develop -c bash -c 'python3 -c "import scapy" ; echo $?'` → non-zero (scapy
  gone); `nix develop` still provides the DPDK build (pyelftools present).

## Risks / mitigations
- **DHCPv6 in gopacket** is the maturity risk (echoed DUID cap, IA_NA/IAAddress build+parse). If
  gopacket can't express it cleanly, fall back to `insomniacslk/dhcp` for the DHCP layer only —
  the design permits it. This is the primary conformance path, so it must be live-validated before
  the Python is deleted.
- **Frame byte-exactness** — the datapath asserts specific grown lengths / option presence, not
  full byte-parity, so gopacket's encoding need only be well-formed, not byte-identical to scapy.
- **afpacket timing** — the sniff must start before the injected frame (the Python sleeps 0.5s
  after `AsyncSniffer.start()`); replicate the pre-arm + settle.
- **Breaking the harness** — mitigation: drop-in CLI parity + the from-real validation gates above
  are the acceptance bar; port mode-by-mode and keep the Python until every gate is green in Go.

## Out of scope
- Removing `python3`/`pyelftools` (DPDK build dep — separate, bigger decision).
- Any datapath / eBPF change; any change to what the probes assert.
