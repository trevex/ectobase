# Port the remaining scapy harnesses to Go (finish dropping scapy) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (fresh subagent per task + review). Steps use `- [ ]`. Same branch as the tap-dhcp-probe port: `feat/tap-dhcp-probe-go-port` (scapy already removed from the flake in commit `9226122`; these tasks make that valid by porting the 5 remaining scapy consumers).

**Goal:** Replace the inline-scapy `python3 - <<PY` blocks in the 5 remaining harnesses with a pure-Go, cgo-free `netprobe` CLI so the flake truly has no scapy.

**Architecture:** A shared pure-Go package `test/e2e/internal/netpkt` (AF_PACKET raw-socket send/sniff + `gopacket/pcapgo` pcap read/write + `gopacket/layers` craft/parse) and one multi-subcommand CLI `test/e2e/cmd/netprobe` with subcommands tailored to each heredoc's job. Each harness builds the static binary once (`CGO_ENABLED=0`) and calls it instead of `python3`.

**Tech Stack:** Go 1.26 (`test/e2e` module), gopacket + gopacket/pcapgo (pure Go), golang.org/x/sys/unix. No cgo (must `docker cp`/run in minimal envs and build static).

**The 5 consumers (read each file's `python3 - <<'PY'` block before porting — preserve its exact assertions + stdout/exit behavior):**
1. `flowplane/nfkit/tests/l2fwd_pcap.rs` — Rust `#[test]` that shells `python3 -c` with `rdpcap`: asserts `len(in)==len(out)==4` and each out frame `dst==in.src && src==in.dst` (MAC swap), prints `OK`.
2. `test/edge-netns.sh` — two `ip netns exec … python3 - <<PY` blocks using `rdpcap`: (a) find a pkt with `IPv6.dst==owner && IPv6.nh==4 && IP.dst==nat_ip` → `PASS: RETURN …` exit 0 else exit 1; (b) find `IP.src==nat_ip && IP.dst==ext_dst && no IPv6` → `PASS: EGRESS …` exit 0 else 1. Plus any inject blocks.
3. `hack/dpdk/afxdp-loopback.sh` — sends UDP frames (`sendp`) and/or sniffs (`AsyncSniffer`). Read the full block.
4. `hack/dpdk/afxdp-uplink.sh` — `rdpcap` an input pcap, `sendp` (replay) to an iface, `wrpcap` the captured output.
5. `hack/dpdk/serve-e2e.sh` — the hairiest: parts A (inject guest egress Ether/IP/TCP, `AsyncSniffer` the uplink, assert outer `IPv6.nh==4`, extract inner `TCP.sport`, assert in `[pmin,pmax]`), B (nat-return inject+sniff), C [stretch, guarded by `SERVE_E2E_GUEST2GUEST=1`] (guest→guest sniff count). Read it fully.

**Env note:** commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Run `go` from `cd test/e2e`. Build the tool with `CGO_ENABLED=0`. No merge/push per task.

---

## Task 1: Shared `netpkt` package + `netprobe` scaffold + `pcap-verify` subcommand

**Files:** create `test/e2e/internal/netpkt/netpkt.go`, `test/e2e/internal/netpkt/netpkt_test.go`, `test/e2e/cmd/netprobe/main.go`, `test/e2e/cmd/netprobe/pcapverify.go`.

- [ ] **Step 1: `netpkt` package** (pure Go, cgo-free). Refactor the AF_PACKET raw-socket send/sniff out of `test/e2e/cmd/tap-dhcp-probe/sniff.go` into reusable helpers here (keep the probe's copy working — do NOT break it; you may leave the probe's sniff.go as-is or have it import netpkt, but simplest: copy the logic, don't touch the probe):
  - `Send(iface string, frame []byte) error` — AF_PACKET `unix.Socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` + `Sendto(SockaddrLinklayer{Ifindex})`.
  - `Sniff(iface string, timeout time.Duration, arm func() error, match func(gopacket.Packet) bool) ([]gopacket.Packet, error)` — bind AF_PACKET, `SO_RCVTIMEO` 200ms, sleep 500ms settle, call `arm()` (optional injector; may be nil), then read+`gopacket.NewPacket` until `match` true or deadline; return all packets seen.
  - `ReadPcap(path string) ([]gopacket.Packet, error)` — `pcapgo.NewReader` over an `os.Open`; loop `ReadPacketData` → `gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)`.
  - `WritePcap(path string, pkts [][]byte) error` — `pcapgo.NewWriter`, `WriteFileHeader(65536, layers.LinkTypeEthernet)`, write each with a `gopacket.CaptureInfo`.
  - `htons(uint16) uint16` helper.
  - `cd test/e2e && go get github.com/google/gopacket/pcapgo` if the sub-package needs pulling (it's part of gopacket v1.1.19 — pure Go).
- [ ] **Step 2: `netpkt_test.go`** — a WritePcap→ReadPcap round-trip: write 2 known frames (build with gopacket layers Ethernet/IPv4), read them back, assert count==2 and the first frame's Ethernet src/dst match. Run `go test ./internal/netpkt` → PASS.
- [ ] **Step 3: `netprobe` scaffold + `pcap-verify`.** `cmd/netprobe/main.go`: subcommand dispatch on `os.Args[1]` (`pcap-verify`, later `send`, `send-sniff`, `pcap-replay`); unknown → usage + exit 2. `pcapverify.go`: flags `--pcap` (or `--in`/`--out` for two-file compares), `--mac-swap` (bool: assert len(in)==len(out)==N and out[i].eth.dst==in[i].eth.src && src==dst), `--count N`, and single-pcap predicate flags: `--want-outer-ipv6-nh <n>`, `--want-outer-ipv6-dst <ip>`, `--want-inner-ip-src <ip>`, `--want-inner-ip-dst <ip>`, `--want-no-ipv6` (bool). Semantics: for a single `--pcap`, PASS (exit 0, print a `PASS: …` line) if AT LEAST ONE packet matches ALL specified predicates; else print a `no matching pkt in <n> captured` line + each pkt summary and exit 1. For `--mac-swap` with `--in`/`--out`, assert the swap over `--count` frames, print `OK`, exit 0, else exit 1. Use `netpkt.ReadPcap` + gopacket layer accessors (outer = first IPv6 layer; inner IP = the IPv4 layer; `--want-no-ipv6` means no IPv6 layer present).
- [ ] **Step 4: Build + test.** `cd test/e2e && CGO_ENABLED=0 go build ./cmd/netprobe ./internal/netpkt && go vet ./cmd/netprobe ./internal/netpkt && go test ./internal/netpkt && gofmt -l cmd/netprobe internal/netpkt` (empty). Confirm static: `CGO_ENABLED=0 go build -o /tmp/np ./cmd/netprobe && file /tmp/np` shows statically linked / no `/nix/store` interpreter; `rm /tmp/np`.
- [ ] **Step 5: Commit** — `feat(test): netpkt pure-Go send/sniff/pcap pkg + netprobe pcap-verify subcommand`.

---

## Task 2: Port the pcap-verify consumers — `l2fwd_pcap.rs` + `edge-netns.sh`

**Files:** `flowplane/nfkit/tests/l2fwd_pcap.rs`, `test/edge-netns.sh`.

- [ ] **Step 1: Read** the `python3 -c` block in `l2fwd_pcap.rs` and both `python3 - <<'PY'` rdpcap blocks in `edge-netns.sh` to capture their exact assertions + arg passing.
- [ ] **Step 2: `l2fwd_pcap.rs`** — replace the `Command::new("python3").arg("-c").arg(&py)` MAC-swap verification with building + invoking the Go tool: build `netprobe` (`CGO_ENABLED=0 go build` from `test/e2e` to a temp path, or a known target path) and run `netprobe pcap-verify --mac-swap --in <input> --out <out> --count 4`; assert exit 0. Keep the test's overall structure (it still produces the two pcaps via the l2fwd example). Remove the embedded python string. If building the Go tool from a Rust test is awkward, resolve a prebuilt path via an env var (e.g. `NETPROBE_BIN`) with a fallback `go run`—but prefer building once. Document the chosen mechanism in a comment.
- [ ] **Step 3: `edge-netns.sh`** — replace the two `python3 - "$ARGS" <<'PY' … rdpcap …'` blocks with `netprobe pcap-verify` calls: (a) return check → `netprobe pcap-verify --pcap "$WANP" --want-outer-ipv6-dst "$OWNER_UL_or_owner" --want-outer-ipv6-nh 4 --want-inner-ip-dst "$NAT_IP"` (match the exact vars the block used — read them from the script); on exit 0 print the same `PASS: RETURN …` (or let netprobe's PASS line stand — but keep a script-level echo if the harness greps a specific string). (b) egress check → `netprobe pcap-verify --pcap "$FABP" --want-inner-ip-src "$NAT_IP" --want-inner-ip-dst "$EXT_DST" --want-no-ipv6`. Build `netprobe` once near the top (like the tap-dhcp-probe scripts build their probe: `NETPROBE="${ROOT}/test/e2e/netprobe.bin"; ( cd "${ROOT}/test/e2e" && CGO_ENABLED=0 go build -o "$NETPROBE" ./cmd/netprobe )`). Preserve any inject `python3` blocks in edge-netns.sh for Task 4 (send) — if this file also has send blocks, note them; do NOT leave scapy in it.
- [ ] **Step 4: Verify.** `cargo test -p nfkit --test l2fwd_pcap 2>&1 | tail` if runnable (needs the l2fwd example + sample pcap — if it self-skips without them, note it; at minimum it must COMPILE and not reference python/scapy). `bash -n test/edge-netns.sh`. `grep -n 'scapy\|python3' test/edge-netns.sh` → only send blocks remain (ported in Task 4) or none.
- [ ] **Step 5: Commit** — `refactor(test): l2fwd_pcap + edge-netns pcap checks via netprobe (drop scapy)`.

---

## Task 3: `netprobe send` + `pcap-replay` — port `afxdp-loopback.sh` + `afxdp-uplink.sh`

**Files:** create `test/e2e/cmd/netprobe/send.go`, `test/e2e/cmd/netprobe/pcapreplay.go`; modify `hack/dpdk/afxdp-loopback.sh`, `hack/dpdk/afxdp-uplink.sh`.

- [ ] **Step 1: Read** the full `python3 - <<'PY'` blocks in both scripts (afxdp-loopback sends UDP + may sniff; afxdp-uplink does rdpcap→sendp replay→wrpcap capture).
- [ ] **Step 2: `netprobe send`** (`send.go`) — flags: `--iface`, `--eth-src`, `--eth-dst`, `--ip-src`, `--ip-dst`, `--ipv6` (bool: build IPv6 instead of IPv4), `--l4 udp|tcp|none`, `--sport`, `--dport`, `--payload <string>`, `--count` (default 1), `--interval-ms` (default 0). Craft with gopacket layers, `netpkt.Send` each. Mirror the exact fields the two scripts' `sendp` used.
- [ ] **Step 3: `netprobe pcap-replay`** (`pcapreplay.go`) — flags: `--in <pcap>`, `--iface`, `--out <pcap>` (optional capture), `--sniff-iface` (optional; default = `--iface`), `--timeout`. Read `--in` via `netpkt.ReadPcap`, optionally start a `netpkt.Sniff` on `--sniff-iface` capturing raw frames, replay each input frame via `netpkt.Send`, then `netpkt.WritePcap(--out, captured)`. Match afxdp-uplink's behavior (replay IN_PCAP to VV1, capture to OUT_PCAP).
- [ ] **Step 4: Rewire** both scripts: build `netprobe` once near the top (`NETPROBE=…; CGO_ENABLED=0 go build`), replace the `python3 - <<PY` blocks with `netprobe send …` / `netprobe pcap-replay …` calls preserving arg passing ($VV1, $IN_PCAP, $OUT_PCAP, etc.) and exit-code checks.
- [ ] **Step 5: Verify.** `CGO_ENABLED=0 go build ./cmd/netprobe` clean; `go vet`/`gofmt`; `bash -n hack/dpdk/afxdp-loopback.sh hack/dpdk/afxdp-uplink.sh`; `grep -n scapy\|python3` both → none. (Live run needs hugepages+DPDK — defer to Task 5's best-effort.)
- [ ] **Step 6: Commit** — `refactor(test): afxdp-loopback/uplink packet I/O via netprobe send+pcap-replay (drop scapy)`.

---

## Task 4: `netprobe send-sniff` — port `serve-e2e.sh` (+ any `edge-netns.sh` inject)

**Files:** create `test/e2e/cmd/netprobe/sendsniff.go`; modify `hack/dpdk/serve-e2e.sh`, and `test/edge-netns.sh` if it has inject blocks.

- [ ] **Step 1: Read** `serve-e2e.sh` fully (parts A/B/C, including the bash-thread orchestration around the python sniff/inject) and any remaining `python3` inject block in `edge-netns.sh`.
- [ ] **Step 2: `netprobe send-sniff`** (`sendsniff.go`) — inject on one iface while sniffing another, then assert/extract. Flags: `--tx-iface`, `--rx-iface`, `--count`, `--interval-ms`, the same craft flags as `send` (eth/ip/ipv6/tcp fields, payload), a filter on captured frames (`--rx-inner-ip-dst`, `--rx-inner-ip-src`, `--rx-outer-ipv6`, `--rx-l4 tcp`), assertions (`--want-outer-ipv6-nh <n>`), extraction+range (`--extract inner-tcp-sport`, `--sport-range min-max` → PASS only if the extracted value is in range), `--timeout`, and a `--count-min <n>` mode (part C: PASS if ≥n frames matched). Print a `PART … OK: …`-style line and the extracted values; exit 0 on pass, non-0 on fail. Use `netpkt.Sniff` with the `arm` callback doing the injects, so RX is armed before TX (mirrors AsyncSniffer.start()+sleep+sendp). Model the exact predicates/prints on the serve-e2e python.
- [ ] **Step 3: Rewire `serve-e2e.sh`** parts A/B/C: replace each `run_in_ns(ns, python-block)` + the bash-thread sniff orchestration with `ip netns exec <ns> netprobe send-sniff …` (netprobe itself does the concurrent arm+inject in one process, removing the need for the bash-managed python threads). Preserve the SNAT-port-range check (A), nat-return delivery (B), and the `SERVE_E2E_GUEST2GUEST` guarded count (C). Keep all the surrounding bash (attach/route/fw via the Rust client, env exports). Build `netprobe` once near the top.
- [ ] **Step 4: `edge-netns.sh` inject** (if present) → `netprobe send …`. After this, `grep -n scapy\|python3 test/edge-netns.sh` must be empty.
- [ ] **Step 5: Verify.** `CGO_ENABLED=0 go build ./cmd/netprobe` + `go vet` + `gofmt`; `bash -n hack/dpdk/serve-e2e.sh test/edge-netns.sh`; `grep -rn 'scapy' hack/dpdk/serve-e2e.sh test/edge-netns.sh` → none.
- [ ] **Step 6: Commit** — `refactor(test): serve-e2e + edge-netns packet inject/sniff via netprobe send-sniff (drop scapy)`.

---

## Task 5: Full validation + finish the branch

- [ ] **Step 1: No scapy anywhere.** `git grep -nI 'scapy' -- ':!docs/superpowers'` → empty (all live refs ported). `git grep -nI "from scapy\|import scapy\|scapy.all"` → empty.
- [ ] **Step 2: Build/vet/unit all-Go.** `cd test/e2e && CGO_ENABLED=0 go build ./... && go vet ./... && go test ./cmd/... ./internal/... 2>&1 | tail`. `bash -n` on every modified script.
- [ ] **Step 3: Flake proof.** `nix develop -c bash -c 'python3 -c "import scapy" 2>&1 | tail -1'` → ModuleNotFoundError; `python3 -c "import elftools"` ok (DPDK pyelftools stays).
- [ ] **Step 4: Live gates (best-effort, document what ran).**
  - `cargo test -p nfkit --test l2fwd_pcap` (if the l2fwd example + sample pcap are available; else note skip).
  - `make tap-dhcp-probe` (sudo, local) → OFFER in native/driver mode (from the tap-dhcp-probe plan's Task 10 — run it here since finish was deferred).
  - `nix develop -c ./test/tc-dhcp-netns.sh` + `./test/tc-egress-netns.sh` (sudo netns) → PASS.
  - Live fabric: `go test ./test/e2e/... -run 'TestCrossNodeOverlayPing|TestDhcpLeaseSmoke|TestLbDistributeSmoke' -timeout 40m` from a plain `nix develop` (brings the fabric up; DHCPv6 = the primary conformance) → PASS / documented best-effort.
  - af_xdp/serve-e2e DPDK harnesses need hugepages — run if the host is set up; else document as "compile-gated only, needs hugepage host".
- [ ] **Step 5: Final review** — dispatch a code-quality reviewer over the whole branch diff (`git diff main...HEAD`) focused on the Go tools + the harness rewires.
- [ ] **Step 6: Finish** (superpowers:finishing-a-development-branch) — verify tests, merge `--no-ff` to main + push. Update memory (scapy fully dropped; python3 kept for DPDK pyelftools; Go probe + netprobe are the packet harnesses).

## Notes / risks
- **serve-e2e.sh (Task 4) is the highest-risk port** — its concurrent sniff/inject + bespoke SNAT-port assertion. If a predicate can't be expressed cleanly as `send-sniff` flags, add a small tailored subcommand rather than contorting the generic one. Its live validation needs DPDK+hugepages; compile-gate + preserve exact assertions even if live-unrunnable here.
- Keep `netprobe` cgo-free (static) — same reason as tap-dhcp-probe (must run in minimal netns/containers; NixOS cgo binary won't run elsewhere).
- Do NOT reintroduce scapy to the flake. The flake drop already landed (Task 9 of the prior plan); these tasks make it correct.
- pcapgo is pure Go (no libpcap) — do NOT use gopacket/pcap (cgo).
