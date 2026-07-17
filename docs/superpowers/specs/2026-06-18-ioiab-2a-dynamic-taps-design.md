# Sub-project 2a — Dynamic Tap Lifecycle + gRPC Completeness (ioiab drop-in)

**Status:** Implemented (2026-06-18) — **88 / 89 dpservice non-DHCP conformance passing.**
**Parent effort:** ioiab drop-in (replace DPDK `dpservice` with `flowplane`). Decomposed into:
**2a** (this) dynamic tap lifecycle + gRPC completeness · **2b** DHCPv4/v6 · **2c** ioiab deployment.
**Predecessor:** full datapath parity M5–M10, M12, M13, M15 (M14 capture deferred).

## Conformance result (final for 2a)

`./test/conformance/run.sh` drives the vendored dpservice `test/local` suite against `flowplane serve`
via the real `dpservice-cli` (per-test daemon isolation). **88 passed / 1 failed / 2 skipped.**

The single remaining failure, `test_arp::test_l2_addr_once`, requires **DHCP** (it re-learns the
VM's MAC via a DHCP exchange) — that is **sub-project 2b**. Every other non-DHCP test passes,
including the features the parity roadmap had scoped as later milestones, which were pulled forward
and implemented here on top of 2a's gRPC/tap foundation:

- **Packet relay** — LB ICMP-error relay + IPv6 LB relay (reuses `encap::reforward` + Maglev).
- **Native IPv6-stateful LB** — v6 Maglev delivery to local backends + ICMPv6 echo for LB VIPs.
- **NAT64** — IPv6 guest → IPv4 external via the `64:ff9b::/96` prefix (v6↔v4 header + ICMP
  translation with `bpf_xdp_adjust_head` resize, verifier-safe fixed-offset checksums), bidirectional.

**Also delivered in 2a:** `flowplane serve` (runtime XDP attach/detach), the full non-DHCP gRPC surface
with dpservice error-code semantics, same-host fast path, virtual-gateway ARP/ND (VF's own MAC),
NAT-GW external with peer-independent return demux (globally-unique ports per nat_ip), same-host VIP
DNAT, ICMP NAT, conntrack flush, and the vendored conformance harness (real `dpservice-cli`, veth
substitution, run-as-root, per-test isolation). netns (15) + HA smoke stay green throughout.

## 1. Goal

Make `flowplane` a runtime, gRPC-driven dataplane that metalnet can drive exactly as it drives
dpservice: a long-running daemon that attaches `uplink_rx` to the PF, serves the `DPDKironcore`
gRPC contract on a configurable port, and **attaches/detaches the `guest_tx` XDP program on VF
interfaces at runtime** as `CreateInterface`/`DeleteInterface` arrive — no static `--guest` flags.

Proven by vendoring dpservice's own `test/local` pytest+scapy conformance suite into this repo and
re-pointing it at `flowplane`, with the **test bodies unchanged**. 2a's gate is the **full non-DHCP
suite** (DHCP is 2b; virtsvc is dropped; telemetry/HA-extras/benchmark are out of scope).

## 2. Why this shape

- dpservice's `test/local` is contract-level, not dpservice-internal: scapy injects/sniffs on tap
  netdevs and a gRPC client drives interface/feature creation. Only the *launch command* and the
  *device plumbing* are dpservice-specific. Passing it is the strongest possible "drop-in" signal —
  it is dpservice's own behavioral expectation.
- Today `bringup` attaches XDP to a fixed interface set at startup. The drop-in needs runtime
  attach/detach, so a dedicated `serve` daemon mode keeps the lab-oriented `bringup` CLI untouched.

## 3. Architecture

```
                        flowplane serve --uplink PF --local-underlay fc00:1::1 --grpc-port 1337
   metalnet / pytest ─────────── gRPC :1337 ──────────►  Service (grpc.rs)
   (DPDKironcore client)                                    │  CreateInterface(device, ip, vni)
                                                            ▼
                                                    Control (control.rs)
                                                      ├─ attach guest_tx -> ifindex, keep XdpLink
                                                      ├─ program PORT_META / UNDERLAY
                                                      └─ shadow by_id / by_ifindex
   PF (uplink) ── XDP uplink_rx ──┐                  links: HashMap<interface_id, XdpLink>
   VF_n (tap/veth) ── XDP guest_tx ┘  (attached at runtime, detached on DeleteInterface)
```

The container ships one binary with two modes: `bringup` (static lab, unchanged) and `serve`
(gRPC daemon, new). `serve` loads the eBPF object once; the `guest_tx` program is attached to many
VF ifindexes over time, each attach returning a link retained for clean detach.

## 4. Components

### 4.1 `serve` subcommand (`flowplane/src/main.rs`)
Args: `--uplink <pf>`, `--local-underlay <ipv6>`, `--grpc-port <u16>` (default 1337),
`--gateway <ipv4>` + `--gateway-mac` (ARP target the datapath answers), `--gateway6 <ipv6>` (ND
target), `--pin-dir <path>` (optional HA pinning, reuses M13), `--adopt`. The `--dhcp-mtu` /
`--dhcp-dns` / `--dhcpv6-dns` flags are accepted and stored (consumed in 2b; parsing them now keeps
the ioiab arg list stable). Boots `Control` in **serve mode** (attach `uplink_rx` to the PF only;
no guests), spawns the tonic gRPC server + the conntrack GC task, idles until ctrl-c.

### 4.2 Runtime attach/detach (`flowplane/src/loader.rs`, `flowplane/src/control.rs`)
- `loader.rs`: expose runtime attach of the already-loaded `guest_tx` program to an additional
  ifindex, returning the `XdpLink` (today attach is one-shot at bringup; refactor so the loaded
  `Ebpf` + program handle live in `Control` and can attach later). When `--pin-dir` is set, pin the
  per-VF link (M13 mechanism) so a control-plane restart re-adopts without dropping the datapath.
- `control.rs`:
  - `attach_interface(id: &[u8], device: &str, vni, ipv4, gw4, gw6, underlay, total_mbps,
    public_mbps) -> [u8;16]` — resolve `device → ifindex` (`/sys/class/net/<dev>/ifindex`), attach
    `guest_tx`, store `links[id] = XdpLink`, program `PORT_META[ifindex]` (incl. `gateway_ipv4`,
    `gateway_ipv6`), `UNDERLAY[underlay]`, optional `METER`, and shadow `by_id[id]` /
    `by_ifindex[ifindex]`. Returns the per-interface underlay /128 (the `underlay_route`).
  - `detach_interface(id: &[u8])` — drop `links[id]` (detach), remove `PORT_META`/`UNDERLAY`/`METER`
    entries and shadow state. Idempotent.
  - Holds `links: HashMap<Vec<u8>, XdpLink>` (or `FdLink` when pinned).

### 4.3 gRPC completeness (`flowplane/src/grpc.rs`)
Wire and complete every RPC the non-DHCP conformance suite + metalnet reconcile drives:
- **Interface lifecycle:** `create_interface → attach_interface` (return `underlay_route` + `vf`);
  implement `delete_interface`, `list_interfaces`, `get_interface` from shadow state.
- **Routes:** `create_route`/`create_route6` (exist), add `list_routes`, `delete_route`.
- **VIP / LB / NAT / NeighborNat / Firewall:** *create* handlers exist; add the matching
  `delete_*` and `list_*`/`get_*` from shadow state (`lbs`, `fw`, `by_id`, `prefixes`, nat shadow).
- **VNI:** `check_vni_in_use`, `reset_vni` (scan shadow state for the vni).
- **Prefixes / LB-prefixes:** `create_prefix`/`delete_prefix`/`list_prefixes` and the LB-prefix
  trio (alias-prefix routes already programmable via ROUTES; back them with shadow state).
All reads come from authoritative userspace shadow state (no map scans for list/get). `Capture*`
stays stubbed (M14 deferred).

### 4.4 Local guest-to-guest fast path (`flowplane-ebpf/src/egress.rs`)
dpservice `test_vf_to_vf` puts both VMs on the **same host**. Today `guest_tx` always encaps and
redirects to the PF, hairpinning a same-host flow off-box. New rule: after ROUTES resolves the
nexthop underlay, if that underlay is **local** (present in `UNDERLAY`), deliver straight to the
destination tap — look up `UNDERLAY[nexthop] → (vni, dst_ifindex, dst_guest_mac)`, rewrite the inner
Ethernet (`dst_guest_mac`, `GW_MAC`, ethertype), `bpf_redirect(dst_ifindex)` — **no encap, no PF
round-trip**. Conntrack/firewall still apply before delivery. This is the one genuine *datapath*
addition in 2a; it is additive (cross-host still encaps via the PF) and must not regress the 15
netns e2e tests. The same short-circuit applies to the IPv6 overlay path (`v6_guest_tx`) and to
LB re-forward when the selected backend underlay is local.

### 4.5 Conformance harness (`test/conformance/`, vendored + adapted)
Vendor dpservice `test/local` into `test/conformance/`. **Adapt scaffolding only; never touch the
`test_*.py` bodies.**
- **veth substitution** (`setup-conformance-net.sh`): each dpservice device (`dtap0`, `dtap1`,
  `dtapvf_0..3`) becomes the **scapy-facing end** of a veth pair; `flowplane` attaches its XDP program
  to the **hidden peer**. `xdp_pass` enablers on the scapy-facing ends so `bpf_redirect` into them
  lands as XDP-RX. Test bodies keep sending/sniffing on `VM1.tap` etc. unchanged. (In real ioiab —
  2c — the guest interface is a qemu-owned tap where XDP-on-netdev works natively; veth is a
  harness-only stand-in.)
- **Launcher** (`dp_service.py` patch): build an `flowplane serve` command (uplink = PF peer,
  `--local-underlay=fc00:1::1`, `--grpc-port`, `--gateway`/`--gateway6` from `config.py`) instead of
  `dpservice-bin`. Keep the existing `--attach` path (start `flowplane` out-of-band, run pytest against
  it). The harness must create the veth topology + enablers before launch and tear it down after.
- **gRPC client = the real `dpservice-cli`** (decided): the harness's `grpc_client.py` is reused
  **unchanged** — it shells out to `dpservice-cli --address=localhost:<port> -o json <subcommand>`
  and parses the JSON. `dpservice-cli` is a generic client for the same `DPDKironcore` contract
  `flowplane` implements, so it drives us directly; this also validates our wire responses against the
  *actual* client metalnet's ecosystem uses. A pinned released `dpservice-cli` binary is fetched as
  a test dependency (dev shell / CI), at the version matching `proto/dpdk.proto`. `config.py`
  constants are reused as-is. **Implication for `grpc.rs`:** every response `flowplane` returns must
  populate its proto fields correctly (e.g. `list_interfaces` → real `Interface` messages with
  `spec`, `delete_*` → proper `Status`), because `dpservice-cli` renders JSON from those fields and
  the tests assert on them (`spec['underlay_route']`, `status['code']`, `source`). No `flowplane ctl`
  CLI and no python `grpcio` shim are built.

## 5. Data flow

**vf_to_vf (same host, the new fast path):** scapy TX on `VM1.tap` → RX on hidden VM1 peer →
`guest_tx`: ARP/ND answered in-datapath; for an IP packet, ROUTES resolves VM2's underlay = local →
conntrack/firewall → local fast path → `bpf_redirect` to VM2's peer → RX on `VM2.tap` → scapy
sniffs. No encap, no PF.

**vf_to_pf (egress to the wire):** scapy TX on `VM1.tap` → `guest_tx` → ROUTES resolves a **remote**
underlay → encap (IPIP/IPV6) → `bpf_redirect` to the PF peer → scapy sniffs the encapped frame on
`dtap0`.

**pf_to_vf (ingress from the wire):** scapy TX an encapped frame on `dtap0` → RX on hidden PF peer →
`uplink_rx`: `UNDERLAY[outer_dst] → (vni, ifindex, mac)` → decap + deliver → `bpf_redirect` to the
VF peer → scapy sniffs on `VM1.tap`.

## 6. Error handling

- `CreateInterface`: unknown `device_name` → `InvalidArgument`; an `interface_id`/device already
  attached → `AlreadyExists`; a failed attach rolls back any partial map writes so a retry is clean.
- `DeleteInterface`: idempotent — clears maps/shadow even if the link is already gone; unknown id →
  `NotFound` (metalnet tolerates this on reconcile).
- Datapath: the local fast path falls back to encap if `UNDERLAY[nexthop]` is absent (never drops a
  routable packet); the verifier gate + the 15 netns e2e tests guard against regressions.

## 7. Testing / definition of done

**Conformance gate (vendored `test/conformance`, full non-DHCP suite):**
`test_vf_to_vf`, `test_vf_to_pf`, `test_pf_to_vf`, `test_encap`, `test_arp`, `test_ipv6_nd`,
`test_flows`, `test_lb`, `test_nat`, `test_vni`, `test_zzz_grpc` — all green against `flowplane serve`.

**Explicitly out of 2a:** `test_dhcpv4`/`test_dhcpv6` (→ 2b), `test_virtsvc` (feature dropped),
`test_telemetry` (`--no-stats`, no telemetry surface), `xtratest_*` / `benchmark_test` (HA-extra /
perf, out of scope).

**Regression:** `env/netns-e2e.sh run` (15 tests) and `env/ha-smoke.sh run` stay green; eBPF
verifier gate passes; `cargo test` host tests pass.

## 8. Out of scope (this sub-project)

DHCPv4/v6 (2b), the ioiab container image + kustomize overlay + real `make up` (2c), packet capture
(M14, deferred), v6 stateful features / NAT64 (parked).
