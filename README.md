# ironcore-net-xdp

An **eBPF/XDP drop-in replacement for IronCore's DPDK [`dpservice`](https://github.com/ironcore-dev/dpservice)** — the L3 software-defined-network dataplane behind [metalnet](https://github.com/ironcore-dev/metalnet). It speaks the same `DPDKironcore` gRPC contract metalnet drives and reproduces dpservice's on-wire behaviour, but runs as a pure-XDP, map-driven datapath in the Linux kernel instead of a DPDK poll-mode application.

The goal is **functional + wire-compatible parity** with dpservice, with a **map-driven design that is offload-ready** (every forwarding decision is a per-flow-keyed table lookup — the shape a SmartNIC `rte_flow`/hardware rule would encode). The end target is forking [ironcore-in-a-box](https://github.com/ironcore-dev/ironcore-in-a-box) and dropping this in for the DPDK `dpservice`.

> Status: full datapath parity is implemented and the gRPC control plane is driven by dpservice's own conformance suite. See [Conformance](#conformance) for the live number.

## What it does

A map-driven XDP overlay dataplane. Guests live on tap/veth interfaces; the underlay is IPv6; overlay traffic is **IP-in-IPv6** (inner-proto 4 for IPv4, 41 for IPv6). The datapath implements:

- **Overlay forwarding** — encap/decap, LPM routing (v4 + v6), multi-VNI tenancy, same-host fast path.
- **In-datapath responders** — ARP, IPv6 Neighbour Discovery, and **DHCPv4/v6** (built in XDP next to ARP/ND, mirroring dpservice's `dhcp_node`/`dhcpv6_node`).
- **Stateful services** — unified conntrack, **NAT-GW** (network NAT with distributed return via neighbor-NAT), **VIP** (1:1 DNAT/SNAT), **load balancing** (Maglev consistent hashing, dpservice underlay-forwarding model), **NAT64**, and **packet relay**.
- **Firewall** (stateful whitelist, enforce-by-default), **rate metering** (srTCM token bucket), and **HA** via pinned maps (control-plane restart re-adopts the kernel-resident datapath).

The control plane is a `tonic` gRPC server implementing the `DPDKironcore` contract, programming the eBPF maps and dynamically attaching/detaching the XDP program on VF taps as `CreateInterface`/`DeleteInterface` arrive.

## Repository layout

| Path | What |
|---|---|
| `xdp-dp-common/` | `#[repr(C)]` POD types shared between the eBPF and userspace sides (map keys/values), with layout tests. |
| `xdp-dp-ebpf/` | The XDP programs: `guest_tx` (guest→overlay egress) and `uplink_rx` (overlay→guest ingress), plus the feature modules (conntrack, nat, nat64, lb, vip, firewall, meter, arp_nd, dhcp, v6, encap). |
| `xdp-dp/` | The userspace daemon: gRPC server (`grpc.rs`), map control plane (`control.rs`), loaders, and the CLI (`serve`, `bringup`, `pass`, `inspect`). |
| `proto/dpdk.proto` | The `DPDKironcore` gRPC contract (mirrors dpservice). |
| `test/conformance/` | dpservice's own `test/local` pytest+scapy suite, vendored and re-pointed at `xdp-dp serve` (see [Conformance](#conformance)). |
| `test/*.sh`, `test/*.py` | Local harnesses: `netns-e2e.sh` (3-node overlay), `ha-smoke.sh`, `tap-vm-smoke.sh` (real CirrOS VM), `tap-dhcp-probe.sh`. |
| `docs/superpowers/specs/`, `docs/superpowers/plans/` | Per-milestone design specs and implementation plans. |

## CLI modes (`xdp-dp`)

- **`serve`** — the production gRPC daemon: attaches `uplink_rx`, serves `DPDKironcore` on a port, and attaches/detaches `guest_tx` on VF taps at runtime as gRPC drives it.
- **`bringup`** — static, flag-driven datapath for the netns lab (no gRPC).
- **`pass`** — attach a trivial `xdp_pass` program (redirect-target enabler for veth peers).
- **`inspect`** — debug packet inspector.

## Getting started

Everything is provided by the Nix flake — Rust (via rustup, pinned in `rust-toolchain.toml`), `bpf-linker`, `protobuf`, `python3`+`scapy`+`pytest`, the genuine `dpservice-cli` (built from source via `buildGoModule`), plus `qemu`, `iproute2`, `ethtool`, `tcpdump`, etc. There are no host-specific paths; run things through the flake.

```sh
nix develop            # enter the dev shell (all targets assume you are inside it)
make                   # list all targets
```

Common workflows (run them from inside `nix develop`):

```sh
make build             # build xdp-dp (host crates + the eBPF object via aya-build)
make lint              # clippy
make test              # host unit + POD-layout tests (no root)
make conformance       # dpservice conformance suite vs `xdp-dp serve`   (sudo)
make e2e               # 3-node netns overlay end-to-end                 (sudo)
make ha                # HA pinned-maps kill+adopt smoke                 (sudo)
make tap-vm-smoke      # boot a CirrOS VM on a real tap                  (sudo + KVM)
make cli               # build the dpservice-cli flake package
```

The `conformance`, `e2e`, `ha`, and `tap-*` targets need **passwordless sudo** (XDP attach, network namespaces, raw sockets). The scripts elevate individual commands themselves.

## Synthetic datapath testing

The real datapath logic lives in `xdp-dp-core` — a `no_std` crate whose functions are generic over `Pkt`/`Maps` traits. The same code runs in two contexts:

- **eBPF** — `CtxPkt`/`GlobalMaps` in `xdp-dp-ebpf/src/coreimpl.rs` bind the trait impls to real kernel maps and the XDP packet context.
- **Native sim** — `VecPkt`/`MemMaps` in `xdp-dp-sim` provide in-process, heap-backed impls. `SimNode` runs the real core functions with no kernel, no clab, no root. `CompiledNIC` (the per-NIC control-plane CRD) is lowered into sim maps via `xdp_dp_sim::compilednic::apply`, so the control-plane→datapath path is tested end-to-end without touching a real interface.

**Multi-node fabric.** `xdp_dp_sim::Fabric` owns several `SimNode`s plus an underlay-`/128`→node table and follows encap/redirect hops across the fabric (`bpf_redirect` semantics), returning a `Trace` of every hop. This runs *whole flows* in-process: North-South (external → edge `wan_rx` → backend host), and East-West load-balancing including the relay **reforward** to a remote backend. The LB coverage (`xdp-dp-sim/src/lb_scenario_test.rs`) reproduces the "LB packets dropped" clab failure synthetically and pins the fix: the firewall is **explicit-only** (LB membership never generates rules) and the dataplane is **deny-by-default** — the control plane materializes k8s open-until-selected as explicit allow-all rules for unpolicied NICs (`Compile()`). Because LB is DSR (inner dst stays the VIP), a policy written for a backend's own overlay IP does *not* cover its LB traffic; an explicit `VIP:port` rule is required.

See `docs/superpowers/specs/2026-07-15-compiled-nic-synthetic-datapath-testing-design.md` (core sim) and `docs/superpowers/specs/2026-07-15-fabric-sim-lb-coverage-design.md` (fabric + LB) for the full designs.

### Commands

```sh
make sim             # fast in-process tests — the everyday dev loop (no root, no clab)
make sim-anchor      # privileged BPF_PROG_TEST_RUN check: native core output == real bytecode output
make conformance     # full dpservice conformance suite against xdp-dp serve (sudo; the regression gate)
```

### How to add a datapath feature

1. **Port the fn into `xdp-dp-core`** generic over `Pkt`/`Maps`; add any new map-accessor methods to the `Maps` trait.
2. **Wire the eBPF side** — call the new fn from `xdp-dp-ebpf` via the existing `CtxPkt`/`GlobalMaps` impls in `coreimpl.rs`.
3. **Implement `MemMaps`** — add the corresponding in-memory map to `xdp-dp-sim` and implement the new `Maps` accessor.
4. **Add a sim test** — write a `SimNode`- or `Fabric`-based scenario in `xdp-dp-sim/src/*_test.rs` (single-node or multi-hop); run it with `make sim`.
5. **Add an anchor case** — add one `BPF_PROG_TEST_RUN` case in the relevant `xdp-dp/tests/anchor_*.rs` to assert native-core output matches real bytecode; verify with `make sim-anchor`.

## Conformance

Drop-in fidelity is proven by **dpservice's own `test/local` suite** — vendored into `test/conformance/` and re-pointed at `xdp-dp serve`. The scapy packet tests and the gRPC client are dpservice's; only the launch + device plumbing is adapted:

- The real **`dpservice-cli`** (the client metalnet's ecosystem uses) drives our gRPC server — built from source by the flake (`buildGoModule` over the pinned `dpservice` input).
- **veth substitution** lets dpservice's unchanged `sendp(iface=…)` tests feed our XDP RX hook (a veth pair turns "TX on one end" into "RX on the other"). Production uses real qemu taps, where XDP attaches natively; `make tap-vm-smoke` / `make tap-dhcp-probe` validate that path.

```sh
make conformance                      # the default suite
CONF_TESTS="test_lb.py" make conformance   # a subset
```

## Design docs

Each milestone has a spec (`docs/superpowers/specs/`) and an implementation plan (`docs/superpowers/plans/`) — the parity gap analysis, the ioiab drop-in sub-projects (2a dynamic taps + gRPC, 2b DHCP, 2c deployment), and the per-feature designs (NAT, LB, NAT64, HA, IPv6 overlay, …).
