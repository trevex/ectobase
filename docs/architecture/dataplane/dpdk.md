# DPDK dataplane backend

The DPDK backend is a second way to run the `flowplane` datapath on a node. Instead of
attaching eBPF programs to the kernel, it runs the datapath in userspace on top of
[DPDK](https://www.dpdk.org/), polling packets straight off the NIC. It exists to reach
higher throughput and to open the door to smartNIC hardware offload, while running the
**exact same datapath logic** as the eBPF programs and speaking the **exact same overlay
wire format** — so a DPDK node and an eBPF node interoperate transparently on one fabric.

The choice of backend is per-node (per-pool in practice): the pool chart selects `ebpf`
or `dpdk`, and everything above the node — the control plane, the compiled configuration,
the fabric encapsulation — is identical either way.

## A fourth implementation of the Pkt / Maps traits

The dataplane's structural invariant is the [pure-core seam](pure-core.md): all datapath
logic lives once in `flowplane-core`, written generically over two traits, `Pkt` (byte
access to a frame) and `Maps` (typed access to the datapath tables). Every environment
supplies its own trait impls and calls the *same* core functions.

The DPDK backend is one such environment — a **fourth `Pkt`/`Maps` implementation**
alongside the eBPF programs (`CtxPkt`/`GlobalMaps`), the in-process simulator
(`VecPkt`/`MemMaps`), and the af_xdp path:

| Backend | `Pkt` impl | `Maps` impl |
|---|---|---|
| Production eBPF | `CtxPkt` / `RawPkt` over an XDP/tc context | `GlobalMaps` over `#[map]` statics |
| Simulator | `VecPkt` over `Vec<u8>` | `MemMaps` (HashMap-backed) |
| **DPDK** | **`MbufPkt`** over an `rte_mbuf` | **`ComposedMaps`** (see below) |

`MbufPkt` (`nfkit/src/mbuf_pkt.rs`) implements `Pkt` over a DPDK `rte_mbuf`, including
`grow_head`/`shrink_head` mapped onto mbuf headroom/`adjust_tail` for encap/decap. The
`Maps` side is `ComposedMaps` (`nfkit/src/per_lcore_flow.rs`), which composes two halves:

- **`SharedConfigMaps`** — the process-wide *config* tables (routes, underlay, firewall,
  NAT, LB/Maglev, DHCP, ports, and the shared reverse-conntrack table). Built on
  `RcuHash` (lock-free + RCU: a single writer, N lock-free readers). Every datapath lcore
  holds an `&SharedConfigMaps` and reads it lock-free on every packet.
- **`PerLcoreFlowMaps`** — the per-lcore *flow* tables (forward conntrack, meters), owned
  by exactly one lcore, so the hot path needs no locking.

These are built on `nfkit`, an agnostic Rust DPDK substrate (the DPDK equivalent of the
aya/kernel layer): `DpdkHash`/`RcuHash` over `rte_hash`, the mbuf/port/EAL wrappers, RSS,
EDT pacing, and the rte_flow bindings. The DPDK-specific crates (`dpdk-sys`, `nfkit`,
`flowplane-dpdk`) are excluded from the default build so ordinary CI is unaffected.

## Byte-parity with the eBPF and sim datapaths

!!! success "Status: Implemented"
    The DPDK datapath runs the same `flowplane-core` source as eBPF and the sim, proven
    byte-identical by parity anchors.

Because `MbufPkt`/`ComposedMaps` satisfy the same traits, the DPDK worker calls the same
generic orchestrators (`process_uplink_rx`, `process_guest_tx`, the NAT/NAT64/LB/firewall
stages) that the simulator calls — the same functions the eBPF programs call. Those
orchestrators were extracted verbatim from `SimNode` into `flowplane-core` precisely so
DPDK, sim, and eBPF share one implementation rather than three parallel ones.

The result is a chain of equalities: **DPDK == sim == eBPF**. It is enforced the same way
the eBPF path is — with parity anchors that push a crafted packet through the real DPDK
datapath and through the native sim and assert the emitted bytes are identical (for
example `nfkit`'s `guest_tx_nat_return_handoff` and `guest_tx_nat64_handoff` tests drive
the *real* `process_guest_tx` write and the *real* `process_uplink_rx` read over a single
`ComposedMaps` — the exact structure a serve worker holds). This is the same discipline
the seam demands of eBPF: never fork the core to make a test pass; move the test to a
level that exercises the real code.

The control plane is shared too. The DPDK node service drives the same
`flowplane_control::ControlCore` orchestration the eBPF binary runs; only the write
surface differs — `DpdkMapWriter` over `SharedConfigMaps` in place of the eBPF
`AyaWriter`, method-for-method. So a compiled configuration lands identically on either
backend.

## Why the DPDK backend exists

The eBPF datapath is fast and ships everywhere, but it is fundamentally a kernel-XDP
program: it cannot hand its hot path (IPIP encap/decap, conntrack, NAT) to NIC hardware.
The DPDK backend is the seam through which that offload becomes possible.

!!! warning "Status: Partial"
    The *software* DPDK datapath is complete and proven; the *hardware-offload* posture is
    largely hardware-gated and only partially reachable without a smartNIC.

The headline reason is **mlx5 rte_flow RAW_DECAP / RAW_ENCAP**: on a Mellanox ConnectX
NIC, rte_flow can strip and push the outer IPv6 overlay header in hardware, moving the
IPIP hot path off the CPU entirely. `nfkit` includes the rte_flow bindings and a safe
wrapper (`nfkit/src/flow.rs`: `FlowRule` RAII, `validate`/`create`/`destroy`), plus a
runtime probe. The offload is **always conditional, never unconditional**: the node reads
the port's driver name, and only if it is `mlx5` *and* `rte_flow_validate` accepts a
RAW_DECAP and a RAW_ENCAP rule does it program hardware — otherwise it falls back to the
software datapath. This keeps a DPDK node correct on any NIC and fast on the ones that can
help.

The rte_flow path is *functionally* testable without a smartNIC via the `net_tap` PMD,
which lowers rte_flow rules to `tc-flower`: an e2e test creates a flow rule and asserts
the resulting tc-flower filter. Real ConnectX offload of the overlay hot path remains
hardware-gated.

## Transports and multi-lcore

A DPDK node ingests packets through one of two transport styles, selected by EAL
arguments — the same binary, no code change:

- **af_xdp PMD (`net_af_xdp`)** — binds the kernel netdev of a `veth` or `tap` and runs
  the datapath over the real kernel AF_XDP fast path. This is the laptop/CI transport and
  the one used for guest ports. The uplink datapath is validated end-to-end over a real
  veth loopback under `sudo`, byte-comparing the decapped delivery against the sim.

    !!! success "Status: Implemented"
        af_xdp on veth/tap is proven under `sudo`; guest ports use a VF-style
        preallocated af_xdp pool.

- **Native DPDK PMDs** — a real NIC bound to `vfio-pci` for production and performance on
  a box with a spare NIC. `dpdk-sys` builds a pinned DPDK release itself, so no system
  DPDK is required. For functional/CI runs with no hardware at all, the `net_pcap` /
  `net_null` vdevs under `--no-huge` provide a `BPF_PROG_TEST_RUN`-style feed-a-pcap /
  assert-a-pcap loop with zero host setup.

Guests attach onto a **preallocated per-guest af_xdp port pool** (VF-style): attach binds
a free pool slot and moves its device end into the pod netns; detach reverses it. Two
guest backends implement this lifecycle behind one `GuestPortBackend` seam:

| Backend | Guest kind | State |
|---|---|---|
| `VethBackend` | containers (veth pair) | Implemented |
| `TapBackend` | KubeVirt VMs (persistent tap, qemu holds the fd) | Datapath implemented; KubeVirt control-plane wiring planned |
| `VfBackend` | SR-IOV on a real NIC | Trait seam only (hardware-gated) |

!!! note "Status: Planned"
    `TapBackend`'s KubeVirt binding-plugin / CNI wiring and `VfBackend` are not yet wired.

The node runs **multi-lcore with shared-nothing per-lcore flow state**: each lcore owns
its own `PerLcoreFlowMaps` (so forward conntrack and meters need no locking), while the
config half and the reverse-conntrack table are `&`-shared. Because a WAN reply is
RSS-steered by the *outer* underlay headers — unrelated to the inner tuple that created
the NAT/LB reverse entry — those peer-independent reverse entries live in a **shared
reverse-conntrack table** so the return resolves on whichever lcore it lands on. RSS uses
a **symmetric Toeplitz key** so both directions of a flow hash to the same queue where it
matters. The single writer to the shared tables runs off the per-packet hot path, behind
a mutex, consistent with `RcuHash`'s single-writer / lock-free-reader model.

## Deployment

!!! success "Status: Implemented"
    The pool chart selects the backend with `dataplane: ebpf | dpdk`; `dpdk` renders a
    `flowplane-dpdk` DaemonSet from the `flowplane-dpdk` image.

`flowplane-dpdk` is a separate binary and container image (`flowplane-dpdk serve`, the
DPDK sibling of the eBPF `flowplane serve`), shipped alongside the eBPF image. It presents
the **same host-integration posture** as the eBPF datapath — `hostNetwork`, and the same
`DataplaneNode` gRPC service on `127.0.0.1:1337` — so the dataplane-agnostic agent dials
it identically.

The [pool chart](../../guides/deploy-helm.md) picks the backend from a single value:

```yaml
dataplane: dpdk          # ebpf | dpdk

images:
  flowplaneDpdk: ghcr.io/trevex/ectobase/flowplane-dpdk:dev

dpdk:
  lcores: "0"            # EAL -l value (single lcore on a shared clab host)
  hugepages: false       # false => --no-huge (clab); true on real hardware
  hugepageSize: 1Gi
  vfioDevices: []        # [{name: <resource>, count: <n>}] device-plugin requests
```

With `dataplane: dpdk` the chart renders the `flowplane-dpdk` DaemonSet
(`templates/dataplane-dpdk.yaml`) instead of the eBPF one; hugepages and `vfio-pci`
device requests are opt-in for real hardware and disabled for containerlab, where a single
lcore under `--no-huge` runs the af_xdp transport.

## In-place / blue-green upgrade

!!! note "Status: Planned"
    The hitless-upgrade primitives (externalized conntrack, consistent-hash steering)
    exist; the blue-green operator that orchestrates them is off by default and not yet
    landed.

A DPDK process cannot be upgraded in place the way a kernel program can be reloaded, so a
version upgrade is modelled as **blue-green**: stand up the new version beside the old,
drain flows across, then retire the old. Two building blocks support a *hitless* drain:

- **Externalized conntrack** — the shared reverse-conntrack table (`RcuHash`) supports
  `for_each` iteration and versioned snapshot/restore, so live NAT/LB flow state can be
  serialized out of the retiring instance and handed to the new one.
- **Consistent-hash steering** — a hash-based flow assignment so existing flows keep
  landing on the instance that owns their state during the flip.

The pool chart carries a `blueGreen` toggle (off by default, requires `dataplane: dpdk`)
for the operator that will drive this. Atomic steering flip and two-instance drain on real
hardware remain future work.

## Where to go next

- [The pure-core seam](pure-core.md) — the `Pkt`/`Maps` traits the DPDK backend implements.
- [Datapath programs](programs.md) — the eBPF glue whose logic the DPDK worker shares.
- [Deploying with Helm](../../guides/deploy-helm.md) — selecting and deploying a backend.
