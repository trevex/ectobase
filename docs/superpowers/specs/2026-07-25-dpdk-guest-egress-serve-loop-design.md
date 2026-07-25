# DPDK guest egress in the serve loop — design

Date: 2026-07-25
Status: designed, approved (implementation deferred to a focused effort)

## Problem

The DPDK `serve` loop (`flowplane/flowplane-dpdk/src/serve.rs` `worker_loop`) is
single-port, single-direction: it polls the **uplink** port, runs
`process_uplink_rx` (fabric→guest), and tx's. Guest egress (`process_guest_tx`,
guest→fabric) is NOT wired — the datapath never receives guest-originated frames.
Consequences: the DPDK dataplane is incomplete (no guest→out path), and the three
just-merged B2b conntrack/NAT fixes (shared reverse-CT, ct_refresh, NAT64 ingress)
are **latent** — they only fully activate once guest egress creates the forward
SNAT/NAT64 conntrack in the serve loop.

## Goal

Wire guest egress into the DPDK serve loop using a **per-guest af_xdp port** model
that mirrors SR-IOV VFs, so the datapath processes guest→fabric traffic
byte-identically to the eBPF/sim backends and the latent CT/NAT fixes go live.

## Key decision: per-guest af_xdp, VF-style preallocated pool (approved)

**Model — per-guest af_xdp, 1:1, port-identity = guest-identity.** Each guest gets
its own af_xdp port bound to its veth host-end. The datapath knows which guest a
frame came from by WHICH port it arrived on (the port's ifindex → that guest's
`PortMeta`) — no shared bridge, no MAC-learning demux. This is the closest software
analogue to SR-IOV VFs (a dedicated port per guest) and keeps datapath parity with
eBPF (af_xdp binds the SAME guest veth host-end that eBPF attaches tc/XDP to).
Rejected: a single shared guest-facing tap (one port + MAC-demux — unlike VFs).

**Preallocation — VFs are preallocated, so preallocate the guest ports.** VFs are
created at PF init (`sriov_numvfs=N`), then assigned to guests and returned to the
pool on teardown. Mirror that: at serve startup, preallocate a **pool of N guest
ports** — N veth pairs whose host-ends have af_xdp sockets bound and are added to
the poll set. This makes the **poll set STATIC** (uplink + N guest ports, all
polled from startup), which sidesteps the hardest DPDK problem: we never
register/deregister an fd into a running poll loop. A pool port is either **idle**
(no guest) or **bound** (assigned to a guest). `N` is a serve arg (like
`sriov_numvfs`), sized to the node's max guests.

- **Assign at attach:** pick an idle pool port; move its guest-end veth into the
  pod netns + configure it (reuse `flowplane_device::configure_guest_netns`); set
  the port→`PortMeta` mapping (vni, guest ipv4/ipv6, guest_mac, underlay) and mark
  the port bound. The af_xdp socket is already bound + polled — nothing changes in
  the poll set.
- **Release at detach:** move the guest-end back to the root netns (or reset it),
  clear the port's `PortMeta` mapping, mark idle → reusable/reconfigurable for the
  next guest.

## Serve-loop changes

`worker_loop` polls the uplink AND its assigned subset of guest ports:
- **Uplink RX** → `process_uplink_rx` (unchanged; fabric→guest, decap/deliver/NAT-return).
- **Guest-port RX** → resolve that port's `PortMeta` (by the port's ifindex/slot) →
  `process_guest_tx` → verdict: encap+redirect out the uplink, or local-deliver to
  another guest port (same-node guest↔guest), or drop. `process_guest_tx` creates
  the forward SNAT/NAT64 conntrack — **this is what lights up the shared reverse-CT
  write path** (the Mutex-serialized `shared_ct` from the just-merged concurrency
  fix now takes real concurrent writes → the concurrent-writer stress test becomes
  meaningful).

**Lcore ownership.** Guest ports are partitioned across worker lcores (round-robin
at assign time), so each guest port is polled by exactly one lcore — preserving the
per-lcore shared-nothing flow state. Cross-lcore NAT returns resolve via the shared
reverse-CT table (already built + serialized).

**Cross-thread coordination.** The attach RPC (tokio side) and the datapath workers
(std::thread) coordinate ONLY through the port→`PortMeta` mapping + the idle/bound
pool state — a shared map update, NOT fd registration. Design this as a
lock-free-read / serialized-write structure consistent with the existing
`SharedConfigMaps` model (or a small dedicated port table). The poll set itself
never changes at runtime.

## First slice (prove the path + light up the CT/NAT fixes)

- Preallocate a SMALL fixed pool (e.g. N=1 or 2) at serve startup, single worker.
- Assign one guest at attach; guest egress (SNAT+encap) out the uplink over af_xdp.
- Validate end-to-end with an af_xdp/tap test (guest sends → SNAT+encap on the
  uplink), and a NAT return (fabric→guest) that exercises the shared reverse-CT
  write+read across the guest-egress and uplink-rx paths.
- Then generalize: larger pool, multi-worker port partitioning, guest↔guest local
  delivery, MTU derivation, detach/reuse, and a multi-threaded concurrent-writer
  stress test for `shared_ct`.

## Open details to resolve during planning

- **Preallocation device.** veth pairs (recommended — matches B2a + eBPF parity)
  vs a dedicated af_xdp-capable device. Confirm af_xdp binds the host-end and the
  guest-end moves into the netns cleanly while the socket stays live.
- **Port→PortMeta table** shape + the tokio↔worker update path (assign/release).
- **Guest↔guest same-node delivery** between two guest ports (local fast path).
- **MTU** on the preallocated veths (derive from uplink − encap, per the eBPF model).
- **B2a attach model change:** attach shifts from "create a veth at attach" to
  "assign a preallocated pool veth" — reconcile with the existing `DpdkAttachState`
  registry + `configure_guest_netns`.
- Interaction with the DPDK `n_queues`/RSS uplink model (guest ports are
  single-queue per guest; RSS applies only to the uplink).

## Scope boundaries (YAGNI)

- **In:** per-guest af_xdp guest ports, VF-style preallocated pool, assign/release at
  attach/detach, serve-loop guest-RX → `process_guest_tx`, the first slice + tests.
- **Out:** SR-IOV VF transport (hardware — same datapath, later); vDPA; the full
  multi-thousand-guest scaling; hitless-upgrade interaction (M11) beyond what the
  shared_ct already provides.
