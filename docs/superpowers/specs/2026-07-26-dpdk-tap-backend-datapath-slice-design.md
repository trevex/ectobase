# DPDK TapBackend (VM guest port) — Datapath Slice Design

**Date:** 2026-07-26
**Status:** Approved (brainstorming)
**Predecessor:** DPDK guest-egress hardening (main @1e6622f) — introduced the `GuestPortBackend` lifecycle seam (`flowplane-dpdk/src/port_backend.rs`: preallocate/assign/release/is_alive/recover/teardown; `VethBackend` impl; tap/VF documented as seams).

## Overview

Add a **`TapBackend`** implementation of the `GuestPortBackend` seam so a VM (qemu/virtio-net, e.g. KubeVirt) can be a guest of the DPDK af_xdp pool — the software analogue for VMs, sitting alongside veth (containers) and the future VF (real NIC). This is the **datapath slice**: prove af_xdp-on-tap forwards guest traffic through the DPDK pool + `process_guest_tx`, tested on this host with a raw tap fd (no KubeVirt). The KubeVirt control-plane wiring (binding plugin, CNI/Multus, fd-handoff-to-qemu-in-a-pod-netns) is a separate deferred effort.

## Tap topology (the key model)

A tap device = **one kernel netdev** (`fpgtap{i}`) + **one char-device fd** (`/dev/net/tun` after `TUNSETIFF`). Whoever holds the fd is the "application" side; the netdev side is where a datapath attaches. Therefore:

- **af_xdp binds the tap's kernel netdev** (the pool port, in the serve netns) — identical mechanism to af_xdp-on-veth-host-end.
- **qemu/virtio-net holds the fd** (the guest-facing side, = the VM's NIC backend).

This is exactly parallel to veth, except the guest-facing side is an **fd handed to qemu** instead of a **netdev moved into a pod netns**. It is MORE VF-like than veth: a persistent tap (`IFF_PERSIST`) **survives the VM's death**, so `recover()` is a near-no-op (no hotplug rebind needed — unlike veth, where the pair dies together).

NOTE: the DPDK `net_tap` PMD is the WRONG tool here — it makes DPDK hold the fd (DPDK-as-endpoint). We want af_xdp-on-the-netdev with qemu on the fd (we are the datapath *between* the VM and the fabric).

The datapath itself (`process_guest_tx` / `process_uplink_rx` / rings / GC) is **unchanged** — it keys on the pool host ifindex regardless of backend kind.

## De-risk gate (FIRST — like the multi-vdev and hotplug gates before it)

Prove af_xdp binds a tap **netdev** and forwards a frame written to its **fd**. af_xdp-on-veth works on this host (M7); af_xdp-on-tap in copy mode is very likely but UNPROVEN. If it fails, the whole model is invalid — STOP and reconsider (do not proceed to the backend).

Gate test (`nfkit/tests/afxdp_tap.rs`, sudo, `--no-huge`): create a persistent tap `fptaphp0` (`/dev/net/tun` + `TUNSETIFF(IFF_TAP|IFF_NO_PI)`, keep the fd), bring the netdev up; `Eal::init` with `--vdev=net_af_xdp0,iface=fptaphp0`; `Port::configure(0,1,&pool)`; write a test Ethernet frame to the tap fd → `RxQueue::rx` on port 0 sees it (byte-match); build a frame + `TxQueue::tx` on port 0 → `read(fd)` returns it (byte-match). Round-trip both directions. Skip (77) if unprivileged.

## Architecture: `TapBackend` on the `GuestPortBackend` seam

`flowplane-dpdk/src/port_backend.rs` gains a `TapBackend` struct (parallel to `VethBackend`) + a `AssignTarget::Tap` variant. A tap-device helper module (`flowplane-device/src/tap.rs`, mirroring `veth.rs`) provides the syscalls.

- **`preallocate(i, mtu) -> HostDevice`** — create a persistent tap `fpgtap{i}` (open `/dev/net/tun`, `ioctl TUNSETIFF` with `IFF_TAP|IFF_NO_PI`, `ioctl TUNSETPERSIST(1)`), set MTU + up, resolve ifindex; return `{host_ifname, host_ifindex}`. The netdev is af_xdp-bound as `net_af_xdp{1+i}` via the SAME `eal_args_lcores_with_guest_ifaces` path (a tap netdev name works there identically to a veth name). The fd used for creation may be closed after `TUNSETPERSIST` (the tap persists); the fd handed to the VM is opened at `assign`.
- **`assign(host_ifname, target: &AssignTarget, mac, mtu) -> Result<()>`** — open the guest-facing fd (`/dev/net/tun` + `TUNSETIFF(host_ifname, IFF_TAP|IFF_NO_PI)`) and deliver it to the consumer. `AssignTarget::Tap { fd_sink }` where `fd_sink` is the handoff mechanism — for the SLICE, an in-process channel/callback that hands the raw fd to the test (simulating qemu); the real fd-passing-to-qemu is deferred to the KubeVirt effort. Set the tap MAC/MTU as needed. Program `PortMeta` keyed by the tap host ifindex (done by the existing `program_interface` path, unchanged).
- **`release(host_ifname, target)`** — close the guest-facing fd; the tap netdev PERSISTS (reusable).
- **`is_alive(slot)`** — `link_exists(host_ifname)` (persistent tap → ~always true).
- **`recover(slot, pool_port_id)`** — near-no-op: the persistent tap survived; reconfirm it exists (recreate via `preallocate` only if somehow gone) and return the ifindex. NO hotplug churn in the common case (the VF-like win). Document the contrast with `VethBackend::recover`.
- **`teardown(host_ifname)`** — `TUNSETPERSIST(0)` + delete the tap (idempotent).

**Serve wiring:** a `--guest-backend veth|tap` arg (default `veth`) selects the pool backend kind for the whole serve process (one kind per process; mixed pools are a follow-up). `run()` constructs `Arc::new(VethBackend{..})` or `Arc::new(TapBackend{..})` accordingly; everything downstream (preallocate loop, attach/detach, worker) is backend-agnostic via the trait.

## Data flow (guest→fabric, VM case)

qemu writes a guest Ethernet frame to the tap fd → appears on the `fpgtap{i}` netdev → af_xdp (pool port `1+i`) rx's it in the worker → `ports_get(host_ifindex)` → `PortMeta` → `process_guest_tx` (v4/v6/NAT64) → SNAT+encap → uplink tx. Return: uplink rx → reverse-DNAT/decap → `Redirect(tap_ifindex)` → the owning worker tx's on the pool port → delivered to the tap fd → qemu reads it. Identical to veth except the guest edge is an fd, not a netns'd veth.

## Testing (this host, no KubeVirt)

- **De-risk gate** (above) — af_xdp-on-tap fd round-trip.
- **TapBackend unit/behavior** — preallocate creates a persistent tap (survives fd close), assign opens a usable fd, release closes it + tap persists, teardown removes it, recover is a no-op when the tap is alive. (Privileged where it touches `/dev/net/tun`.)
- **Tap-backed datapath component test** — a serve/component test (mirroring `serve_e2e` / `guest_tx_datapath`) driving the "VM side" via a raw tap fd reader/writer: write a guest IPv4 frame to the fd → assert encapped egress on the uplink (guest→fabric); inject the NAT-return on the uplink → assert reverse-DNAT delivery readable on the tap fd. Deterministic, no VM.
- **Follow-on (deferred):** a real-qemu e2e (like the eBPF `tap-vm-smoke`), and the full KubeVirt binding-plugin path.

## Components / files

- New: `flowplane-device/src/tap.rs` (+ `lib.rs` export) — `create_persistent_tap(name, mac, mtu) -> DeviceInfo`, `open_tap_fd(name) -> OwnedFd`, `delete_tap(name)`; reuse `veth.rs`'s `ifindex_of`/`mac_of`/`link_exists`.
- Modify: `flowplane-dpdk/src/port_backend.rs` (`TapBackend`, `AssignTarget::Tap`), `flowplane-dpdk/src/serve.rs` (`--guest-backend` + backend construction), possibly `flowplane-dpdk/src/node.rs` (build the tap `AssignTarget` when the backend is tap — but keep the assign call site backend-agnostic; the target variant is the only difference).
- Tests: `nfkit/tests/afxdp_tap.rs` (de-risk), a TapBackend test in `flowplane-dpdk/tests/`, a tap-backed datapath component test.

## Out of scope / deferred (documented)

- KubeVirt binding plugin (`domainAttachmentType=tap`), CNI/Multus wiring, real fd-handoff to a qemu in a pod netns.
- Real-qemu VM e2e (`tap-vm-smoke` analogue).
- Mixed veth+tap pools in one serve process.
- VfBackend (hardware-gated).

## Risks & mitigations

| Risk | Mitigation |
|------|------------|
| af_xdp-on-tap doesn't work on this host (copy mode) | The de-risk GATE runs first; if it fails, STOP + reconsider before building the backend |
| tap fd lifecycle (leak/double-close across assign/release) | `OwnedFd` ownership; release closes exactly once; teardown idempotent |
| `AssignTarget::Tap` fd-handoff shape churns when KubeVirt lands | Slice uses an in-process fd sink (test/callback); the real qemu handoff is a deferred, isolated change behind the same trait method |
| Persistent tap leaks across serve restarts | `teardown` clears `IFF_PERSIST` + deletes; startup deletes stale same-named taps (mirror veth) |
