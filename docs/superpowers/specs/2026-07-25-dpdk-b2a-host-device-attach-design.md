# DPDK B2a: host-device attach lifecycle + transport decision — design

Date: 2026-07-25
Status: designed, approved

## Problem

The DPDK dataplane's `AttachInterface`/`DetachInterface` gRPC handlers program the
agnostic map half (via `ControlCore::program_interface`) but return
`Unimplemented` — the host-device step (create the guest device, resolve real
ifindex/MAC, underlay /128 IPAM, return the real response) is deferred (B2). The
DPDK datapath is also **uplink-only** today: the serve loop owns one uplink port
and has no guest-device ports, so a guest cannot yet attach or pass traffic.

"B2" therefore splits into:
- **B2a (this spec):** the *attach lifecycle* — stand up the guest device, IPAM,
  program maps, return the real response, and register the device so the datapath
  can later bind/poll it. Decides the *transport model* (which reshapes the k8s
  packaging). Fully dev-testable (device stand-up + response; no traffic).
- **B2b (deferred):** the *multi-port datapath* — af_xdp-bind each guest device
  port, poll it on the worker lcores, deliver to guest + guest→fabric egress.
  Needs live devices/NIC to validate.

## How the eBPF backend does it (the model to reuse)

The **agent** (not the CNI) owns the device lifecycle. The CNI hands
`{interface_id, netns_path, vni, requested_ips, device_type, mac}`; the eBPF
`flowplane/src/attach.rs` then: (a) creates a veth pair (guest end moved into the
pod netns, host end stays in root netns as the datapath device), (b) allocates an
underlay /128 via `UnderlayIpam` (`flowplane/src/underlay.rs`) + a deterministic
MAC, (c) delegates to `ControlCore::program_interface(IfaceParams{…})` (SHARED —
already called by the DPDK stub) which programs PORT_META/INTERFACES/UNDERLAY +
the self-route, and for eBPF also attaches `tc_guest_tx`. Device creation is done
by **shelling out to `ip link` / `ip netns exec`** (`run`/`run_netns` helpers), not
netlink — simple subprocess plumbing. Three device types exist: `Veth`
(container), `Tap` (VM fd), `PodTap` (KubeVirt mirred).

## Decision: reuse behind a clean seam; duplicate only where the interface would be ugly

Approach A (approved): reuse the eBPF device/IPAM lifecycle behind well-defined
seams; per-guest af_xdp is the eventual transport (B2b). Guided by KISS +
correctness + maintainability > DRY (user directive): extract the cleanly-
separable core, leave the messy VM device types eBPF-only (not-supported in DPDK
yet = no duplication), and route BOTH backends' container path through the shared
core so device creation cannot drift.

## Architecture

New **`flowplane-device`** crate — pure host-device + IPAM plumbing (subprocess
`ip`/`ip netns exec`), no tonic, no eBPF, no DPDK:

```
flowplane-common → flowplane-control (orchestration) / flowplane-device (host dev + IPAM)
                                     ↓                          ↓
                            flowplane-node (gRPC) ──────────────┘
                                     ↓
                        flowplane (eBPF)   flowplane-dpdk
```

### `flowplane-device` contents (extracted, shared)

- **`underlay.rs` moved verbatim**: `UnderlayIpam` (allocate/release/mark_used),
  `infer_underlay_address`/`infer_underlay_prefix`, `read_host_ifaddrs`, `IfAddr`.
  Pure; zero risk; both backends share the same IPAM (no drift).
- **The veth-container device core** as a well-bounded fn:
  ```
  pub fn create_veth_pair(spec: &VethSpec) -> anyhow::Result<DeviceInfo>
  pub struct VethSpec { pub interface_id: String, pub netns_path: String, pub mac: [u8;6], pub mtu: u32, pub guest_ifname: String }
  pub struct DeviceInfo { pub host_ifindex: u32, pub host_name: String, pub mac: [u8;6] }
  pub fn delete_link(name: &str) // idempotent `ip link del`
  ```
  plus the shared `run`/`run_netns` subprocess helpers and the deterministic
  name/MAC helpers (`host_veth_name`, `mac_for`) that both backends need.
  `create_veth_pair` does exactly the `ip link add … type veth peer …` → move
  peer to netns → rename → set mac/mtu/up (both ends) → resolve host ifindex
  sequence, with rollback (`delete_link`) on any step failure.

**NOT extracted (stays eBPF-only in `attach.rs`):** the `Tap`/`PodTap` device
types, the `mirred` splice, and the eBPF-fabric MTU-finalization/checksum quirks
— no clean cross-backend interface, and DPDK doesn't need them for B2a.

### eBPF side (de-drift, minimal churn)

Refactor `flowplane/src/attach.rs`'s **Veth path only** to call
`flowplane_device::create_veth_pair` + the shared IPAM/helpers (it currently
inlines the same `ip link` sequence). `Tap`/`PodTap` paths unchanged. The eBPF
attach behavior and its tests must stay identical (the container path is the
clab-tested one). `flowplane/src/underlay.rs` is **deleted** and its importers
repointed to `flowplane_device` (no re-export shim — one home for the type).

### DPDK side (B2a — the new capability)

`flowplane-dpdk` `AttachInterface` (container/`veth` device_type only; other
device_types → `InvalidArgument "device_type X not supported on DPDK yet"`):
1. `flowplane_device::create_veth_pair` (+ `UnderlayIpam.allocate()` for the /128
   + `mac_for`) → `DeviceInfo`.
2. `ControlCore::program_interface(IfaceParams{ tap: host_ifindex, effective_mac,
   underlay_ipv6, vni, ipv4, ipv6, gateway_*, … })` — the SAME shared call the
   stub already makes, now with REAL device-resolved values.
3. Insert into a new DPDK-local **`PortRegistry`**: `interface_id →
   AttachedDevice { host_ifindex, host_name, netns_path }`. This is the list B2b
   will iterate to af_xdp-bind + poll each guest port. (B2a does NOT bind or poll.)
4. Return the real `AttachInterfaceResponse { ifname, ips, mac, gateway,
   underlay_route }`.

`DetachInterface`: the existing map purge + `forget_iface_meta`, PLUS
`flowplane_device::delete_link(host_name)` and drop the `PortRegistry` entry.
Best-effort/idempotent (a missing device is not an error).

The DPDK serve process owns an `AttachState`-equivalent (the `UnderlayIpam` seeded
from the uplink /64 at startup + the `PortRegistry`), held alongside the existing
`ctrl` writer in `DpdkNodeService`.

## Scope boundaries (YAGNI)

- **In:** container/`veth` device_type attach+detach on DPDK; shared
  `flowplane-device` crate; eBPF Veth path routed through it; underlay IPAM
  shared; `PortRegistry`; real `AttachInterfaceResponse`.
- **Out (B2b / later):** af_xdp port hotplug + guest-traffic polling + delivery +
  guest→fabric egress; `Tap`/`PodTap` on DPDK; the DaemonSet changes (B3, but
  informed by this — see below).
- Untouched: `ControlCore`/`MapWriter`/`flowplane-node`/the datapath/eBPF
  programs/sim.

## Packaging implications (why B2 precedes B3)

B2a confirms the DPDK dataplane pod must, to attach containers, run with
`CAP_NET_ADMIN` (+ `CAP_SYS_ADMIN` for `setns`/`ip netns exec`), share the host
network namespace / have access to pod netns paths, and mount the netns dir —
the same host-device privileges the eBPF agent already needs. B2b adds per-guest
af_xdp port hotplug (BPF + xsk, already present for the uplink). These become
explicit requirements for the B3 DaemonSet, so B3 is written against a settled
model rather than guessed.

## Testing (dev, no NIC / no traffic)

1. **`flowplane-device` tests:** `create_veth_pair` into a throwaway netns +
   assert host ifindex resolves, MACs/MTU set, guest end present in the netns;
   `delete_link` idempotent; `UnderlayIpam` allocate/release/mark_used +
   inference unit tests (moved with the code). Device-creating tests are
   `#[ignore]` + run under sudo (mirroring the eBPF attach tests) since `ip link`
   needs `CAP_NET_ADMIN`; IPAM/inference tests run unprivileged.
2. **DPDK `AttachInterface` integration test:** call `attach_interface` (veth) →
   assert the real `AttachInterfaceResponse` fields, that `program_interface`
   populated the shared maps (readable via the `ControlCore`/registry), and a
   `PortRegistry` entry exists; `detach_interface` → device gone + registry entry
   dropped. Uses a throwaway netns; no EAL, no traffic. (`#[ignore]` + sudo for
   the device step.)
3. **eBPF attach suite stays green:** the Veth path now routes through
   `flowplane-device`; existing container attach tests (and clab) must be
   unchanged in behavior.
4. Non-root suites (`make test`/`sim`/`sim-anchor`) unaffected — control/host
   plane only.
