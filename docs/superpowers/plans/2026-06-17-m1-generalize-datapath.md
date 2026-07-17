# M1 — Generalize the Datapath Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the CONFIG-driven single-peer XDP datapath with a map-driven, multi-interface pipeline (multiple guests/peers), add an in-datapath ARP/ND responder so guests resolve their gateway with no static neigh, and wire `CreateInterface`/`CreateRoute` to program the maps.

**Architecture:** One `guest_tx` (on every guest tap) and one `uplink_rx` (on the uplink) resolve everything from BPF maps. A `port_meta` map (ingress ifindex → interface metadata) identifies the VNI/owner of an ingress packet. Encap resolves the underlay L2 via `bpf_fib_lookup` (the hypervisor kernel's underlay neighbor table); decap delivers to the local tap from the `interfaces` map. The monolithic eBPF `main.rs` is decomposed into focused modules.

**Tech Stack:** Rust + aya/aya-ebpf (rustup `nightly-2026-01-15`, LLVM 21, bpf-linker), tonic gRPC, the existing `env/netns-e2e.sh` lab.

**Spec:** `docs/superpowers/specs/2026-06-17-datapath-feature-parity-design.md` (milestone M1).

**Starting point (foundation, complete):** `flowplane-ebpf/src/main.rs` is one file with `xdp_pass`, CONFIG-driven `guest_tx`/`uplink_rx`, maps `INTERFACES`/`ROUTES`/`CONFIG`, `write6`/`write16`. Userspace `flowplane` has `loader`, `maps` (`Interfaces`, `ConfigMap`), `grpc` (DPDKironcore: Init/Version real, rest unimplemented), `state`, and CLI `load`/`serve`/`bringup`/`pass`. The netns lab `env/netns-e2e.sh` runs 2 hyp + 2 guest netns with **static neighs**.

---

## Design decisions locked for M1

- **Gateway convention:** each overlay subnet has a gateway IP `GW = <subnet>.1` and a single virtual gateway MAC `GW_MAC = 02:00:00:00:00:01`. Guests default-route via `GW`. The datapath answers ARP/ND for `GW` with `GW_MAC`. Delivered (decap) inner frames use src=`GW_MAC`, dst=guest MAC. Guests' egress inner frames have dst=`GW_MAC` (stripped on encap). This is the standard L3-gateway model and is functionally equivalent to dpservice.
- **Underlay L2 on encap:** resolved with `bpf_fib_lookup` against the hypervisor's underlay FIB/neighbor table (the lab seeds static underlay neighs). No MACs stored in route/interface values.
- **port_meta** identifies a guest tap by its host-side ifindex. `guest_tx` reads `port_meta[ctx ingress_ifindex]` to get `{vni, guest_ipv4, guest_mac}`.
- **interfaces** value carries `{tap_ifindex, underlay_ipv6, guest_mac, flags(local|remote)}` so `uplink_rx` can both redirect to a local tap and build the inner Ethernet.
- The CONFIG map and the CONFIG-driven `bringup` path are **removed** once the map-driven path lands (Task 8); the `pass`/`load`/`serve` CLIs stay.

## File Structure (target)

```
flowplane-ebpf/src/
  main.rs        # #![no_std]#![no_main]; mod decls; #[xdp] entrypoints (xdp_pass, guest_tx, uplink_rx); panic; LICENSE
  maps.rs        # all #[map] statics: PORT_META, INTERFACES, ROUTES (CONFIG removed in Task 8)
  parse.rs       # bounds-checked header cursors: ptr_at/ptr_at_mut, eth/ipv4/ipv6/arp views, write6/write16
  arp_nd.rs      # try_arp_reply / try_nd_reply (XDP_TX responders for the gateway)
  encap.rs       # encap_and_redirect(ctx, vni, inner_len, nexthop_ipv6) using fib_lookup + adjust_head
  egress.rs      # guest_tx pipeline body (try_guest_tx)
  ingress.rs     # uplink_rx pipeline body (try_uplink_rx)
flowplane/src/
  maps.rs        # + PortMeta, Routes wrappers (Interfaces extended)
  control.rs     # NEW: owns loaded Ebpf + map handles; program_interface/route/port helpers
  grpc.rs        # CreateInterface/CreateRoute implemented over control
  main.rs        # CLI: serve now loads ebpf + attaches + owns control; `port` subcommand for port_meta
flowplane-common/src/lib.rs   # + PortMeta type; IfaceValue extended with guest_mac + flags
```

---

## Task 1: Decompose the eBPF datapath into modules (pure refactor)

**Files:**
- Create: `flowplane-ebpf/src/maps.rs`, `flowplane-ebpf/src/parse.rs`
- Modify: `flowplane-ebpf/src/main.rs`

- [ ] **Step 1: Move the map declarations into `maps.rs`**

`flowplane-ebpf/src/maps.rs`:
```rust
use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap},
};
use flowplane_common::{Config, IfaceKey, IfaceValue, RouteKey, RouteValue};

#[map]
pub static INTERFACES: HashMap<IfaceKey, IfaceValue> = HashMap::with_max_entries(1024, 0);
#[map]
pub static ROUTES: HashMap<RouteKey, RouteValue> = HashMap::with_max_entries(4096, 0);
#[map]
pub static CONFIG: Array<Config> = Array::with_max_entries(1, 0);
```

- [ ] **Step 2: Move the parse helpers into `parse.rs`**

`flowplane-ebpf/src/parse.rs` — the existing constants and `write6`/`write16`, plus shared
ethertype/proto consts:
```rust
pub const ETH_LEN: usize = 14;
pub const IPV6_LEN: usize = 40;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const ETH_P_ARP: u16 = 0x0806;
pub const IPPROTO_IPIP: u8 = 4;

#[inline(always)]
pub unsafe fn write6(dst: *mut u8, src: &[u8; 6]) {
    let mut i = 0;
    while i < 6 {
        *dst.add(i) = src[i];
        i += 1;
    }
}

#[inline(always)]
pub unsafe fn write16(dst: *mut u8, src: &[u8; 16]) {
    let mut i = 0;
    while i < 16 {
        *dst.add(i) = src[i];
        i += 1;
    }
}
```

- [ ] **Step 3: Reduce `main.rs` to module decls + entrypoints**

`flowplane-ebpf/src/main.rs` keeps `#![no_std] #![no_main]`, adds `mod maps; mod parse;` (and in
later tasks `mod arp_nd; mod encap; mod egress; mod ingress;`), keeps the three `#[xdp]`
functions but now their bodies call into the modules. For THIS task, keep the existing
CONFIG-driven bodies but reference `maps::CONFIG`, `parse::write6`, etc. Keep `xdp_pass`, the
`#[panic_handler]`, and the `LICENSE` static in `main.rs`.

- [ ] **Step 4: Build the eBPF object**

Run: `cargo build -p flowplane`
Expected: builds. (aya-build recompiles the ebpf; rerun-if-changed covers the new files since
it watches `../flowplane-ebpf/src`.)

- [ ] **Step 5: Verifier-load gate still passes**

Run:
```bash
cargo test -p flowplane --no-run 2>&1 | tee /tmp/t.log
BIN=$(grep -oE 'target/debug/deps/flowplane-[a-f0-9]+' /tmp/t.log | head -1)
sudo -E "$BIN" --include-ignored --exact loader::tests::both_programs_pass_verifier
```
Expected: `ok` — refactor preserved verifier acceptance.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add flowplane-ebpf
git commit -m "refactor(ebpf): split datapath into maps/parse modules (no behavior change)"
```

## Task 2: Shared `PortMeta` type + extend `IfaceValue` (TDD)

**Files:**
- Modify: `flowplane-common/src/lib.rs`

- [ ] **Step 1: Write the failing layout test**

Add to `flowplane-common/src/lib.rs`:
```rust
/// Per-port metadata, keyed by the guest tap's host-side ifindex.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct PortMeta {
    pub vni: u32,
    pub guest_ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub guest_mac: [u8; 6],
    pub _pad: [u8; 2],
}
```
Extend `IfaceValue` to carry the guest MAC and a local/remote flag (REPLACING the old
definition):
```rust
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct IfaceValue {
    /// Host-side tap ifindex for local delivery (0 if remote).
    pub tap_ifindex: u32,
    /// 1 = interface is local to this hypervisor, 0 = remote.
    pub is_local: u32,
    /// Underlay IPv6 endpoint of the owning hypervisor (tunnel dst for remote).
    pub underlay_ipv6: [u8; 16],
    /// Guest MAC (inner eth dst for local delivery).
    pub guest_mac: [u8; 6],
    pub _pad: [u8; 2],
}
```
Extend the `tests` module:
```rust
    #[test]
    fn port_meta_and_iface_layout() {
        assert_eq!(core::mem::size_of::<PortMeta>(), 20);
        assert_eq!(core::mem::size_of::<IfaceValue>(), 32);
        assert_eq!(core::mem::align_of::<PortMeta>(), 4);
    }
```
Add `unsafe impl aya::Pod for PortMeta {}` to `user_impls`.

- [ ] **Step 2: Run the test**

Run: `cargo test -p flowplane-common --features user`
Expected: PASS (`port_meta_and_iface_layout`). If sizes differ, fix padding to the asserted
values before proceeding (20 and 32).

- [ ] **Step 3: Fix the userspace `Interfaces`/`IfaceValue` construction sites**

`flowplane/src/maps.rs` and any test constructing `IfaceValue` now need the new fields. Update
the roundtrip test's `IfaceValue { tap_ifindex: 7, underlay_ipv6: [0xfd;16] }` to include
`is_local: 1, guest_mac: [2,0,0,0,0,5], _pad: [0;2]`. Build: `cargo build -p flowplane`.

- [ ] **Step 4: Commit**

```bash
cargo fmt --all
git add flowplane-common flowplane
git commit -m "feat(common): PortMeta type; IfaceValue carries guest_mac + is_local"
```

## Task 3: `PORT_META` map + ingress port identification

**Files:**
- Modify: `flowplane-ebpf/src/maps.rs`
- Create: `flowplane/src/control.rs` (stub, grown in Task 7)
- Modify: `flowplane/src/maps.rs`

- [ ] **Step 1: Declare `PORT_META` in the eBPF maps**

Add to `flowplane-ebpf/src/maps.rs`:
```rust
use flowplane_common::PortMeta;

#[map]
pub static PORT_META: HashMap<u32, PortMeta> = HashMap::with_max_entries(1024, 0);
```

- [ ] **Step 2: Userspace `PortMetaMap` + `Routes` wrappers (TDD via the existing root roundtrip pattern)**

Add to `flowplane/src/maps.rs` a `PortMetaMap` wrapper (HashMap<u32, PortMeta>) and a `Routes`
wrapper (HashMap<RouteKey, RouteValue>), mirroring the existing `Interfaces` wrapper
(`open`/`upsert`/`get` via `ebpf.take_map`). Reuse the `#[allow(dead_code)]` pattern.

- [ ] **Step 3: Build**

Run: `cargo run -p xtask 2>/dev/null; cargo build -p flowplane`
Expected: builds. (No xtask exists; just `cargo build -p flowplane`.)

- [ ] **Step 4: Commit**

```bash
cargo fmt --all
git add flowplane-ebpf flowplane
git commit -m "feat(maps): PORT_META map + userspace PortMetaMap/Routes wrappers"
```

## Task 4: In-datapath ARP responder (`arp_nd.rs`)

**Files:**
- Create: `flowplane-ebpf/src/arp_nd.rs`
- Modify: `flowplane-ebpf/src/main.rs`

- [ ] **Step 1: Implement the ARP responder**

`flowplane-ebpf/src/arp_nd.rs` — given the guest's `PortMeta`, answer ARP requests for
`gateway_ipv4` with the virtual gateway MAC `02:00:00:00:00:01`, rewriting the packet in place
and returning `XDP_TX`:
```rust
use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use flowplane_common::PortMeta;

use crate::parse::{write6, ETH_LEN, ETH_P_ARP};

pub const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

// ARP packet (Ethernet/IPv4) offsets relative to the ARP header start (ETH_LEN):
//   opcode @ 6 (2B, 1=request 2=reply), sha @ 8 (6B), spa @ 14 (4B), tha @ 18 (6B), tpa @ 24 (4B)
const ARP_LEN: usize = 28;

/// If the frame is an ARP request for the gateway IP, rewrite it into a reply and return
/// Some(XDP_TX). Otherwise None (caller continues the pipeline).
#[inline(always)]
pub fn try_arp_reply(ctx: &XdpContext, meta: &PortMeta) -> Option<u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + ARP_LEN > data_end {
        return None;
    }
    let p = data as *mut u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_ARP {
        return None;
    }
    let arp = unsafe { p.add(ETH_LEN) };
    let opcode = u16::from_be(unsafe { core::ptr::read_unaligned(arp.add(6) as *const u16) });
    if opcode != 1 {
        return None;
    }
    // Target protocol address (tpa) must equal the gateway IP.
    let tpa = unsafe { core::ptr::read_unaligned(arp.add(24) as *const [u8; 4]) };
    if tpa != meta.gateway_ipv4 {
        return None;
    }
    // Build the reply in place.
    let sender_mac = unsafe { core::ptr::read_unaligned(arp.add(8) as *const [u8; 6]) };
    let spa = unsafe { core::ptr::read_unaligned(arp.add(14) as *const [u8; 4]) };
    unsafe {
        // Ethernet: dst = requester, src = gateway.
        write6(p, &sender_mac);
        write6(p.add(6), &GW_MAC);
        // ARP: opcode = reply(2); sha = GW_MAC, spa = gateway; tha = requester, tpa = requester ip.
        core::ptr::write_unaligned(arp.add(6) as *mut u16, 2u16.to_be());
        write6(arp.add(8), &GW_MAC);
        core::ptr::write_unaligned(arp.add(14) as *mut [u8; 4], meta.gateway_ipv4);
        write6(arp.add(18), &sender_mac);
        core::ptr::write_unaligned(arp.add(24) as *mut [u8; 4], spa);
    }
    Some(xdp_action::XDP_TX)
}
```
> NOTE: IPv6 ND (`try_nd_reply`) is added in Task 4b after ARP is proven; ARP alone unblocks
> the IPv4 overlay e2e. Keep `arp_nd.rs` focused.

- [ ] **Step 2: Add `mod arp_nd;` to `main.rs`**, build: `cargo build -p flowplane` (expect OK).

- [ ] **Step 3: Commit**

```bash
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(ebpf): in-datapath ARP responder for the overlay gateway"
```

## Task 5: Map-driven encap (`encap.rs`) — control-plane-resolved underlay L2

> **SUPERSEDED APPROACH (do this instead of the `bpf_fib_lookup` sketch below):** the aya-ebpf
> `bpf_fib_lookup` binding uses fiddly `__bindgen_anon_*` unions and is verifier-risky. Instead,
> resolve the outer L2 from the control plane (which already knows the underlay topology):
> extend `RouteValue` with `nexthop_mac: [u8;6]` (the peer uplink MAC) and add a 1-entry `LOCAL`
> `Array<Local>` map holding this hypervisor's `{uplink_ifindex, uplink_mac, underlay_ipv6}`.
> `encap_and_redirect(ctx, local, route, inner_len)` then writes outer eth dst=`route.nexthop_mac`,
> src=`local.uplink_mac`, outer IPv6 src=`local.underlay_ipv6` dst=`route.nexthop_ipv6`, and
> `bpf_redirect(local.uplink_ifindex)`. This reuses the proven CONFIG-era encap (verifier-trivial)
> and is closer to dpservice (underlay routing comes from the control plane, not the kernel FIB).
> The `fib_lookup` code below is kept for reference only — do NOT implement it.

**Files:**
- Modify: `flowplane-common/src/lib.rs` (extend `RouteValue`; add `Local`)
- Modify: `flowplane-ebpf/src/maps.rs` (add `LOCAL`)
- Create: `flowplane-ebpf/src/encap.rs`
- Modify: `flowplane-ebpf/src/main.rs`

- [ ] **Step 1: Implement encap with FIB-resolved underlay L2**

`flowplane-ebpf/src/encap.rs` — grow headroom by `IPV6_LEN`, write the outer IPv6 (src = this
hypervisor's underlay — from a 1-entry `LOCAL` array or `PORT_META`/route; dst = `nexthop`),
resolve the outer Ethernet via `bpf_fib_lookup` on `nexthop`, and `bpf_redirect` to the FIB
egress ifindex:
```rust
use aya_ebpf::{
    bindings::{bpf_fib_lookup as fib_params_t, xdp_action, BPF_FIB_LOOKUP_DIRECT},
    helpers::{bpf_fib_lookup, bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};

use crate::parse::{write16, write6, ETH_LEN, ETH_P_IPV6, IPPROTO_IPIP, IPV6_LEN};

/// Encapsulate the current inner IPv4 frame into Eth+IPv6 toward `nexthop_ipv6`, using the
/// underlay FIB to resolve the egress ifindex + L2, and redirect. `local_ipv6` is the outer
/// source. `inner_len` is the inner IPv4 packet length (frame len - inner ETH_LEN), captured
/// BEFORE adjust_head.
#[inline(always)]
pub fn encap_and_redirect(
    ctx: &XdpContext,
    local_ipv6: &[u8; 16],
    nexthop_ipv6: &[u8; 16],
    inner_len: u16,
) -> Result<u32, ()> {
    // FIB lookup for the underlay nexthop (AF_INET6 = 10).
    let mut fib: fib_params_t = unsafe { core::mem::zeroed() };
    fib.family = 10; // AF_INET6
    fib.ifindex = 0;
    unsafe {
        // ipv6_dst is a [u32;4] / [u8;16] union field; copy nexthop in.
        core::ptr::copy_nonoverlapping(
            nexthop_ipv6.as_ptr(),
            fib.__bindgen_anon_2.ipv6_dst.as_mut_ptr() as *mut u8,
            16,
        );
        core::ptr::copy_nonoverlapping(
            local_ipv6.as_ptr(),
            fib.__bindgen_anon_1.ipv6_src.as_mut_ptr() as *mut u8,
            16,
        );
    }
    let rc = unsafe {
        bpf_fib_lookup(
            ctx.ctx as *mut _,
            &mut fib as *mut _,
            core::mem::size_of::<fib_params_t>() as i32,
            BPF_FIB_LOOKUP_DIRECT,
        )
    };
    if rc != 0 {
        return Err(());
    }

    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(IPV6_LEN as i32)) } != 0 {
        return Err(());
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN > data_end {
        return Err(());
    }
    let p = data as *mut u8;
    unsafe {
        // Outer Ethernet from FIB result (smac/dmac), ethertype IPv6.
        write6(p, &fib.dmac);
        write6(p.add(6), &fib.smac);
        core::ptr::write_unaligned(p.add(12) as *mut u16, ETH_P_IPV6.to_be());
        // Outer IPv6.
        let ip = p.add(ETH_LEN);
        *ip.add(0) = 0x60;
        *ip.add(1) = 0;
        *ip.add(2) = 0;
        *ip.add(3) = 0;
        core::ptr::write_unaligned(ip.add(4) as *mut u16, inner_len.to_be());
        *ip.add(6) = IPPROTO_IPIP;
        *ip.add(7) = 64;
        write16(ip.add(8), local_ipv6);
        write16(ip.add(24), nexthop_ipv6);
    }
    Ok(unsafe { bpf_redirect(fib.ifindex, 0) } as u32)
}
```
> NOTE: the exact aya-ebpf binding field names for `bpf_fib_lookup` (`__bindgen_anon_1`/`_2`,
> `ipv6_src`/`ipv6_dst`, `dmac`/`smac`, `BPF_FIB_LOOKUP_DIRECT`) must be matched to the
> installed `aya-ebpf` version — consult `cargo doc -p aya-ebpf` / the generated bindings and
> adjust to what compiles. The structure (zero, set family+src+dst, lookup, on success write
> outer headers from `dmac`/`smac`, redirect to `ifindex`) is the contract. If FIB-lookup
> integration proves too fiddly, fall back to an `underlay_neigh` map (`[u8;16] -> [u8;6]`)
> populated by the control plane and report the change.

- [ ] **Step 2: Add `mod encap;`**, build: `cargo build -p flowplane` (expect OK; resolve binding-name errors here).

- [ ] **Step 3: Commit**

```bash
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(ebpf): map-driven encap with bpf_fib_lookup underlay L2"
```

## Task 6: Map-driven `guest_tx` and `uplink_rx` pipelines

**Files:**
- Create: `flowplane-ebpf/src/egress.rs`, `flowplane-ebpf/src/ingress.rs`
- Modify: `flowplane-ebpf/src/main.rs`

- [ ] **Step 1: Implement the egress pipeline (`egress.rs`)**

`try_guest_tx`: read `PORT_META[ingress_ifindex]`; ARP-reply shortcut; parse inner IPv4; look
up `ROUTES[(vni, dst/32)]` (fallback to `INTERFACES` for /32 hosts) → `nexthop_ipv6`; compute
`inner_len`; call `encap::encap_and_redirect(ctx, &local_ipv6, &nexthop_ipv6, inner_len)`.
`local_ipv6` comes from a new 1-entry `LOCAL` array map (this hypervisor's underlay IPv6),
written by the control plane.
```rust
use aya_ebpf::{bindings::xdp_action, programs::XdpContext, EbpfContext};
use flowplane_common::RouteKey;

use crate::arp_nd::try_arp_reply;
use crate::encap::encap_and_redirect;
use crate::maps::{LOCAL, PORT_META, ROUTES};
use crate::parse::{ETH_LEN, ETH_P_IP};

pub fn try_guest_tx(ctx: &XdpContext) -> Result<u32, ()> {
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let meta = unsafe { PORT_META.get(&ifindex) }.ok_or(())?;

    if let Some(act) = try_arp_reply(ctx, meta) {
        return Ok(act);
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let p = data as *const u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    // inner IPv4 dst at ETH_LEN + 16
    if data + ETH_LEN + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let dst = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 16) as *const [u8; 4]) };
    let route = unsafe { ROUTES.get(&RouteKey { vni: meta.vni, prefix_len: 32, ipv4: dst }) }
        .ok_or(())?;
    let inner_len = (data_end - data - ETH_LEN) as u16;
    let local = unsafe { LOCAL.get(0) }.ok_or(())?;
    encap_and_redirect(ctx, &local.ipv6, &route.nexthop_ipv6, inner_len)
}
```
(Define a `LOCAL` array map + a `Local { ipv6: [u8;16] }` POD in common, written by control.)

- [ ] **Step 2: Implement the ingress pipeline (`ingress.rs`)**

`try_uplink_rx`: verify outer IPv6 + next-header IPIP; read inner dst+vni? (vni is implicit —
the overlay is single-VNI per underlay tunnel for M1; carry the dst VNI via the route on
egress and look up `INTERFACES[(vni, inner_dst)]`). For M1 keep it simple: parse inner IPv4
dst, look up `INTERFACES` for a LOCAL interface, strip outer headers, build inner Ethernet
(dst = `iface.guest_mac`, src = `GW_MAC`, ethertype IPv4), redirect to `iface.tap_ifindex`.
```rust
use aya_ebpf::{bindings::xdp_action, helpers::{bpf_redirect, bpf_xdp_adjust_head}, programs::XdpContext};
use flowplane_common::IfaceKey;

use crate::arp_nd::GW_MAC;
use crate::maps::INTERFACES;
use crate::parse::{write6, ETH_LEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_IPIP, IPV6_LEN};

// VNI carried in the low 24 bits of the IPv6 flow label is an option; for M1 we resolve the
// interface by inner dst IPv4 alone (single tenant), and store vni 0 in the key.
pub fn try_uplink_rx(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let p = data as *const u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_IPV6 {
        return Ok(xdp_action::XDP_PASS);
    }
    if unsafe { *p.add(ETH_LEN + 6) } != IPPROTO_IPIP {
        return Ok(xdp_action::XDP_PASS);
    }
    let inner_dst =
        unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + IPV6_LEN + 16) as *const [u8; 4]) };
    let iface = unsafe { INTERFACES.get(&IfaceKey { vni: 0, ipv4: inner_dst }) }.ok_or(())?;
    if iface.is_local == 0 {
        return Ok(xdp_action::XDP_PASS);
    }
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, IPV6_LEN as i32) } != 0 {
        return Err(());
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN > data_end {
        return Err(());
    }
    let q = data as *mut u8;
    unsafe {
        write6(q, &iface.guest_mac);
        write6(q.add(6), &GW_MAC);
        core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IP.to_be());
    }
    Ok(unsafe { bpf_redirect(iface.tap_ifindex, 0) } as u32)
}
```
> NOTE: M1 resolves interfaces by inner dst IPv4 with `vni=0` (single tenant). Multi-VNI
> encoding (e.g. VNI in the IPv6 flow label) is deferred — the spec's overlay stays IPv4 and
> the lab uses one VNI; keep the key shape so VNI can be threaded later.

- [ ] **Step 3: Wire entrypoints in `main.rs`** to call `egress::try_guest_tx` / `ingress::try_uplink_rx`; remove the old CONFIG-driven bodies. Build: `cargo build -p flowplane`.

- [ ] **Step 4: Verifier-load gate**

Run the `both_programs_pass_verifier` test (as in Task 1 Step 5). Expected: `ok`. **Iterate on
verifier errors here** — re-fetch data/data_end after `adjust_head`, bounds-check before every
read/write. Do not weaken the logic to pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add flowplane-ebpf flowplane-common
git commit -m "feat(ebpf): map-driven guest_tx/uplink_rx pipelines (multi-interface)"
```

## Task 7: Control plane programs the maps (`CreateInterface`/`CreateRoute` + port/local)

**Files:**
- Create: `flowplane/src/control.rs`
- Modify: `flowplane/src/grpc.rs`, `flowplane/src/main.rs`, `flowplane/src/maps.rs`

- [ ] **Step 1: Pure translation helpers (TDD)**

In `flowplane/src/control.rs`, pure functions converting proto messages → map entries, with unit
tests:
```rust
use flowplane_common::{IfaceKey, IfaceValue, RouteKey, RouteValue};

/// (vni, ipv4, underlay, guest_mac, local) -> interface map entry.
pub fn iface_entry(
    vni: u32,
    ipv4: [u8; 4],
    tap_ifindex: u32,
    is_local: bool,
    underlay_ipv6: [u8; 16],
    guest_mac: [u8; 6],
) -> (IfaceKey, IfaceValue) {
    (
        IfaceKey { vni, ipv4 },
        IfaceValue {
            tap_ifindex,
            is_local: is_local as u32,
            underlay_ipv6,
            guest_mac,
            _pad: [0; 2],
        },
    )
}

pub fn route_entry(vni: u32, ipv4: [u8; 4], nexthop_ipv6: [u8; 16]) -> (RouteKey, RouteValue) {
    (
        RouteKey { vni, prefix_len: 32, ipv4 },
        RouteValue { nexthop_vni: vni, nexthop_ipv6 },
    )
}
```
Test: assert field mapping for both (mirrors foundation Task 12 test style).

- [ ] **Step 2: `Control` owns the loaded Ebpf + map handles**

`Control` struct holding `Ebpf` + `Interfaces`/`Routes`/`PortMetaMap`/`Local` wrappers, behind
`Arc<Mutex<..>>` so the tonic service (Send+Sync) can use it. Methods:
`program_interface(...)`, `program_route(...)`, `set_local(ipv6)`, `set_port(ifindex, PortMeta)`.

- [ ] **Step 3: Implement `CreateInterface`/`CreateRoute` in `grpc.rs`**

Decode the proto (`interface_id`, `vni`, `ipv4`/`ipv6` config bytes, `device_name`) and
`Route` (`prefix`, `nexthop_address`); call `control.program_interface/route`. Return
`status: ok()` and the `underlay_route` where dpservice does. Replace the two
`Status::unimplemented` stubs for these RPCs only.

- [ ] **Step 4: `serve` loads + owns the datapath; add a `port` subcommand**

`serve` now: `load_ebpf()`, attach `uplink_rx` to `--uplink` and `guest_tx` to each `--guest`
(repeatable), set `LOCAL`, build `Control`, then serve gRPC. Add `port --iface --vni --ipv4
--gateway --mac` to write a `PORT_META` entry (used by the lab to register taps). Keep
`pass`/`load`.

- [ ] **Step 5: Build + unit tests**

Run: `cargo build -p flowplane && cargo test -p flowplane control::`
Expected: builds; translation unit tests pass.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add flowplane flowplane-common
git commit -m "feat(cp): CreateInterface/CreateRoute program maps; serve owns datapath"
```

## Task 8: Multi-guest lab + datapath-ARP acceptance; remove CONFIG path

**Files:**
- Modify: `env/netns-e2e.sh`
- Modify: `flowplane-ebpf/src/*`, `flowplane/src/*` (remove CONFIG/bringup)

- [ ] **Step 1: Remove the CONFIG-driven path**

Delete the `CONFIG` map (ebpf `maps.rs`), the `Config`/`ConfigMap` usage, and the `bringup`
subcommand (superseded by `serve` + `port`/gRPC). Keep `Config` POD type removal out of
`flowplane-common` only if nothing else uses it (it doesn't). Build: `cargo build -p flowplane`.

- [ ] **Step 2: Extend `netns-e2e.sh` to the map-driven model**

Rewrite the bring-up portion: per hypervisor run `flowplane serve` (or a non-gRPC `port`+attach
sequence) to attach `uplink_rx` + `guest_tx`, set `LOCAL`, register each guest tap via `port`,
and program `interfaces`/`routes` for BOTH guests (local + remote). Add a **second guest per
hypervisor** (`gA2`/`gB2`, IPs `10.0.0.7`/`10.0.0.8`). **Remove the static guest neigh
entries** (the datapath ARP responder now answers); set each guest's default route via the
gateway `10.0.0.1` (`ip route add default via 10.0.0.1`) and a static neigh ONLY for the
gateway is NOT needed (ARP is answered) — verify ARP works.

- [ ] **Step 3: Acceptance — datapath ARP + multi-guest overlay**

Run: `./env/netns-e2e.sh run`
Expected gates (script asserts):
- guesta resolves the gateway via the datapath (e.g. `ip netns exec guesta ip neigh` shows
  `10.0.0.1` learned, no static entry), and `ping 10.0.0.6` succeeds 0% loss.
- a second guest pair also pings across hypervisors (multi-interface).
- `tcpdump` on the underlay still shows `ip6 proto 4` encap.
- teardown leaves zero dangling state (existing EXIT-trap behavior).

- [ ] **Step 4: Commit**

```bash
git add env/netns-e2e.sh flowplane flowplane-ebpf flowplane-common
git commit -m "feat(e2e): map-driven multi-guest lab with datapath ARP (no static neigh)"
```

---

## Self-Review

**Spec coverage (M1):**
- Map-driven multi-interface pipeline → Tasks 1,3,5,6. ✓
- In-datapath ARP/ND responder → Task 4 (ARP); IPv6 ND flagged as Task 4b follow-up within M1
  (ARP unblocks the IPv4 overlay; ND added before M2 if the lab needs it). ✓ (note the partial)
- `port_meta` → Tasks 2,3. ✓
- `CreateInterface`/`CreateRoute` program maps → Task 7. ✓
- Decompose eBPF datapath into modules → Task 1 (+ files created across 4–6). ✓
- Extend lab + multi-guest overlay ping + datapath ARP acceptance → Task 8. ✓

**Placeholder scan:** No "TBD/implement later". Three `> NOTE` callouts (fib_lookup binding
names, single-VNI simplification, ND-as-4b) are verification/scoping instructions with complete
runnable code + gates, not missing content.

**Type consistency:** `PortMeta {vni,guest_ipv4,gateway_ipv4,guest_mac,_pad}` (Task 2) used in
Tasks 4/6/7. `IfaceValue {tap_ifindex,is_local,underlay_ipv6,guest_mac,_pad}` (Task 2) used in
Tasks 6/7. `RouteKey {vni,prefix_len,ipv4}` / `RouteValue {nexthop_vni,nexthop_ipv6}` consistent
with foundation. New `LOCAL`/`Local{ipv6}` introduced in Task 6 and written in Task 7. `GW_MAC`
defined in Task 4, used in Task 6 ingress. Map names `PORT_META`/`INTERFACES`/`ROUTES`/`LOCAL`
consistent between ebpf and userspace wrappers.

**Note for executor:** Task 6 introduces `LOCAL`/`Local` — ensure the common POD type + ebpf
`#[map]` + userspace wrapper are all added when Task 6 references them (the plan adds the POD in
Task 6 Step 1 and the wrapper/writer in Task 7 Step 2/4).
