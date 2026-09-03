//! Geneve `collect_md` tunnel-key stamping for the overlay-egress path.
//!
//! Replaces the old byte-written outer Eth+IPv6 header: instead of growing the skb and writing an
//! outer frame by hand, the tc programs stamp the resolved [`TunnelEncap`] decision as the skb's
//! tunnel-key metadata dst via `bpf_skb_set_tunnel_key`, then redirect to the kernel's `collect_md`
//! Geneve device (Task 1). The geneve device reads the metadata dst back on transmit and builds the
//! real outer Eth/IPv6/UDP/Geneve header itself.
//!
//! `bpf_skb_set_tunnel_key` is an skb-only helper (tc/cls_act, cgroup_skb, sock_ops, sk_skb,
//! cgroup_sock_addr) — it has no XDP counterpart, since XDP runs before skb allocation (pre
//! `collect_md` metadata dst). So this module is used ONLY by the tc guest-egress path
//! (`tc.rs`/`nat64.rs`). The uplink/WAN-edge XDP programs (`ingress.rs`) cannot adopt it without
//! first migrating to tc — that conversion is out of scope here (see `xdp_encap.rs`).

use aya_ebpf::{
    bindings::{__sk_buff, bpf_tunnel_key},
    helpers::{bpf_redirect, gen::bpf_skb_set_tunnel_key},
};
use flowplane_core::encap::TunnelEncap;

/// `BPF_F_TUNINFO_IPV6` (`include/uapi/linux/bpf.h`): tells `bpf_skb_set_tunnel_key` the
/// `remote_ipv6` union arm of `bpf_tunnel_key` is populated, not `remote_ipv4`. Mirrored as a raw
/// value here — aya-ebpf-bindings emits the kernel's `BPF_F_TUNINFO_IPV6` as an untyped bindgen
/// anonymous-enum constant, awkward to reference directly from a `u64` call site.
const BPF_F_TUNINFO_IPV6: u64 = 1;

/// Fixed outer hop limit for every Geneve-encapped overlay frame — the underlay fabric is a single
/// administrative hop count budget, not something the inner route/backend selection varies.
const TUNNEL_TTL: u8 = 64;

/// Stamp `tunnel` (VNI + remote underlay) as `skb`'s Geneve tunnel key (`collect_md` metadata dst).
/// Returns `false` on a helper failure (caller should drop rather than redirect an unstamped skb).
#[inline(always)]
pub fn set_tunnel_key(skb: *mut __sk_buff, tunnel: &TunnelEncap) -> bool {
    // SAFETY: `key` is a plain-old-data struct fully zeroed before any field is read; the two fields
    // set outside the union (`tunnel_id`, `tunnel_ttl`) are non-union `bpf_tunnel_key` members. The
    // `remote_ipv6` union arm is populated via a raw 16-byte copy — the same "copy the IPv6 address
    // bytes straight into the union's u32 slots" idiom `fib_nexthop`'s `bpf_fib_lookup` glue used for
    // its own anonymous `ipv6_dst` union, so the byte layout matches what the kernel expects (no
    // per-word byte-swap: the bytes are already network-order, verbatim).
    let mut key: bpf_tunnel_key = unsafe { core::mem::zeroed() };
    key.tunnel_id = tunnel.vni;
    key.tunnel_ttl = TUNNEL_TTL;
    unsafe {
        core::ptr::copy_nonoverlapping(
            tunnel.remote.as_ptr(),
            core::ptr::addr_of_mut!(key.__bindgen_anon_1) as *mut u8,
            16,
        );
    }
    let ret = unsafe {
        bpf_skb_set_tunnel_key(
            skb,
            &mut key as *mut bpf_tunnel_key,
            core::mem::size_of::<bpf_tunnel_key>() as u32,
            BPF_F_TUNINFO_IPV6,
        )
    };
    ret == 0
}

/// Redirect the (already tunnel-key-stamped) skb to the geneve `collect_md` device, which builds the
/// outer frame from the metadata dst `set_tunnel_key` just stamped and transmits it. Returns the tc
/// verdict (`TC_ACT_REDIRECT` on success).
#[inline(always)]
pub fn redirect() -> i32 {
    unsafe { bpf_redirect(crate::maps::geneve_ifindex(), 0) as i32 }
}
