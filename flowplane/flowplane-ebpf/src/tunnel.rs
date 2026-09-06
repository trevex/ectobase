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
    cty::c_void,
    helpers::{
        bpf_redirect,
        gen::{
            bpf_skb_get_tunnel_key, bpf_skb_get_tunnel_opt, bpf_skb_set_tunnel_key,
            bpf_skb_set_tunnel_opt,
        },
    },
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

/// Recover the Geneve tunnel key the kernel's `collect_md` ingress device stamped on `skb` as it
/// decapped: the VNI (`tunnel_id`) and the sender's remote underlay (`remote_ipv6`). Counterpart to
/// [`set_tunnel_key`] for the ingress direction. Returns `None` on a helper failure (no tunnel
/// metadata present — e.g. the skb did not arrive via the geneve device).
#[inline(always)]
pub fn get_tunnel_key(skb: *mut __sk_buff) -> Option<(u32, [u8; 16])> {
    // SAFETY: `key` is a plain-old-data struct fully zeroed before any field is read; the helper
    // fills it in on success. See `set_tunnel_key` for why the `remote_ipv6` union arm is read via a
    // raw 16-byte copy (no per-word byte-swap: the bytes are already network-order, verbatim).
    let mut key: bpf_tunnel_key = unsafe { core::mem::zeroed() };
    let ret = unsafe {
        bpf_skb_get_tunnel_key(
            skb,
            &mut key as *mut bpf_tunnel_key,
            core::mem::size_of::<bpf_tunnel_key>() as u32,
            BPF_F_TUNINFO_IPV6,
        )
    };
    if ret != 0 {
        return None;
    }
    let mut remote = [0u8; 16];
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(key.__bindgen_anon_1) as *const u8,
            remote.as_mut_ptr(),
            16,
        );
    }
    Some((key.tunnel_id, remote))
}

/// Total Geneve DSR option buffer = 4-byte Geneve option header + 20-byte payload (candidate layout;
/// the B1 spike confirms/freezes this).
pub const DSR_OPT_BUF_LEN: u32 = 24;

/// Attach a Geneve TLV to the skb tunnel metadata. MUST be called AFTER [`set_tunnel_key`] — the
/// kernel's `collect_md` Geneve device only serializes an option alongside a tunnel key that is
/// already staged on the skb. `buf` is the RAW option bytes INCLUDING the 4-byte Geneve option
/// header (class/type/len); there is no separate flags parameter (unlike `set_tunnel_key`'s
/// `BPF_F_TUNINFO_IPV6` — `bpf_skb_set_tunnel_opt` takes only the buffer + its length). Returns
/// `false` on a helper failure.
#[inline(always)]
pub fn set_tunnel_opt(skb: *mut __sk_buff, buf: &[u8; DSR_OPT_BUF_LEN as usize]) -> bool {
    // SAFETY: `buf` is a valid, fully-initialized `DSR_OPT_BUF_LEN`-byte buffer for the duration of
    // this call; the helper only reads from it.
    let ret = unsafe { bpf_skb_set_tunnel_opt(skb, buf.as_ptr() as *mut c_void, DSR_OPT_BUF_LEN) };
    ret == 0
}

/// Apply a core `TunnelEncap` to the skb: set the tunnel key. Key-only — `TunnelEncap` no longer
/// carries a DSR option (B7b relocated it to `WanRxOut::dsr`, since only the edge `wan_rx` encode
/// ever sets it); the `wan_rx` program stamps the DSR Geneve TLV itself, via `set_tunnel_opt`,
/// right after calling this. Every other `apply_encap` caller (uplink execute, nat64, tc
/// guest_tx x2) never carries a DSR option, so key-only is correct for them too.
#[inline(always)]
pub fn apply_encap(skb: *mut __sk_buff, tunnel: &TunnelEncap) -> bool {
    set_tunnel_key(skb, tunnel)
}

/// Read the Geneve TLV off the skb tunnel metadata (counterpart to [`set_tunnel_opt`] for the
/// ingress/decap direction). Returns the helper's raw return value: `>= 0` means the option was
/// present (and `buf` was filled), `< 0` means no option (or another helper error) — `buf` should
/// not be trusted in that case.
#[inline(always)]
pub fn get_tunnel_opt(skb: *mut __sk_buff, buf: &mut [u8; DSR_OPT_BUF_LEN as usize]) -> i64 {
    // SAFETY: `buf` is a valid, writable `DSR_OPT_BUF_LEN`-byte buffer for the duration of this call.
    unsafe { bpf_skb_get_tunnel_opt(skb, buf.as_mut_ptr() as *mut c_void, DSR_OPT_BUF_LEN) as i64 }
}

/// Redirect the (already tunnel-key-stamped) skb to the geneve `collect_md` device, which builds the
/// outer frame from the metadata dst `set_tunnel_key` just stamped and transmits it. Returns the tc
/// verdict (`TC_ACT_REDIRECT` on success).
#[inline(always)]
pub fn redirect() -> i32 {
    unsafe { bpf_redirect(crate::maps::geneve_ifindex(), 0) as i32 }
}
