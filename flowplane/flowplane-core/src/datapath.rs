//! Substrate-agnostic datapath orchestrators shared by the eBPF program, the native `SimNode`
//! harness, and the DPDK NF (`nfkit`). These compose the REAL per-step core fns (`lb_select_forward`,
//! `reforward`, `fw_eval_dir`, `ct_create_default`, `decap_and_rewrite`, metering) in the exact order
//! and gates of the eBPF program tails, over any `Pkt` + `Maps` implementation. The SAME code thus
//! runs under the sim, under the `BPF_PROG_TEST_RUN` anchor, and on DPDK mbufs.

use flowplane_common::{Local, UnderlayValue, FW_ACTION_DROP, FW_DIR_INGRESS};

use crate::conntrack::{ct_create_default, ct_key};
use crate::encap::{reforward, ETH_LEN, IPV6_LEN};
use crate::firewall::fw_eval_dir;
use crate::lb::lb_select_forward;
use crate::maps::Maps;
use crate::pkt::{Action, Pkt};
use crate::uplink::decap_and_rewrite;

/// Inputs for [`process_uplink`]. `u` is `UNDERLAY[outer_dst]` (this node's resolved vni + base tap);
/// `outer_dst` is the encapped frame's current outer IPv6 dst; `local` supplies the outer
/// MACs/ifindex for an LB remote `reforward`; `now` is the monotonic clock (ns) the ingress-lane
/// meter stamps `last_ns` from (models `bpf_ktime_get_ns()`).
pub struct UplinkIn<'a> {
    pub vni: u32,
    pub u: UnderlayValue,
    pub outer_dst: [u8; 16],
    pub local: &'a Local,
    pub now: u64,
}

/// Host uplink_rx for the LB + base path, operating in place on `pkt`. Mirrors `try_uplink_rx`:
///   1. `lb_select_forward` → local backend (deliver to its tap) | remote (reforward, no decap)
///      | None (base tap);
///   2. ingress firewall on the inner 5-tuple against the deliver tap (new-flow gate);
///   3. conntrack create-on-miss, **skipped for LB** (DSR, no ct — `ingress.rs:266`);
///   4. decap + inner-Ethernet rewrite;
///   5. ingress-lane policing (keyed by dest tap).
///
/// Returns the final delivery `Action`, having mutated `pkt` in place.
pub fn process_uplink<P: Pkt, M: Maps>(pkt: &mut P, maps: &mut M, in_: &UplinkIn) -> Action {
    let inner_off = ETH_LEN + IPV6_LEN;

    // 1. LB dispatch (mirror ingress.rs:135-157).
    let lb_ul = lb_select_forward(&*pkt, &*maps, inner_off, in_.vni);
    let (tap, guest_mac, is_lb) = match lb_ul {
        Some(bul) => match maps.underlay_get(&bul) {
            Some(bu) => (bu.tap_ifindex, bu.guest_mac, true), // LB backend local
            None => {
                // Remote backend: reforward the encapped frame, no decap.
                return reforward(pkt, in_.local, &in_.outer_dst, &bul);
            }
        },
        None => (in_.u.tap_ifindex, in_.u.guest_mac, false), // non-LB base
    };

    // 2. Ingress firewall on NEW inbound flows against the deliver tap.
    if let Some(key) = ct_key(&*pkt, inner_off, in_.vni) {
        if maps.conntrack_get(&key).is_none()
            && fw_eval_dir(&*pkt, &*maps, inner_off, tap, FW_DIR_INGRESS) == FW_ACTION_DROP
        {
            return Action::Drop;
        }
    }

    // 3. Conntrack: create on miss, but ONLY for non-LB (LB is DSR — no ct, ingress.rs:266).
    if !is_lb {
        if let Some(key) = ct_key(&*pkt, inner_off, in_.vni) {
            if maps.conntrack_get(&key).is_none() {
                ct_create_default(&*pkt, maps, inner_off, in_.vni, 0);
            }
        }
    }

    // 4. Decap outer Eth+IPv6 and rewrite the inner Ethernet for the guest.
    let action = match decap_and_rewrite(pkt, tap, guest_mac) {
        Ok(a) => a,
        Err(_) => Action::Drop,
    };
    if action == Action::Drop {
        return action;
    }

    // 5. Ingress-lane policing (keyed by dest tap) — mirrors ingress.rs uplink_rx. Post-decap inner
    // length is the frame delivered to the guest. No cap => pass.
    let in_len = pkt.len() as u64;
    if !crate::meter::ingress_pass(maps, tap, in_len, in_.now) {
        return Action::Drop;
    }

    action
}
