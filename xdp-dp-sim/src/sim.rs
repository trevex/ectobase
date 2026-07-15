//! Native `SimNode` that runs the REAL `xdp_dp_core` datapath fns over the sim `VecPkt`/`MemMaps`.
//! No parallel reimplementation: `edge_encap` calls `write_outer_v6`; `host_uplink` composes
//! `fw_eval_dir` + `ct_create_default` + `decap_and_rewrite` in the exact order + gates of the
//! eBPF `try_uplink_rx` base-delivery tail.

use xdp_dp_common::{FW_ACTION_DROP, FW_DIR_INGRESS};
use xdp_dp_core::conntrack::{ct_create_default, ct_key};
use xdp_dp_core::encap::{write_outer_v6, EncapParams, ETH_LEN, IPV6_LEN};
use xdp_dp_core::firewall::fw_eval_dir;
use xdp_dp_core::maps::Maps;
use xdp_dp_core::pkt::{Action, Pkt};
use xdp_dp_core::uplink::decap_and_rewrite;

use crate::maps::MemMaps;
use crate::pkt::VecPkt;

/// A native node running the shared eBPF datapath core over in-memory maps.
pub struct SimNode {
    pub maps: MemMaps,
}

/// Result of `host_uplink`: the delivery `Action` plus the resulting (decapped) frame bytes.
pub struct SimOut {
    pub action: Action,
    pub pkt: Vec<u8>,
}

impl Default for SimNode {
    fn default() -> Self {
        Self::new()
    }
}

impl SimNode {
    pub fn new() -> Self {
        Self {
            maps: MemMaps::default(),
        }
    }

    /// Edge: encapsulate a full guest Ethernet frame `[InnerEth(14)][IPv4 ...]` toward `nexthop`,
    /// producing `[OuterEth(14)][OuterIPv6(40)][bare IPv4 ...]` — the exact fabric wire format the
    /// eBPF egress path emits. Byte-identical to the real encap: `grow_head(40)` prepends 40 bytes,
    /// then the 54-byte outer header write consumes the 40 new bytes AND the 14-byte inner Ethernet,
    /// leaving the bare inner IPv4 (inner_proto=IPIP, inner_len = IPv4 length = frame len - 14).
    pub fn edge_encap(&self, inner_frame: &[u8], mut e: EncapParams) -> Vec<u8> {
        assert!(
            inner_frame.len() >= ETH_LEN,
            "inner_frame must be a full Eth+IPv4 frame"
        );
        let mut p = VecPkt::from_bytes(inner_frame);
        assert!(p.grow_head(IPV6_LEN));
        e.inner_len = (inner_frame.len() - ETH_LEN) as u16; // bare inner IPv4 length
        assert!(write_outer_v6(&mut p, &e));
        p.into_bytes()
    }

    /// Host: run the REAL base uplink path (ingress firewall on new+enforcing, conntrack create on
    /// miss, then decap + inner-Ethernet rewrite) on an encapped frame. Mirrors the eBPF
    /// `try_uplink_rx` tail's ordering and gates. Returns the final `Action` + decapped bytes.
    ///
    /// The inner IPv4 is at `ETH_LEN + IPV6_LEN` pre-decap (outer Eth+IPv6 precede the bare IPv4).
    pub fn host_uplink(
        &mut self,
        encapped: &[u8],
        vni: u32,
        tap: u32,
        guest_mac: [u8; 6],
    ) -> SimOut {
        use xdp_dp_core::encap::ETH_LEN;
        let inner_off = ETH_LEN + IPV6_LEN;
        let mut pkt = VecPkt::from_bytes(encapped);

        // 1. Ingress firewall: enforce the tap's INGRESS rules on NEW inbound flows only.
        if let Some(key) = ct_key(&pkt, inner_off, vni) {
            if self.maps.conntrack_get(&key).is_none()
                && fw_eval_dir(&pkt, &self.maps, inner_off, tap, FW_DIR_INGRESS) == FW_ACTION_DROP
                && self.maps.fw_enforcing()
            {
                return SimOut {
                    action: Action::Drop,
                    pkt: pkt.into_bytes(),
                };
            }
        }

        // 2. Conntrack: create a DEFAULT entry on miss (base path, non-LB/non-NAT). `now`=0 in sim.
        if let Some(key) = ct_key(&pkt, inner_off, vni) {
            if self.maps.conntrack_get(&key).is_none() {
                ct_create_default(&pkt, &mut self.maps, inner_off, vni, 0);
            }
            // else: eBPF calls ct_touch (last_seen refresh) — a no-op for observable base state.
        }

        // 3+4. Decap outer Eth+IPv6 and rewrite the inner Ethernet for the guest.
        let action = match decap_and_rewrite(&mut pkt, tap, guest_mac) {
            Ok(a) => a,
            Err(()) => Action::Drop,
        };
        SimOut {
            action,
            pkt: pkt.into_bytes(),
        }
    }
}
