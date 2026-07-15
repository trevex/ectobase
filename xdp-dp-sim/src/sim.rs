//! Native `SimNode` that runs the REAL `xdp_dp_core` datapath fns over the sim `VecPkt`/`MemMaps`.
//! No parallel reimplementation: `edge_encap` calls `write_outer_v6`; `uplink` composes the REAL
//! core fns — `lb_select_forward` + `reforward` + `fw_eval_dir` + `ct_create_default` +
//! `decap_and_rewrite` — in the exact order + gates of the eBPF `try_uplink_rx` LB/base tail
//! (`ingress.rs` 135-157 dispatch + 245-304 tail). The LB-dispatch glue is composed here (as it is
//! in the eBPF wrapper); the `BPF_PROG_TEST_RUN` anchor guards native==bytecode on the LB path.
//!
//! Scope: this harness models the LB-select + firewall + conntrack-create + decap/reforward tail.
//! The `try_uplink_rx` branches gated on `lb_ul.is_none()` — NAT64 reply, neighbor-NAT reforward,
//! ICMP-echo reply, and inner `dnat_ingress` — are NOT modeled (out of scope; separate follow-on
//! slices per the spec). For LB packets those branches are skipped anyway.

use xdp_dp_common::{Local, UnderlayValue, FW_ACTION_DROP, FW_DIR_INGRESS};
use xdp_dp_core::conntrack::{ct_create_default, ct_key};
use xdp_dp_core::encap::{reforward, write_outer_v6, EncapParams, ETH_LEN, IPV6_LEN};
use xdp_dp_core::firewall::fw_eval_dir;
use xdp_dp_core::lb::lb_select_forward;
use xdp_dp_core::maps::Maps;
use xdp_dp_core::pkt::{Action, Pkt};
use xdp_dp_core::uplink::decap_and_rewrite;

use crate::maps::MemMaps;
use crate::pkt::VecPkt;

/// A native node running the shared eBPF datapath core over in-memory maps.
pub struct SimNode {
    pub maps: MemMaps,
    /// This node's own underlay identity (uplink ifindex/MACs, underlay IPv6). Used by `wan_rx` and
    /// `run` to encapsulate or reforward without an external `Local` argument.
    pub local: Local,
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
            local: Local::default(),
        }
    }

    /// Construct a node with a pre-set underlay identity.
    pub fn with_local(local: Local) -> Self {
        Self {
            maps: MemMaps::default(),
            local,
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

    /// Host uplink_rx for the LB + base path. `u` is `UNDERLAY[outer_dst]` (this node's resolved
    /// vni + base tap); `outer_dst` is the encapped frame's current outer IPv6 dst; `local` supplies
    /// the outer MACs/ifindex for an LB remote `reforward`. Mirrors `try_uplink_rx`:
    ///   1. `lb_select_forward` → local backend (deliver to its tap) | remote (reforward, no decap)
    ///      | None (base tap);
    ///   2. ingress firewall on the inner 5-tuple against the deliver tap (new-flow gate);
    ///   3. conntrack create-on-miss, **skipped for LB** (DSR, no ct — `ingress.rs:266`);
    ///   4. decap + inner-Ethernet rewrite.
    /// Returns the final `Action` + the resulting frame bytes.
    pub fn uplink(
        &mut self,
        encapped: &[u8],
        vni: u32,
        u: UnderlayValue,
        outer_dst: [u8; 16],
        local: &Local,
    ) -> SimOut {
        let inner_off = ETH_LEN + IPV6_LEN;
        let mut pkt = VecPkt::from_bytes(encapped);

        // 1. LB dispatch (mirror ingress.rs:135-157).
        let lb_ul = lb_select_forward(&pkt, &self.maps, inner_off, vni);
        let (tap, guest_mac, is_lb) = match lb_ul {
            Some(bul) => match self.maps.underlay_get(&bul) {
                Some(bu) => (bu.tap_ifindex, bu.guest_mac, true), // LB backend local
                None => {
                    // Remote backend: reforward the encapped frame, no decap.
                    let action = reforward(&mut pkt, local, &outer_dst, &bul);
                    return SimOut {
                        action,
                        pkt: pkt.into_bytes(),
                    };
                }
            },
            None => (u.tap_ifindex, u.guest_mac, false), // non-LB base
        };

        // 2. Ingress firewall on NEW inbound flows against the deliver tap.
        if let Some(key) = ct_key(&pkt, inner_off, vni) {
            if self.maps.conntrack_get(&key).is_none()
                && fw_eval_dir(&pkt, &self.maps, inner_off, tap, FW_DIR_INGRESS) == FW_ACTION_DROP
            {
                return SimOut {
                    action: Action::Drop,
                    pkt: pkt.into_bytes(),
                };
            }
        }

        // 3. Conntrack: create on miss, but ONLY for non-LB (LB is DSR — no ct, ingress.rs:266).
        if !is_lb {
            if let Some(key) = ct_key(&pkt, inner_off, vni) {
                if self.maps.conntrack_get(&key).is_none() {
                    ct_create_default(&pkt, &mut self.maps, inner_off, vni, 0);
                }
            }
        }

        // 4. Decap outer Eth+IPv6 and rewrite the inner Ethernet for the guest.
        let action = match decap_and_rewrite(&mut pkt, tap, guest_mac) {
            Ok(a) => a,
            Err(()) => Action::Drop,
        };
        SimOut {
            action,
            pkt: pkt.into_bytes(),
        }
    }

    /// Convenience wrapper for a plain non-LB delivery to `tap` (used by `ns_scenario_test`): builds
    /// a base `UnderlayValue` and delegates to [`SimNode::uplink`]. With no LB maps set,
    /// `lb_select_forward` returns None and the base path runs.
    pub fn host_uplink(
        &mut self,
        encapped: &[u8],
        vni: u32,
        tap: u32,
        guest_mac: [u8; 6],
    ) -> SimOut {
        let u = UnderlayValue {
            vni,
            tap_ifindex: tap,
            guest_mac,
            _pad: [0; 2],
        };
        let local = Local {
            uplink_ifindex: 0,
            uplink_mac: [0; 6],
            gateway_mac: [0; 6],
            underlay_ipv6: [0; 16],
        };
        self.uplink(encapped, vni, u, [0u8; 16], &local)
    }

    /// Edge WAN-VIP ingress (`wan_rx`): a plain `[Eth][IPv4]` WAN frame; if its dst+port is a WAN LB
    /// VIP (vni=0), Maglev-select a backend and encap IP-in-IPv6 to the backend underlay. Else Pass.
    /// Mirrors `ingress.rs::try_wan_rx` VIP branch. Returns the encapped frame (or the input on Pass).
    pub fn wan_rx(&self, plain: &[u8]) -> SimOut {
        use xdp_dp_core::encap::ETH_LEN;
        match lb_select_forward(&VecPkt::from_bytes(plain), &self.maps, ETH_LEN, 0) {
            Some(backend) => {
                let e = EncapParams {
                    gateway_mac: self.local.gateway_mac,
                    uplink_mac: self.local.uplink_mac,
                    uplink_ifindex: self.local.uplink_ifindex,
                    src_underlay: self.local.underlay_ipv6,
                    nexthop_ipv6: backend,
                    inner_len: 0,   // edge_encap sets this
                    inner_proto: 4, // IPPROTO_IPIP
                };
                SimOut {
                    action: Action::Redirect(self.local.uplink_ifindex),
                    pkt: self.edge_encap(plain, e),
                }
            }
            None => SimOut {
                action: Action::Pass,
                pkt: plain.to_vec(),
            },
        }
    }

    /// Uniform entry for the Fabric. UplinkRx resolves `u = UNDERLAY[outer_dst]` from this node's maps.
    pub fn run(&mut self, prog: crate::fabric::Prog, pkt: &[u8]) -> SimOut {
        use xdp_dp_core::encap::ETH_LEN;
        match prog {
            crate::fabric::Prog::WanRx => self.wan_rx(pkt),
            crate::fabric::Prog::UplinkRx => {
                // outer IPv6 dst at ETH_LEN+24; resolve to this node's UnderlayValue.
                let vp = VecPkt::from_bytes(pkt);
                let outer_dst = match vp.read_array::<16>(ETH_LEN + 24) {
                    Some(d) => d,
                    None => {
                        return SimOut {
                            action: Action::Pass,
                            pkt: pkt.to_vec(),
                        }
                    }
                };
                let u = match self.maps.underlay_get(&outer_dst) {
                    Some(u) => u,
                    None => {
                        return SimOut {
                            action: Action::Pass,
                            pkt: pkt.to_vec(),
                        }
                    }
                };
                let local = self.local;
                self.uplink(pkt, u.vni, u, outer_dst, &local)
            }
        }
    }
}
