//! Native `SimNode` that runs the REAL `flowplane_core` datapath fns over the sim `VecPkt`/`MemMaps`.
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

use flowplane_common::{
    Local, PortMeta, UnderlayValue, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS,
};
use flowplane_core::conntrack::{ct_create_default, ct_key};
use flowplane_core::egress::{deliver, route4, Deliver, IPPROTO_IPIP};
use flowplane_core::encap::{reforward, write_outer_v6, EncapParams, ETH_LEN, IPV6_LEN};
use flowplane_core::firewall::fw_eval_dir;
use flowplane_core::lb::{lb_select_forward, lb_select_forward_v6};
use flowplane_core::maps::Maps;
use flowplane_core::nat::snat_egress;
use flowplane_core::pkt::{Action, Pkt};
use flowplane_core::uplink::{decap_and_rewrite, GW_MAC};

use crate::maps::MemMaps;
use crate::pkt::VecPkt;

/// A native node running the shared eBPF datapath core over in-memory maps.
pub struct SimNode {
    pub maps: MemMaps,
    /// This node's own underlay identity (uplink ifindex/MACs, underlay IPv6). Used by `wan_rx` and
    /// `run` to encapsulate or reforward without an external `Local` argument.
    pub local: Local,
    /// Source (guest tap) ifindex the `guest_tx` egress firewall is keyed on — the eBPF path uses
    /// the frame's ingress_ifindex. Defaults to 0; set it before calling `guest_tx`.
    pub src_ifindex: u32,
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
            src_ifindex: 0,
        }
    }

    /// Construct a node with a pre-set underlay identity.
    pub fn with_local(local: Local) -> Self {
        Self {
            maps: MemMaps::default(),
            local,
            src_ifindex: 0,
        }
    }

    /// Edge: encapsulate a full guest Ethernet frame `[InnerEth(14)][IPv4 ...]` toward `nexthop`,
    /// producing `[OuterEth(14)][OuterIPv6(40)][bare IPv4 ...]` — the exact fabric wire format the
    /// eBPF egress path emits. Byte-identical to the real encap: `grow_head(40)` prepends 40 bytes,
    /// then the 54-byte outer header write consumes the 40 new bytes AND the 14-byte inner Ethernet,
    /// leaving the bare inner IPv4 (inner_proto=IPIP; the outer length is derived from `logical_len`).
    pub fn edge_encap(&self, inner_frame: &[u8], e: EncapParams) -> Vec<u8> {
        assert!(
            inner_frame.len() >= ETH_LEN,
            "inner_frame must be a full Eth+IPv4 frame"
        );
        let mut p = VecPkt::from_bytes(inner_frame);
        assert!(p.grow_head(IPV6_LEN));
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
            Err(_) => Action::Drop,
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

    /// Guest egress (`guest_tx`) for the IPv4 forwarding path. `frame` is a full guest Ethernet
    /// frame `[InnerEth(14)][IPv4][L4]`; `meta` is the sending port's `PortMeta` (vni + underlay
    /// identity). Composes the REAL core fns in the exact order + gates of the eBPF
    /// `egress::forward_decision_v4` for the byte-parity-relevant steps:
    ///   1. conntrack: on a NEW flow (miss) enforce the SOURCE egress firewall (deny-by-default);
    ///      an established flow's CT_REWRITE_SRC translation + refresh (ct_apply/ct_touch) is NOT
    ///      modelled here (separate slice) — the anchor + tests exercise fresh flows;
    ///   2. VIP snat/dnat: NOT modelled (separate slice; anchor installs no VIP maps → no-op);
    ///   3. route lookup (`route4`) → Pass on miss;
    ///   4. network NAT SNAT (`snat_egress`) when the route is external;
    ///   5. conntrack create-on-miss (`ct_create_default`);
    ///   6. rate metering: NOT modelled (separate slice; no METER map → unlimited);
    ///   7. deliver decision (`deliver`): Local tap (inner-Eth rewrite) | Encap | Pass.
    ///
    /// Returns the delivery `Action` + the resulting frame bytes (encapped on the Encap path).
    ///
    /// NOTE (scope): only the fresh-flow / non-VIP / unmetered path is composed here — that is the
    /// slice whose OUTPUT PACKET is byte-identical to the eBPF program and thus anchorable. The
    /// interleaved un-ported steps (ct_apply/ct_touch, vip, meter) are map/refresh-only on this
    /// fixture and do not change the emitted bytes.
    pub fn guest_tx(&mut self, frame: &[u8], meta: &PortMeta) -> SimOut {
        let ip_off = ETH_LEN;
        let mut pkt = VecPkt::from_bytes(frame);

        // 1. Conntrack miss → source egress firewall (deny-by-default). Fresh flow only.
        let mut was_new = false;
        if let Some(key) = ct_key(&pkt, ip_off, meta.vni) {
            if self.maps.conntrack_get(&key).is_none() {
                was_new = true;
                // Egress firewall keyed on the SOURCE interface. The sim keys FW_META/FW_RULES on a
                // synthetic ifindex == meta.vni's port; the fixture installs it under `src_ifindex`.
                if fw_eval_dir(&pkt, &self.maps, ip_off, self.src_ifindex, FW_DIR_EGRESS)
                    == FW_ACTION_DROP
                {
                    return SimOut {
                        action: Action::Drop,
                        pkt: pkt.into_bytes(),
                    };
                }
            }
        }

        // 2. VIP snat/dnat: not modelled (no VIP maps → no-op in the eBPF path too).

        // 3. Route lookup on the inner IPv4 dst.
        let dst = match pkt.read_array::<4>(ip_off + 16) {
            Some(d) => d,
            None => {
                return SimOut {
                    action: Action::Pass,
                    pkt: pkt.into_bytes(),
                }
            }
        };
        let route = match route4(&self.maps, meta.vni, &dst) {
            Some(r) => r,
            None => {
                return SimOut {
                    action: Action::Pass,
                    pkt: pkt.into_bytes(),
                }
            }
        };

        // 4. Network NAT SNAT when the route is external.
        let is_ext = route.is_external != 0;
        snat_egress(&mut pkt, &mut self.maps, ip_off, meta.vni, is_ext, 0);

        // 5. Track every flow (create-on-miss).
        if let Some(key) = ct_key(&pkt, ip_off, meta.vni) {
            if self.maps.conntrack_get(&key).is_none() {
                ct_create_default(&pkt, &mut self.maps, ip_off, meta.vni, 0);
            }
        }

        // 6. Rate metering: not modelled (no METER map → unlimited pass).

        // 7. Deliver decision.
        match deliver(&self.maps, &route, meta, IPPROTO_IPIP) {
            Deliver::Local {
                tap_ifindex,
                guest_mac,
            } => {
                // Destination ingress firewall on NEW flows (same-node delivery).
                if was_new
                    && fw_eval_dir(&pkt, &self.maps, ip_off, tap_ifindex, FW_DIR_INGRESS)
                        == FW_ACTION_DROP
                {
                    return SimOut {
                        action: Action::Drop,
                        pkt: pkt.into_bytes(),
                    };
                }
                // Rewrite the inner Ethernet for the local guest: dst=guest MAC, src=GW_MAC,
                // ethertype stays IPv4.
                pkt.write_bytes(0, &guest_mac);
                pkt.write_bytes(6, &GW_MAC);
                SimOut {
                    action: Action::Redirect(tap_ifindex),
                    pkt: pkt.into_bytes(),
                }
            }
            Deliver::Encap(e) => {
                // Prepend 40 bytes (bpf_xdp_adjust_head(-40)) then write the outer Eth+IPv6, which
                // consumes the new 40 bytes + the 14-byte inner Ethernet, leaving the bare inner IPv4.
                if !pkt.grow_head(IPV6_LEN) || !write_outer_v6(&mut pkt, &e) {
                    return SimOut {
                        action: Action::Drop,
                        pkt: pkt.into_bytes(),
                    };
                }
                SimOut {
                    action: Action::Redirect(e.uplink_ifindex),
                    pkt: pkt.into_bytes(),
                }
            }
            Deliver::Pass => SimOut {
                action: Action::Pass,
                pkt: pkt.into_bytes(),
            },
        }
    }

    /// Edge WAN-VIP ingress (`wan_rx`): a plain `[Eth][IPv4|IPv6]` WAN frame; if its dst+port is a WAN
    /// LB VIP (vni=0), Maglev-select a backend and encap the inner packet IP-in-IPv6 to the backend
    /// underlay. Else Pass. Mirrors `ingress.rs::try_wan_rx` VIP branch. Dispatches on the frame's
    /// ethertype (bytes [12..14]): `0x0800` runs the v4 core select (`inner_proto=4`/IPIP), `0x86DD`
    /// runs the v6 core select (`inner_proto=41`/IPPROTO_IPV6). Returns the encapped frame (or the
    /// input on Pass).
    pub fn wan_rx(&self, plain: &[u8]) -> SimOut {
        use flowplane_core::encap::ETH_LEN;
        let ethertype = u16::from_be_bytes([
            plain.get(12).copied().unwrap_or(0),
            plain.get(13).copied().unwrap_or(0),
        ]);
        // v4 => IPIP; v6 => IPPROTO_IPV6. Select with the matching core fn, then share one encap.
        let selected = match ethertype {
            0x86DD => lb_select_forward_v6(&VecPkt::from_bytes(plain), &self.maps, ETH_LEN, 0)
                .map(|b| (b, 41u8)),
            _ => lb_select_forward(&VecPkt::from_bytes(plain), &self.maps, ETH_LEN, 0)
                .map(|b| (b, 4u8)),
        };
        match selected {
            Some((backend, inner_proto)) => {
                let e = EncapParams {
                    gateway_mac: self.local.gateway_mac,
                    uplink_mac: self.local.uplink_mac,
                    uplink_ifindex: self.local.uplink_ifindex,
                    src_underlay: self.local.underlay_ipv6,
                    nexthop_ipv6: backend,
                    inner_proto, // 4 (IPIP) for v4 inner, 41 (IPPROTO_IPV6) for v6 inner
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
        use flowplane_core::encap::ETH_LEN;
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
