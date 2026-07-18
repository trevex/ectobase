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
use flowplane_core::conntrack::{ct_apply, ct_create_default, ct_key};
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
    /// Controlled monotonic clock (ns) the `guest_tx` egress meter stamps `last_ns` from — models
    /// `bpf_ktime_get_ns()`. Defaults to 0; tests advance it to drive token-bucket refill.
    pub now: u64,
    /// EDT departure timestamp (ns) recorded by the last `guest_tx` call that hit the `edt_egress`
    /// shaping path. `None` when the interface has no egress cap (`total_bps == 0`) or no METER
    /// entry. Tests can assert pacing intervals; wire bytes are unchanged (FQ pacing is kernel-side).
    pub last_tstamp: Option<u64>,
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
            now: 0,
            last_tstamp: None,
        }
    }

    /// Construct a node with a pre-set underlay identity.
    pub fn with_local(local: Local) -> Self {
        Self {
            maps: MemMaps::default(),
            local,
            src_ifindex: 0,
            now: 0,
            last_tstamp: None,
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
        if action == Action::Drop {
            return SimOut {
                action,
                pkt: pkt.into_bytes(),
            };
        }

        // 5. Ingress-lane policing (keyed by dest tap) — mirrors ingress.rs uplink_rx. Post-decap inner
        // length is the frame delivered to the guest. No cap => pass.
        let in_len = pkt.len() as u64;
        if !flowplane_core::meter::ingress_pass(&mut self.maps, tap, in_len, self.now) {
            return SimOut {
                action: Action::Drop,
                pkt: pkt.into_bytes(),
            };
        }

        SimOut {
            action,
            pkt: pkt.into_bytes(),
        }
    }

    /// Host uplink_rx for the NAT return / reverse-DNAT path. `encapped` is the fabric frame
    /// `[OuterEth(14)][OuterIPv6(40)][inner IPv4 ...]` returning from an external peer to a NAT'd
    /// guest; `u`/`guest_mac` come from `UNDERLAY[outer_dst]` (base tap). Composes the REAL core fns
    /// in the exact order + gates of the eBPF `try_uplink_rx` non-LB NAT branch (`ingress.rs`
    /// 160-209 + the base decap tail):
    ///   1. build the inner 5-tuple key; if the inner dst is a registered nat_ip, zero the external
    ///      src ip+port so it hits the peer-independent `(vni,0,nat_ip,0,nat_port)` reverse entry;
    ///   2. CT lookup: if the entry has `CT_REWRITE_DST`, apply the reverse-DNAT translation
    ///      (`ct_apply`: inner dst IP -> guest, dst port -> orig sport, +IP/L4 checksums);
    ///   3. decap outer Eth+IPv6 and rewrite the inner Ethernet for the guest.
    /// Returns the delivery `Action` + resulting (decapped, reverse-DNAT'd) frame bytes.
    ///
    /// Scope: the `ct_touch` refresh, NAT64 v4->v6 expansion, neighbor-NAT reforward, and inner
    /// `dnat_ingress` (VIP) branches are NOT modelled here — this seam covers the network-NAT
    /// reverse-DNAT apply (`ct_apply`) + decap, which is the byte-output-relevant slice for a
    /// plain (non-NAT64) NAT return.
    pub fn uplink_nat_return(
        &mut self,
        encapped: &[u8],
        vni: u32,
        u: UnderlayValue,
        guest_mac: [u8; 6],
    ) -> SimOut {
        use flowplane_common::CT_REWRITE_DST;
        use flowplane_core::conntrack::ct_apply;

        let inner_off = ETH_LEN + IPV6_LEN;
        let mut pkt = VecPkt::from_bytes(encapped);

        // 1. Build the inner 5-tuple key; NAT returns are demuxed peer-independently.
        if let Some(mut key) = ct_key(&pkt, inner_off, vni) {
            if self.maps.nat_ips.contains(&(vni, key.dst_ip)) {
                key.src_ip = [0; 4];
                key.src_port = 0;
            }
            // 2. Reverse-DNAT apply when the matched entry carries CT_REWRITE_DST.
            if let Some(e) = self.maps.conntrack_get(&key) {
                if e.flags & CT_REWRITE_DST != 0 {
                    ct_apply(&mut pkt, inner_off, &e);
                }
            }
        }

        // 3. Decap outer Eth+IPv6 and rewrite the inner Ethernet for the guest.
        let action = match decap_and_rewrite(&mut pkt, u.tap_ifindex, guest_mac) {
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
    ///   6. rate metering: public-lane policing (`public_pass`, external only) + EDT egress shaping
    ///      (`edt_egress`, records `self.last_tstamp`, no drop). Mirrors the eBPF split in
    ///      `egress.rs` + `tc.rs`. No METER entry => unlimited (pass / no tstamp), preserving prior
    ///      behavior. `now` comes from `self.now` (the controlled clock);
    ///   7. deliver decision (`deliver`): Local tap (inner-Eth rewrite) | Encap | Pass.
    ///
    /// Returns the delivery `Action` + the resulting frame bytes (encapped on the Encap path).
    ///
    /// NOTE (scope): only the fresh-flow / non-VIP path is composed here for the OUTPUT PACKET — that
    /// slice is byte-identical to the eBPF program and thus anchorable. Metering does not mutate
    /// packet bytes (it only reads/writes the METER map and returns a verdict), so with no METER entry
    /// the emitted bytes are unaffected; the interleaved un-ported steps (ct_apply/ct_touch, vip) are
    /// map/refresh-only on this fixture and do not change the emitted bytes.
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

        // 6. Egress metering — mirrors the eBPF split in egress.rs + tc.rs:
        //    a) Public-lane policing (drop-on-exhaust, external only) — mirrors egress.rs `public_pass`.
        //    b) EDT egress shaping (records departure stamp, no drop) — mirrors tc.rs `edt_stamp`.
        //    The `total` token-bucket (`meter_pass`) is no longer called: the eBPF path migrated the
        //    total lane to EDT shaping, so `meter_state()` sets `total_burst=0`/`total_tokens=0`
        //    (no bucket); calling `meter_pass` would clamp tokens to 0 and drop all capped egress.
        let frame_len = pkt.len() as u64;
        // a) Public-lane policing (external egress only) — mirrors egress.rs.
        if !flowplane_core::meter::public_pass(
            &mut self.maps,
            self.src_ifindex,
            frame_len,
            is_ext,
            self.now,
        ) {
            return SimOut {
                action: Action::Drop,
                pkt: pkt.into_bytes(),
            };
        }
        // b) EDT egress shaping — mirrors tc.rs encap path. The sim records the departure stamp so
        // tests can assert pacing; wire bytes are unchanged (FQ pacing is kernel-side).
        self.last_tstamp = flowplane_core::meter::edt_egress(
            &mut self.maps,
            self.src_ifindex,
            frame_len,
            self.now,
        );

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

    /// Guest NAT64 egress (`v6_guest_tx` → `nat64_egress`) for the IPv6→IPv4 translation path.
    /// `frame` is a full guest Ethernet frame `[InnerEth(14)][IPv6(40)][L4]` whose IPv6 dst is in the
    /// NAT64 well-known prefix `64:ff9b::/96`; `meta` is the sending port's `PortMeta` (vni + guest
    /// IPv4 for the NAT key + underlay identity). Composes the REAL core fns in the exact order + gates
    /// of the eBPF `nat64_egress`:
    ///   1. parse (`nat64_egress_parse`): dst-prefix check, NAT config lookup, source-port allocation,
    ///      forward + reverse `CT_F_NAT64` conntrack inserts;
    ///   2. resize: shrink the inner IPv6(40)→IPv4(20) — models `bpf_xdp_adjust_head(+20)` (drop 20
    ///      bytes off the front; the writer restores the Ethernet header in front of the IPv4 hdr);
    ///   3. write (`nat64_egress_write`, `write_eth = true`): Ethernet + IPv4 header + L4 translation;
    ///   4. route lookup (`route4`) → Pass on miss;
    ///   5. encap IP-in-IPv6 toward the route nexthop (`write_outer_v6`).
    ///
    /// Returns `Redirect(uplink_ifindex)` + the encapped `[OuterEth][OuterIPv6][IPv4][L4]` frame, or
    /// `Pass` when the frame is not a NAT64 packet / has no route. Byte-identical to the eBPF path.
    pub fn guest_tx_nat64(&mut self, frame: &[u8], meta: &PortMeta) -> SimOut {
        use flowplane_core::nat64::{nat64_egress_parse, nat64_egress_write};

        let ip6_off = ETH_LEN;
        let mut pkt = VecPkt::from_bytes(frame);

        // 1. Parse (dst-prefix check + NAT config + port alloc + CT_F_NAT64 conntrack inserts).
        let xlate =
            match nat64_egress_parse(&pkt, &mut self.maps, ip6_off, meta.vni, meta.guest_ipv4, 0) {
                Some(x) => x,
                None => {
                    return SimOut {
                        action: Action::Pass,
                        pkt: pkt.into_bytes(),
                    }
                }
            };

        // 2. Resize: shrink inner IPv6(40)→IPv4(20) via a 20-byte front drop (models adjust_head(+20)).
        if !pkt.shrink_head(20) {
            return SimOut {
                action: Action::Drop,
                pkt: pkt.into_bytes(),
            };
        }

        // 3. Write: restore the Ethernet header + build the IPv4 header + translate the L4.
        if !nat64_egress_write(&mut pkt, ETH_LEN, true, &xlate) {
            return SimOut {
                action: Action::Drop,
                pkt: pkt.into_bytes(),
            };
        }

        // 4. Route lookup on the embedded IPv4 dst.
        let route = match route4(&self.maps, meta.vni, &xlate.ipv4_dst) {
            Some(r) => r,
            None => {
                return SimOut {
                    action: Action::Pass,
                    pkt: pkt.into_bytes(),
                }
            }
        };

        // 5. Encap IP-in-IPv6 toward the route nexthop (IPIP inner-proto).
        let e = EncapParams {
            gateway_mac: self.local.gateway_mac,
            uplink_mac: self.local.uplink_mac,
            uplink_ifindex: self.local.uplink_ifindex,
            src_underlay: meta.underlay_ipv6,
            nexthop_ipv6: route.nexthop_ipv6,
            inner_proto: IPPROTO_IPIP,
        };
        if !pkt.grow_head(IPV6_LEN) || !write_outer_v6(&mut pkt, &e) {
            return SimOut {
                action: Action::Drop,
                pkt: pkt.into_bytes(),
            };
        }
        SimOut {
            action: Action::Redirect(self.local.uplink_ifindex),
            pkt: pkt.into_bytes(),
        }
    }

    /// Host NAT64 INGRESS reply (`try_uplink_rx` → `nat64_ingress`): an external IPv4 reply arriving
    /// encapped IP-in-IPv6 as `[Eth][outerIPv6(40)][innerIPv4(20)][L4]`, whose reverse conntrack entry
    /// (`rev` — keyed peer-independently on `(vni, 0, nat_ip, 0, nat_port)`, carrying `CT_REWRITE_DST`
    /// + `CT_F_NAT64`) restores the guest IPv4 + orig L4 port. `meta` supplies the guest tap
    /// (`guest_mac`) plus the guest IPv6 (`guest_ipv6`). Composes the REAL core fns in the exact
    /// order and gates of the eBPF ingress dispatch:
    ///   1. `ct_apply(rev)`: rewrite the inner IPv4 dst (nat_ip→guest_ipv4) + L4 dst port
    ///      (nat_port→orig_sport) + fold both into the IPv4/L4 checksums (mirrors `ingress.rs:187`);
    ///   2. parse (`nat64_ingress_parse`): IHL==5, L4 proto/TTL/inner-v4-addrs/total-len/L4-checksum,
    ///      reconstruct the `64:ff9b::server` IPv6 src;
    ///   3. resize: shrink `[Eth][outerIPv6][innerIPv4][L4]`→`[Eth][innerIPv6][L4]` — models
    ///      `bpf_xdp_adjust_head(+20)` (drop 20 bytes off the front; the writer rebuilds Eth+IPv6);
    ///   4. write (`nat64_ingress_write`): guest Ethernet + inner IPv6 header + L4 translation.
    ///
    /// Returns `Redirect(tap_ifindex)` + the reconstructed `[Eth][IPv6][L4]` guest frame. Byte-identical
    /// to the eBPF path. `rev.xlate_port` is the restored guest L4 port/id (used by the ICMPv6 id +
    /// consumed here before `ct_apply` overwrites the packet).
    pub fn uplink_nat64_ingress(
        &self,
        encapped: &[u8],
        tap_ifindex: u32,
        guest_mac: [u8; 6],
        guest_ipv6: [u8; 16],
        rev: &flowplane_common::CtEntry,
    ) -> SimOut {
        use flowplane_core::nat64::{nat64_ingress_parse, nat64_ingress_write};

        let inner_off = ETH_LEN + IPV6_LEN;
        let orig_sport = rev.xlate_port;
        let mut pkt = VecPkt::from_bytes(encapped);

        // 1. Reverse conntrack apply: restore the guest IPv4 dst + orig L4 port (+ checksums).
        ct_apply(&mut pkt, inner_off, rev);

        // 2. Parse (IHL/proto/TTL/addrs/checksum + reconstructed 64:ff9b:: IPv6 src).
        let xlate = match nat64_ingress_parse(&pkt, inner_off, guest_ipv6, guest_mac, orig_sport) {
            Some(x) => x,
            None => {
                return SimOut {
                    action: Action::Pass,
                    pkt: pkt.into_bytes(),
                }
            }
        };

        // 3. Resize: shrink 20 bytes off the front (models adjust_head(+20)).
        if !pkt.shrink_head(20) {
            return SimOut {
                action: Action::Drop,
                pkt: pkt.into_bytes(),
            };
        }

        // 4. Write: guest Ethernet + inner IPv6 header + L4 translation.
        if !nat64_ingress_write(&mut pkt, ETH_LEN, GW_MAC, &xlate) {
            return SimOut {
                action: Action::Drop,
                pkt: pkt.into_bytes(),
            };
        }

        SimOut {
            action: Action::Redirect(tap_ifindex),
            pkt: pkt.into_bytes(),
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

    /// Guest-facing gateway responder (`guest_tx` ARP/ND head): if `frame` is an ARP request for
    /// `meta.gateway_ipv4` OR an ICMPv6 Neighbor Solicitation for `meta.gateway_ipv6`, rewrite it in
    /// place into the corresponding reply (ARP reply / Neighbor Advertisement from `meta.guest_mac`)
    /// and return `Redirect(ingress_ifindex)` — the exact `reflect(ctx)` verdict the eBPF datapath
    /// uses (`bpf_redirect(ingress_ifindex)`). Otherwise `Pass` (unchanged frame).
    ///
    /// Runs the SAME `flowplane_core::arp_nd::{arp_reply, nd_reply}` the production eBPF `guest_tx`
    /// dispatches to. `ingress_ifindex` models the frame's arrival interface (the redirect target);
    /// the eBPF path uses `ctx.ingress_ifindex` (== 1 under `BPF_PROG_TEST_RUN`).
    pub fn guest_arp_nd(&self, frame: &[u8], meta: &PortMeta, ingress_ifindex: u32) -> SimOut {
        use flowplane_core::arp_nd::{arp_reply, nd_reply};
        let mut pkt = VecPkt::from_bytes(frame);
        // Mirror the eBPF `try_guest_tx` head: ARP first, then ND.
        if arp_reply(&mut pkt, meta.gateway_ipv4, meta.guest_mac)
            || nd_reply(&mut pkt, meta.gateway_ipv6, meta.guest_mac)
        {
            return SimOut {
                action: Action::Redirect(ingress_ifindex),
                pkt: pkt.into_bytes(),
            };
        }
        SimOut {
            action: Action::Pass,
            pkt: pkt.into_bytes(),
        }
    }

    /// Guest DHCPv4 responder. If `frame` is a DISCOVER/REQUEST (UDP dport 67) for this port, build
    /// the OFFER/ACK and return `Redirect(ingress_ifindex)` — the exact `reflect(ctx)` verdict the
    /// eBPF `guest_dhcp` datapath uses (`bpf_redirect(ingress_ifindex)`). Otherwise `Pass`.
    ///
    /// Runs the SAME `flowplane_core::dhcp::{parse, write}` the production eBPF `guest_dhcp` glue
    /// dispatches to, over `VecPkt`/`MemMaps`. Mirrors the eBPF glue exactly: parse the request, then
    /// resize the frame to the constant `REPLY_LEN` (models `bpf_xdp_adjust_tail`) before writing the
    /// fixed-layout reply. The reply's server MAC / assigned IP / gateway come from `meta`; MTU + DNS
    /// + host-name come from the node's `DHCP_CONFIG` / `DHCP_META[ingress_ifindex]`.
    pub fn guest_dhcp4(&self, frame: &[u8], meta: &PortMeta, ingress_ifindex: u32) -> SimOut {
        use flowplane_core::dhcp;
        let mut pkt = VecPkt::from_bytes(frame);
        let req = match dhcp::parse(&pkt) {
            Some(r) => r,
            None => {
                return SimOut {
                    action: Action::Pass,
                    pkt: pkt.into_bytes(),
                }
            }
        };
        // Grow/shrink the frame to the constant reply length, as the eBPF glue does via adjust_tail.
        pkt.set_tail(dhcp::REPLY_LEN);
        let ok = dhcp::write(
            &mut pkt,
            &req,
            meta.guest_ipv4,
            meta.gateway_ipv4,
            GW_MAC,
            &self.maps,
            ingress_ifindex,
        );
        SimOut {
            action: if ok {
                Action::Redirect(ingress_ifindex)
            } else {
                Action::Pass
            },
            pkt: pkt.into_bytes(),
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
