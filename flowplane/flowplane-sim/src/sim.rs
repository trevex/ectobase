//! Native `SimNode` that runs the REAL `flowplane_core` datapath fns over the sim `VecPkt`/`MemMaps`.
//! No parallel reimplementation: `edge_encap` calls `write_outer_v6`; `uplink` composes the REAL
//! core fns — `lb_select_forward` + `reforward` + `fw_eval_dir` + `ct_create_default` +
//! `decap_and_rewrite` — in the exact order + gates of the eBPF `try_uplink_rx` LB/base tail
//! (`ingress.rs` 135-157 dispatch + 245-304 tail). The LB-dispatch glue is composed here (as it is
//! in the eBPF wrapper); the `BPF_PROG_TEST_RUN` anchor guards native==bytecode on the LB path.
//!
//! Scope: this harness models the LB-select + firewall + conntrack-create + decap/reforward tail.
//! The `try_uplink_rx` branches gated on `lb_ul.is_none()` — NAT64 reply, neighbor-NAT reforward,
//! ICMP-echo reply, and inner `dnat_ingress` — are NOT modeled (out of scope for this LB-path
//! harness). For LB packets those branches are skipped anyway.

use flowplane_common::{Local, PortMeta, UnderlayValue};
use flowplane_core::encap::{write_outer_v6, EncapParams, ETH_LEN, IPV6_LEN};
use flowplane_core::maps::Maps;
use flowplane_core::pkt::{Action, Pkt};

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
    ///
    /// Returns the final `Action` + the resulting frame bytes.
    pub fn uplink(
        &mut self,
        encapped: &[u8],
        vni: u32,
        u: UnderlayValue,
        outer_dst: [u8; 16],
        local: &Local,
    ) -> SimOut {
        let mut pkt = VecPkt::from_bytes(encapped);
        let in_ = flowplane_core::datapath::UplinkIn {
            vni,
            u,
            outer_dst,
            local,
            now: self.now,
            // Base path (never NAT64); guest_ipv6 is only read on the CT_F_NAT64 return branch.
            guest_ipv6: [0; 16],
        };
        let action = flowplane_core::datapath::process_uplink(&mut pkt, &mut self.maps, &in_);
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
    ///
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
        let mut pkt = VecPkt::from_bytes(encapped);
        let action = flowplane_core::datapath::process_uplink_nat_return(
            &mut pkt,
            &mut self.maps,
            &flowplane_core::datapath::UplinkNatReturnIn {
                vni,
                tap_ifindex: u.tap_ifindex,
                guest_mac,
            },
        );
        SimOut {
            action,
            pkt: pkt.into_bytes(),
        }
    }

    /// Unified host `uplink_rx`: drives [`flowplane_core::datapath::process_uplink_rx`], the shared
    /// entry that dispatches an established NAT return (inner dst a registered nat_ip with a matching
    /// `CT_REWRITE_DST` reverse entry, not LB-claimed) to the reverse-DNAT path and everything else to
    /// the LB + base path — the SAME base-vs-NAT-return decision the eBPF `try_uplink_rx` makes inline.
    /// Use this (over [`SimNode::uplink`] / [`SimNode::uplink_nat_return`], which force one branch) to
    /// exercise the dispatch itself. A `CT_F_NAT64` reverse hit dispatches to
    /// the v4→v6 expansion path, which reconstructs the reply's inner IPv6 dst from `guest_ipv6` (the
    /// guest's own overlay IPv6); it is unread on all other branches.
    pub fn uplink_rx(
        &mut self,
        encapped: &[u8],
        vni: u32,
        u: UnderlayValue,
        outer_dst: [u8; 16],
        local: &Local,
        guest_ipv6: [u8; 16],
    ) -> SimOut {
        let mut pkt = VecPkt::from_bytes(encapped);
        let in_ = flowplane_core::datapath::UplinkIn {
            vni,
            u,
            outer_dst,
            local,
            now: self.now,
            guest_ipv6,
        };
        let action = flowplane_core::datapath::process_uplink_rx(&mut pkt, &mut self.maps, &in_);
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
    ///   6. rate metering: public-lane policing (`public_pass`, external only, step 6a). Mirrors
    ///      `egress.rs`. No METER entry => unlimited (pass). `now` comes from `self.now`;
    ///   7. deliver decision (`deliver`): Local tap (inner-Eth rewrite) | Encap | Pass.
    ///      In the Encap arm ONLY, after `grow_head(IPV6_LEN)`/`write_outer_v6`, EDT egress shaping
    ///      (`edt_egress`, records `self.last_tstamp`, no drop, step 6b) is called using the
    ///      POST-encap `pkt.len()` — mirrors `tc.rs` `edt_stamp` after `adjust_room`. Local/Pass
    ///      leave `last_tstamp` unchanged (EDT shaping applies only on the encap/uplink egress path).
    ///
    /// Returns the delivery `Action` + the resulting frame bytes (encapped on the Encap path).
    ///
    /// NOTE (scope): only the fresh-flow / non-VIP path is composed here for the OUTPUT PACKET — that
    /// slice is byte-identical to the eBPF program and thus anchorable. Metering does not mutate
    /// packet bytes (it only reads/writes the METER map and returns a verdict), so with no METER entry
    /// the emitted bytes are unaffected; the interleaved un-ported steps (ct_apply/ct_touch, vip) are
    /// map/refresh-only on this fixture and do not change the emitted bytes.
    pub fn guest_tx(&mut self, frame: &[u8], meta: &PortMeta) -> SimOut {
        let mut pkt = VecPkt::from_bytes(frame);
        let out = flowplane_core::datapath::process_guest_tx(
            &mut pkt,
            &mut self.maps,
            &flowplane_core::datapath::GuestTxIn {
                meta,
                src_ifindex: self.src_ifindex,
                now: self.now,
            },
        );
        self.last_tstamp = out.edt_tstamp;
        SimOut {
            action: out.action,
            pkt: pkt.into_bytes(),
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
        let mut pkt = VecPkt::from_bytes(frame);
        let action = flowplane_core::datapath::process_guest_tx_nat64(
            &mut pkt,
            &mut self.maps,
            &flowplane_core::datapath::GuestTxNat64In {
                meta,
                local: &self.local,
            },
        );
        SimOut {
            action,
            pkt: pkt.into_bytes(),
        }
    }

    /// Guest egress (`tc_guest_egress_v6` → `forward_decision_v6`) for the NATIVE IPv6→IPv6 forwarding
    /// path. `frame` is a full guest Ethernet frame `[InnerEth(14)][IPv6(40)][L4]` whose dst is NOT in
    /// the NAT64 prefix; `meta` is the sending port's `PortMeta`. Composes the REAL shared core stages
    /// (`egress_fw_ct6` + `route_decision6`) the eBPF `forward_decision_v6` delegates to, via
    /// [`flowplane_core::datapath::process_guest_tx_v6`]:
    ///   1. egress firewall + firewall-only v6 conntrack (deny-by-default on a fresh flow);
    ///   2. route6 + deliver → Local tap (inner-Eth rewrite) | Encap (outer IPv6, inner-proto 41, IPv6-in-IPv6) | Pass;
    ///   3. dest ingress firewall on a NEW same-node Local flow (deny-by-default).
    ///
    /// Returns `Redirect(uplink_ifindex)` + the encapped `[OuterEth][OuterIPv6][innerIPv6][L4]` frame
    /// on the encap arm. Byte-identical to the eBPF path.
    pub fn guest_tx_v6(&mut self, frame: &[u8], meta: &PortMeta) -> SimOut {
        let mut pkt = VecPkt::from_bytes(frame);
        let out = flowplane_core::datapath::process_guest_tx_v6(
            &mut pkt,
            &mut self.maps,
            &flowplane_core::datapath::GuestTxIn {
                meta,
                src_ifindex: self.src_ifindex,
                now: self.now,
            },
        );
        self.last_tstamp = out.edt_tstamp;
        SimOut {
            action: out.action,
            pkt: pkt.into_bytes(),
        }
    }

    /// Host NAT64 INGRESS reply (`try_uplink_rx` → `nat64_ingress`): an external IPv4 reply arriving
    /// encapped IP-in-IPv6 as `[Eth][outerIPv6(40)][innerIPv4(20)][L4]`, whose reverse conntrack entry
    /// (`rev` — keyed peer-independently on `(vni, 0, nat_ip, 0, nat_port)`, carrying `CT_REWRITE_DST` +
    /// `CT_F_NAT64`) restores the guest IPv4 + orig L4 port. `meta` supplies the guest tap
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
        let mut pkt = VecPkt::from_bytes(encapped);
        let action = flowplane_core::datapath::process_uplink_nat64_ingress(
            &mut pkt,
            &flowplane_core::datapath::UplinkNat64IngressIn {
                tap_ifindex,
                guest_mac,
                guest_ipv6,
                rev,
            },
        );
        SimOut {
            action,
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
        let mut pkt = VecPkt::from_bytes(plain);
        let action = flowplane_core::datapath::process_wan_rx(
            &mut pkt,
            &self.maps,
            &flowplane_core::datapath::WanRxIn { local: &self.local },
        );
        SimOut {
            action,
            pkt: pkt.into_bytes(),
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
        let mut pkt = VecPkt::from_bytes(frame);
        let action = flowplane_core::datapath::process_guest_arp_nd(
            &mut pkt,
            &flowplane_core::datapath::GuestArpNdIn {
                gateway_ipv4: meta.gateway_ipv4,
                gateway_ipv6: meta.gateway_ipv6,
                ingress_ifindex,
            },
        );
        SimOut {
            action,
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
        let mut pkt = VecPkt::from_bytes(frame);
        let action = flowplane_core::datapath::process_guest_dhcp4(
            &mut pkt,
            &self.maps,
            &flowplane_core::datapath::GuestDhcp4In {
                guest_ipv4: meta.guest_ipv4,
                gateway_ipv4: meta.gateway_ipv4,
                ingress_ifindex,
            },
        );
        SimOut {
            action,
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
