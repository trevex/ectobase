//! Native `SimNode` that runs the REAL `flowplane_core` datapath fns over the sim `VecPkt`/`MemMaps`.
//! No parallel reimplementation of PRODUCTION logic: encap arms call `flowplane_core::encap::{
//! tunnel_encap, reforward}` and carry the resulting `TunnelEncap` decision on `SimOut` — they no
//! longer write outer bytes (see `flowplane_core::encap` for why). `uplink` composes the REAL core
//! fns — `lb_select_forward` + `reforward` + `fw_eval_dir` + `ct_create_default` +
//! `decap_and_rewrite` — in the exact order + gates of the eBPF `try_uplink_rx` LB/base tail
//! (`ingress.rs` 135-157 dispatch + 245-304 tail). The LB-dispatch glue is composed here (as it is
//! in the eBPF wrapper); the `BPF_PROG_TEST_RUN` anchor guards native==bytecode on the LB path.
//!
//! Scope: this harness models the LB-select + firewall + conntrack-create + decap/reforward tail,
//! PLUS the ingress delivery-target reconstruction (`ROUTES` self-route / neighbor-NAT relay /
//! WAN-edge sentinel / genuine-miss drop — see `flowplane_core::datapath::resolve_uplink_target`).
//! The `try_uplink_rx` branches gated on `lb_ul.is_none()` — NAT64 reply, ICMP-echo reply, and inner
//! `dnat_ingress` — are NOT modeled (out of scope for this LB-path harness). For LB packets those
//! branches are skipped anyway.
//!
//! `EncapParams`/`edge_encap` below are a TEST-FIXTURE-ONLY byte writer: decap/ingress
//! (`flowplane_core::uplink::decap_and_rewrite` and friends) still consume the old wire shape
//! `[OuterEth(14)][OuterIPv6(40)][inner...]` until a later task migrates ingress to
//! `bpf_skb_get_tunnel_key`, so ingress-path sim tests still need byte-accurate "arrived over the
//! wire" input frames. Production egress never calls this — see `TunnelEncap` instead.

use flowplane_common::{Local, PortMeta, RouteValue, UnderlayValue};
use flowplane_core::encap::{TunnelEncap, ETH_LEN, IPV6_LEN};
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

/// Result of a `SimNode` datapath call: the delivery `Action`, the resulting frame bytes, and the
/// `TunnelEncap` decision when this call's verdict was an overlay encap (`None` otherwise — Local
/// delivery, Pass, Drop, and every decap/ingress path never set it). Since production egress no
/// longer writes outer bytes, `tunnel` is how tests observe the encap decision.
pub struct SimOut {
    pub action: Action,
    pub pkt: Vec<u8>,
    pub tunnel: Option<TunnelEncap>,
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

    /// TEST-FIXTURE-ONLY: encapsulate a full guest Ethernet frame `[InnerEth(14)][IPv4 ...]` toward
    /// `e.nexthop_ipv6`, producing `[OuterEth(14)][OuterIPv6(40)][bare IPv4 ...]` — the wire format
    /// decap (`flowplane_core::uplink::decap_and_rewrite`) still consumes. NOT used by any
    /// production datapath fn (which emits a `TunnelEncap` decision instead — see module docs).
    pub fn edge_encap(&self, inner_frame: &[u8], e: EncapParams) -> Vec<u8> {
        wrap_fixture_outer_full(inner_frame, &e)
    }

    /// Host uplink_rx for the LB + base path. Under Geneve `collect_md` there is no pre-resolved
    /// `UnderlayValue`/outer-dst: `vni` (from `get_tunnel_key`) + the inner packet + maps are the
    /// only inputs the delivery-target reconstruction has to work with (see
    /// `flowplane_core::datapath::resolve_uplink_target`). `local` supplies the outer MACs/ifindex
    /// for an LB remote `reforward` / neighbor-NAT relay / WAN-edge local-deliver rewrite. Mirrors
    /// `try_uplink_rx`:
    ///   1. `lb_select_forward` → local backend (deliver to its tap) | remote (reforward, no decap)
    ///      | None → neighbor-NAT relay → ROUTES self-route + WAN-edge sentinel / genuine-miss drop;
    ///   2. ingress firewall on the inner 5-tuple against the deliver tap (new-flow gate);
    ///   3. conntrack create-on-miss, **skipped for LB** (DSR, no ct — `ingress.rs:266`);
    ///   4. decap + inner-Ethernet rewrite.
    ///
    /// Returns the final `Action` + the resulting frame bytes + the `TunnelEncap` decision on a
    /// relay/reforward arm (`None` otherwise).
    pub fn uplink(&mut self, encapped: &[u8], vni: u32, local: &Local) -> SimOut {
        let mut pkt = VecPkt::from_bytes(encapped);
        let in_ = flowplane_core::datapath::UplinkIn {
            vni,
            local,
            now: self.now,
            // Base path (never NAT64); guest_ipv6 is only read on the CT_F_NAT64 return branch.
            guest_ipv6: [0; 16],
        };
        let out = flowplane_core::datapath::process_uplink(&mut pkt, &mut self.maps, &in_);
        SimOut {
            action: out.action,
            pkt: pkt.into_bytes(),
            tunnel: out.tunnel,
        }
    }

    /// Host uplink_rx for the NAT return / reverse-DNAT path. `encapped` is the fabric frame
    /// `[OuterEth(14)][OuterIPv6(40)][inner IPv4 ...]` returning from an external peer to a NAT'd
    /// guest. Composes the REAL core fns in the exact order + gates of the eBPF `try_uplink_rx`
    /// non-LB NAT branch (`ingress.rs` 160-209 + the base decap tail):
    ///   1. build the inner 5-tuple key; if the inner dst is a registered nat_ip, zero the external
    ///      src ip+port so it hits the peer-independent `(vni,0,nat_ip,0,nat_port)` reverse entry;
    ///   2. CT lookup: if the entry has `CT_REWRITE_DST`, apply the reverse-DNAT translation
    ///      (`ct_apply`: inner dst IP -> guest, dst port -> orig sport, +IP/L4 checksums);
    ///   3. resolve the delivery target from the RESTORED guest IP (`ROUTES` self-route ->
    ///      `UNDERLAY`) and decap outer Eth+IPv6 + rewrite the inner Ethernet for the guest.
    ///
    /// Returns the delivery `Action` + resulting (decapped, reverse-DNAT'd) frame bytes. Decap-only
    /// — `tunnel` is always `None`.
    ///
    /// Scope: the `ct_touch` refresh, NAT64 v4->v6 expansion, neighbor-NAT reforward, and inner
    /// `dnat_ingress` (VIP) branches are NOT modelled here — this seam covers the network-NAT
    /// reverse-DNAT apply (`ct_apply`) + decap, which is the byte-output-relevant slice for a
    /// plain (non-NAT64) NAT return.
    pub fn uplink_nat_return(&mut self, encapped: &[u8], vni: u32, local: &Local) -> SimOut {
        let mut pkt = VecPkt::from_bytes(encapped);
        let action = flowplane_core::datapath::process_uplink_nat_return(
            &mut pkt,
            &mut self.maps,
            &flowplane_core::datapath::UplinkNatReturnIn { vni, local },
        );
        SimOut {
            action,
            pkt: pkt.into_bytes(),
            tunnel: None,
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
        local: &Local,
        guest_ipv6: [u8; 16],
    ) -> SimOut {
        let mut pkt = VecPkt::from_bytes(encapped);
        let in_ = flowplane_core::datapath::UplinkIn {
            vni,
            local,
            now: self.now,
            guest_ipv6,
        };
        let out = flowplane_core::datapath::process_uplink_rx(&mut pkt, &mut self.maps, &in_);
        SimOut {
            action: out.action,
            pkt: pkt.into_bytes(),
            tunnel: out.tunnel,
        }
    }

    /// Convenience wrapper for a plain non-LB delivery of a guest at overlay `dst` to `tap` (used by
    /// `ns_scenario_test`): synthesizes the `ROUTES` self-route + `UNDERLAY` entry
    /// `program_interface` would have written for that guest (mechanism #1 of the ingress
    /// delivery-target reconstruction — see `flowplane_core::datapath::resolve_uplink_target`) under
    /// a fixed placeholder underlay, then delegates to [`SimNode::uplink`]. With no LB maps set,
    /// `lb_select_forward` returns None and the base path runs.
    pub fn host_uplink(
        &mut self,
        encapped: &[u8],
        vni: u32,
        dst: [u8; 4],
        tap: u32,
        guest_mac: [u8; 6],
    ) -> SimOut {
        // Placeholder self-route underlay — its VALUE is irrelevant (never re-parsed from the
        // wire), it only needs to be a unique key joining the ROUTES entry to the UNDERLAY entry.
        let underlay = [
            0x20,
            0x01,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (tap >> 8) as u8,
            tap as u8,
        ];
        self.maps.underlay.insert(
            underlay,
            UnderlayValue {
                vni,
                tap_ifindex: tap,
                guest_mac,
                _pad: [0; 2],
            },
        );
        self.maps.add_route4(
            vni,
            dst,
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6: underlay,
                is_external: 0,
                _pad: [0; 3],
            },
        );
        let local = Local {
            uplink_ifindex: 0,
            uplink_mac: [0; 6],
            gateway_mac: [0; 6],
            underlay_ipv6: [0; 16],
        };
        self.uplink(encapped, vni, &local)
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
    ///   7. deliver decision (`deliver`): Local tap (inner-Eth rewrite) | Encap (`TunnelEncap`
    ///      decision — no byte write) | Pass. In the Encap arm ONLY, EDT egress shaping
    ///      (`edt_egress`, records `self.last_tstamp`, no drop, step 6b) is called using `pkt.len()`
    ///      — mirrors `tc.rs` `edt_stamp`. Local/Pass leave `last_tstamp` unchanged (EDT shaping
    ///      applies only on the encap/uplink egress path).
    ///
    /// Returns the delivery `Action` + the resulting frame bytes (UNCHANGED on the Encap path — see
    /// `TunnelEncap`) + the tunnel decision.
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
            tunnel: out.tunnel,
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
    ///   5. the [`flowplane_core::encap::tunnel_encap`] decision toward the route nexthop (no byte
    ///      write).
    ///
    /// Returns `Redirect(uplink_ifindex)` + `Some(TunnelEncap{..})` + the translated (NOT
    /// outer-wrapped) `[Eth][IPv4][L4]` frame, or `Pass` when the frame is not a NAT64 packet / has
    /// no route.
    pub fn guest_tx_nat64(&mut self, frame: &[u8], meta: &PortMeta) -> SimOut {
        let mut pkt = VecPkt::from_bytes(frame);
        let out = flowplane_core::datapath::process_guest_tx_nat64(
            &mut pkt,
            &mut self.maps,
            &flowplane_core::datapath::GuestTxNat64In {
                meta,
                local: &self.local,
            },
        );
        SimOut {
            action: out.action,
            pkt: pkt.into_bytes(),
            tunnel: out.tunnel,
        }
    }

    /// Guest egress (`tc_guest_egress_v6` → `forward_decision_v6`) for the NATIVE IPv6→IPv6 forwarding
    /// path. `frame` is a full guest Ethernet frame `[InnerEth(14)][IPv6(40)][L4]` whose dst is NOT in
    /// the NAT64 prefix; `meta` is the sending port's `PortMeta`. Composes the REAL shared core stages
    /// (`egress_fw_ct6` + `route_decision6`) the eBPF `forward_decision_v6` delegates to, via
    /// [`flowplane_core::datapath::process_guest_tx_v6`]:
    ///   1. egress firewall + firewall-only v6 conntrack (deny-by-default on a fresh flow);
    ///   2. route6 + deliver → Local tap (inner-Eth rewrite) | Encap (`TunnelEncap` decision) | Pass;
    ///   3. dest ingress firewall on a NEW same-node Local flow (deny-by-default).
    ///
    /// Returns `Redirect(uplink_ifindex)` + `Some(TunnelEncap{..})` on the encap arm, with `pkt`
    /// UNCHANGED (no outer bytes written).
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
            tunnel: out.tunnel,
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
    /// consumed here before `ct_apply` overwrites the packet). Decap-only — `tunnel` is always `None`.
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
            tunnel: None,
        }
    }

    /// Edge WAN-VIP ingress (`wan_rx`): a plain `[Eth][IPv4|IPv6]` WAN frame; if its dst+port is a WAN
    /// LB VIP (vni=0), Maglev-select a backend and emit the tunnel-key decision toward it (no byte
    /// write). Else Pass. Mirrors `ingress.rs::try_wan_rx` VIP branch. Dispatches on the frame's
    /// ethertype (bytes [12..14]): `0x0800` runs the v4 core select, `0x86DD` runs the v6 core select.
    /// Returns `Some(TunnelEncap{vni: 0, remote: backend})` with `pkt` UNCHANGED on a VIP hit, or the
    /// input unchanged with `tunnel: None` on Pass.
    pub fn wan_rx(&self, plain: &[u8]) -> SimOut {
        let mut pkt = VecPkt::from_bytes(plain);
        let out = flowplane_core::datapath::process_wan_rx(
            &mut pkt,
            &self.maps,
            &flowplane_core::datapath::WanRxIn { local: &self.local },
        );
        SimOut {
            action: out.action,
            pkt: pkt.into_bytes(),
            tunnel: out.tunnel,
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
            tunnel: None,
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
            tunnel: None,
        }
    }

    /// Uniform entry for the Fabric. `Prog::UplinkRx(vni)` carries the VNI explicitly — under
    /// Geneve `collect_md` it rides the tunnel key (`get_tunnel_key().tunnel_id`), out-of-band from
    /// the packet bytes, not encoded in an outer destination address to be re-parsed here.
    pub fn run(&mut self, prog: crate::fabric::Prog, pkt: &[u8]) -> SimOut {
        match prog {
            crate::fabric::Prog::WanRx => self.wan_rx(pkt),
            crate::fabric::Prog::UplinkRx(vni) => {
                let local = self.local;
                self.uplink(pkt, vni, &local)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TEST-FIXTURE-ONLY outer-header byte writer.
//
// Production egress (`flowplane_core::datapath::process_guest_tx*` / `process_wan_rx` / the LB
// remote-backend re-forward in `process_uplink`) no longer writes outer bytes — it emits a
// `TunnelEncap{vni, remote}` decision (see `flowplane_core::encap`), which the kernel's `collect_md`
// Geneve device turns into the real wire header. Decap (`flowplane_core::uplink::decap_and_rewrite`)
// has NOT been migrated yet — it still expects `[OuterEth(14)][OuterIPv6(40)][inner...]` — so
// ingress/decap-path sim tests (and the `Fabric` harness, which stands in for "the wire") still need
// a byte-accurate way to build that shape. This lives here, sim-side, precisely so it can't be
// mistaken for production code.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// TEST-FIXTURE-ONLY: parameters for the hand-rolled outer Eth+IPv6 header [`SimNode::edge_encap`]
/// writes. See the module-level fixture-writer note above — production egress does not use this.
#[derive(Copy, Clone)]
pub struct EncapParams {
    pub gateway_mac: [u8; 6],
    pub uplink_mac: [u8; 6],
    pub src_underlay: [u8; 16],
    pub nexthop_ipv6: [u8; 16],
    pub inner_proto: u8,
}

/// TEST-FIXTURE-ONLY: build `[OuterEth(14)][OuterIPv6(40)][bare inner ...]` from a full inner
/// Ethernet frame + explicit header fields. Used by [`SimNode::edge_encap`].
fn wrap_fixture_outer_full(inner_frame: &[u8], e: &EncapParams) -> Vec<u8> {
    assert!(
        inner_frame.len() >= ETH_LEN,
        "inner_frame must be a full Eth+IPv4 frame"
    );
    let mut p = VecPkt::from_bytes(inner_frame);
    assert!(p.grow_head(IPV6_LEN));
    assert!(write_fixture_outer_v6(&mut p, e));
    p.into_bytes()
}

/// TEST-FIXTURE-ONLY: [`Fabric`](crate::fabric::Fabric)-internal convenience for a FRESH egress hop
/// (WanRx / GuestTx-style — the ORIGIN of a fabric crossing). `inner` is a FULL `[Eth][IP]...]`
/// frame; its own 14-byte Ethernet header is consumed (mirrors a real encap), same as
/// [`SimNode::edge_encap`]. Defaults the (functionally irrelevant to decap) outer MACs + next-header.
pub(crate) fn wrap_fixture_outer_fresh(
    inner: &[u8],
    src_underlay: [u8; 16],
    dst_underlay: [u8; 16],
) -> Vec<u8> {
    wrap_fixture_outer_full(
        inner,
        &EncapParams {
            gateway_mac: [0; 6],
            uplink_mac: [0; 6],
            src_underlay,
            nexthop_ipv6: dst_underlay,
            inner_proto: 4,
        },
    )
}

/// TEST-FIXTURE-ONLY: [`Fabric`](crate::fabric::Fabric)-internal convenience for a RE-FORWARD hop
/// (an `UplinkRx` frame whose PREVIOUS outer wrapper was just stripped). Unlike
/// [`wrap_fixture_outer_fresh`], `inner` here is the BARE `[IP]...]` payload with NO Ethernet header
/// — an earlier hop's encap already consumed it, and re-forward never decaps — so this PREPENDS the
/// full outer header without consuming any of `inner`.
pub(crate) fn wrap_fixture_outer_reforward(
    inner: &[u8],
    src_underlay: [u8; 16],
    dst_underlay: [u8; 16],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ETH_LEN + IPV6_LEN + inner.len());
    out.extend_from_slice(&[0u8; 6]); // outer eth dst (irrelevant to decap)
    out.extend_from_slice(&[0u8; 6]); // outer eth src (irrelevant to decap)
    out.extend_from_slice(&0x86DDu16.to_be_bytes());
    out.push(0x60); // version 6, traffic-class/flow-label = 0
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    out.push(4); // next-header (irrelevant to decap)
    out.push(64); // hop-limit
    out.extend_from_slice(&src_underlay);
    out.extend_from_slice(&dst_underlay);
    out.extend_from_slice(inner);
    out
}

/// TEST-FIXTURE-ONLY byte writer — mirrors the old (now-removed) core `write_outer_v6` exactly,
/// minus the RFC 6438 flow-label field (never meaningful to decap, which ignores the whole outer
/// header's content bar its length + dst). `pkt` must already have `IPV6_LEN` bytes of front room
/// (via `grow_head`).
fn write_fixture_outer_v6(pkt: &mut VecPkt, e: &EncapParams) -> bool {
    if ETH_LEN + IPV6_LEN > pkt.len() {
        return false;
    }
    let inner_len = pkt.logical_len().saturating_sub(ETH_LEN + IPV6_LEN) as u16;
    let mut ok = true;
    ok &= pkt.write_bytes(0, &e.gateway_mac);
    ok &= pkt.write_bytes(6, &e.uplink_mac);
    ok &= pkt.write_bytes(12, &0x86DDu16.to_be_bytes());
    let ip = ETH_LEN;
    ok &= pkt.write_bytes(ip, &[0x60, 0, 0, 0]); // version 6, traffic-class/flow-label = 0
    ok &= pkt.write_bytes(ip + 4, &inner_len.to_be_bytes());
    ok &= pkt.write_bytes(ip + 6, &[e.inner_proto, 64]); // [next_header, hop_limit=64]
    ok &= pkt.write_bytes(ip + 8, &e.src_underlay);
    ok &= pkt.write_bytes(ip + 24, &e.nexthop_ipv6);
    ok
}
