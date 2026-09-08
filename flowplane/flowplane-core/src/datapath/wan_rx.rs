//! Edge WAN-VIP ingress orchestrator ([`process_wan_rx`]): DSR-encode a VIP hit + the v4/v6
//! neighbor-NAT WAN-return relay. Split out of the datapath god-file per review P1.2;
//! behavior-preserving.

use crate::encap::{TunnelEncap, ETH_LEN};
use crate::lb::{lb_select_forward, lb_select_forward_v6};
use crate::maps::Maps;
use crate::parse::{l4_ports, l4_ports_v6};
use crate::pkt::{Action, Pkt};

use super::vip_dnat_rewrite;

/// Inputs for [`process_wan_rx`]. `local` supplies the outer MACs/ifindex + this node's underlay src.
pub struct WanRxIn<'a> {
    pub local: &'a flowplane_common::Local,
}

/// Result of [`process_wan_rx`]: the delivery `Action`, plus the tunnel-key decision on a VIP hit
/// (`None` on Pass). `dsr` carries the Geneve DSR option to stamp alongside `tunnel` on a VIP hit
/// (`None` for every other arm — plain reforward, neighbor-NAT relay, Pass). Lives here (not on
/// `TunnelEncap`) because only the edge `wan_rx` encode ever sets it — see `TunnelEncap`'s doc.
pub struct WanRxOut {
    pub action: Action,
    pub tunnel: Option<TunnelEncap>,
    pub dsr: Option<flowplane_common::DsrOpt>,
}

/// Edge WAN-VIP ingress, in place on `pkt`. Mirrors `ingress.rs::try_wan_rx`: dispatch on ethertype
/// (offset 12) — 0x86DD → v6 core select; else v4 core select, falling back to mechanism #3
/// (neighbor-NAT relay, v4-only — `NEIGHBOR_NAT` has no v6 WAN-return path) on an LB miss. On a
/// VIP hit or a neighbor-NAT relay hit, emit the tunnel-key decision (no byte write — see
/// [`TunnelEncap`]) → `Redirect(uplink_ifindex)`; else `Pass`. The WAN LB service space is `vni = 0`
/// (mirrors the `lb_select_forward*(.., 0)` lookup below). The relay hit uses the REAL owner VNI
/// from [`Maps::neighbor_nat_lookup_any`]. The eBPF `try_wan_rx` (ingress.rs:452) discards it
/// (`let (owner_ul, _vni) = ..`); without the owner's VNI, the relayed packet's tunnel key would
/// carry the WRONG VNI and the owner's peer-independent reverse conntrack key
/// `(vni,0,nat_ip,0,nat_port)` would never match.
pub fn process_wan_rx<P: Pkt, M: Maps>(pkt: &mut P, maps: &M, in_: &WanRxIn) -> WanRxOut {
    let ethertype = match pkt.read_array::<2>(12) {
        Some(b) => u16::from_be_bytes(b),
        None => 0, // frame < 14 bytes → v4 branch (matches plain.get(..).unwrap_or(0))
    };
    let selected = match ethertype {
        0x86DD => lb_select_forward_v6(&*pkt, maps, ETH_LEN, 0),
        _ => lb_select_forward(&*pkt, maps, ETH_LEN, 0),
    };
    if let Some(backend) = selected {
        // DSR-encode. Capture the ORIGINAL VIP (the packet's current inner dst, BEFORE
        // rewriting) into the Geneve DSR option, then rewrite the inner dst -> the backend's OWN
        // overlay IP (the guest only accepts its own IP as a dst). The inner SRC is left as the
        // real client so the backend can key its own DSR conntrack/reverse-SNAT on the real client
        // flow, not the VIP. The `dsr` option travels on `WanRxOut` (not `TunnelEncap` — only this
        // edge encode ever sets it); `try_wan_rx` stamps it on the wire as a Geneve TLV AFTER the
        // tunnel key, via `set_tunnel_opt`.
        let is_v6 = ethertype == 0x86DD;
        let dsr = if is_v6 {
            let vip = match pkt.read_array::<16>(ETH_LEN + 24) {
                Some(v) => v,
                None => {
                    return WanRxOut {
                        action: Action::Drop,
                        tunnel: None,
                        dsr: None,
                    }
                }
            };
            let port = pkt.read_u16_be(ETH_LEN + 40 + 2).unwrap_or(0);
            let nexthdr = pkt.read_u8(ETH_LEN + 6).unwrap_or(0);
            // Rewrite the inner dst VIP -> the backend's own overlay IP, folding the TCP/UDP
            // checksum (no IPv6 header checksum to fix).
            crate::conntrack::rewrite_v6_addr(
                pkt,
                ETH_LEN,
                ETH_LEN + 24,
                nexthdr,
                &vip,
                &backend.overlay_ip,
            );
            flowplane_common::DsrOpt {
                family: 1,
                _pad: 0,
                port,
                vip,
            }
        } else {
            let vip4 = match pkt.read_array::<4>(ETH_LEN + 16) {
                Some(v) => v,
                None => {
                    return WanRxOut {
                        action: Action::Drop,
                        tunnel: None,
                        dsr: None,
                    }
                }
            };
            let port = pkt.read_u16_be(ETH_LEN + 20 + 2).unwrap_or(0);
            let be4 = [
                backend.overlay_ip[0],
                backend.overlay_ip[1],
                backend.overlay_ip[2],
                backend.overlay_ip[3],
            ];
            vip_dnat_rewrite(pkt, ETH_LEN, &vip4, &be4);
            let mut vip16 = [0u8; 16];
            vip16[0..4].copy_from_slice(&vip4);
            flowplane_common::DsrOpt {
                family: 0,
                _pad: 0,
                port,
                vip: vip16,
            }
        };
        return WanRxOut {
            action: Action::Redirect(in_.local.uplink_ifindex),
            tunnel: Some(TunnelEncap {
                vni: backend.vni,
                remote: backend.node_vtep,
            }),
            dsr: Some(dsr),
        };
    }
    // Mechanism #3 (WAN-edge sub-case): a plain WAN-arriving IPv4 packet destined to a nat_ip block
    // owned by some node, relayed toward the owner WITH the owner's real VNI.
    if ethertype != 0x86DD {
        if let Some(dst) = pkt.read_array::<4>(ETH_LEN + 16) {
            if let Some((_proto, _sport, dport)) = l4_ports(&*pkt, ETH_LEN) {
                if let Some((owner_ul, owner_vni)) = maps.neighbor_nat_lookup_any(dst, dport) {
                    return WanRxOut {
                        action: Action::Redirect(in_.local.uplink_ifindex),
                        tunnel: Some(TunnelEncap {
                            vni: owner_vni,
                            remote: owner_ul,
                        }),
                        dsr: None,
                    };
                }
            }
        }
    }
    // Mechanism #3 (WAN-edge sub-case), v6: a plain WAN-arriving IPv6 packet destined to a nat_ip6
    // block owned by some node, relayed toward the owner WITH the owner's real VNI. Mirror of the v4
    // arm above via `neighbor_nat_lookup_any6`.
    if ethertype == 0x86DD {
        if let Some(dst) = pkt.read_array::<16>(ETH_LEN + 24) {
            if let Some((_proto, _sport, dport)) = l4_ports_v6(&*pkt, ETH_LEN) {
                if let Some((owner_ul, owner_vni)) = maps.neighbor_nat_lookup_any6(dst, dport) {
                    return WanRxOut {
                        action: Action::Redirect(in_.local.uplink_ifindex),
                        tunnel: Some(TunnelEncap {
                            vni: owner_vni,
                            remote: owner_ul,
                        }),
                        dsr: None,
                    };
                }
            }
        }
    }
    WanRxOut {
        action: Action::Pass,
        tunnel: None,
        dsr: None,
    }
}
