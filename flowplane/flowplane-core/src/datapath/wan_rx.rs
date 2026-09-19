//! Edge WAN-LB address ingress orchestrator ([`process_wan_rx`]): DSR-encode an LB address hit + the v4/v6
//! neighbor-NAT WAN-return relay. Split out of the datapath god-file per review P1.2;
//! behavior-preserving.

use crate::encap::{TunnelEncap, ETH_LEN};
use crate::lb::{lb_select_forward, lb_select_forward_v6};
use crate::maps::Maps;
use crate::nat::{nat_icmp_error_relay_port, nat_icmp_error_relay_port6};
use crate::parse::{l4_ports, l4_ports_v6};
use crate::pkt::{Action, Pkt};

use super::floating_ip_dnat_rewrite;

/// Inputs for [`process_wan_rx`]. `local` supplies the outer MACs/ifindex + this node's underlay src.
pub struct WanRxIn<'a> {
    pub local: &'a flowplane_common::Local,
}

/// Result of [`process_wan_rx`]: the delivery `Action`, plus the tunnel-key decision on an LB address hit
/// (`None` on Pass). `dsr` carries the Geneve DSR option to stamp alongside `tunnel` on an LB address hit
/// (`None` for every other arm — plain reforward, neighbor-NAT relay, Pass). Lives here (not on
/// `TunnelEncap`) because only the edge `wan_rx` encode ever sets it — see `TunnelEncap`'s doc.
pub struct WanRxOut {
    pub action: Action,
    pub tunnel: Option<TunnelEncap>,
    pub dsr: Option<flowplane_common::DsrOpt>,
}

/// Edge WAN-LB address ingress, in place on `pkt` — the eBPF `try_wan_rx` is thin glue calling this.
/// Dispatch on ethertype (offset 12) — 0x86DD → v6 core select; else v4 core select, falling back to mechanism #3
/// (neighbor-NAT relay, both families — [`Maps::nat_owner`]/[`Maps::nat_owner6`]) on an LB miss. On a
/// LB address hit or a neighbor-NAT relay hit, emit the tunnel-key decision (no byte write — see
/// [`TunnelEncap`]) → `Redirect(uplink_ifindex)`; else `Pass`. The WAN LB service space is `vni = 0`
/// (mirrors the `lb_select_forward*(.., 0)` lookup below). The relay hit carries the REAL owner VNI
/// from `Maps::nat_owner{,6}` — the edge has no VNI of its own to relay with, and without the
/// owner's VNI the relayed packet's tunnel key would carry the WRONG VNI and the owner's
/// peer-independent reverse conntrack key `(vni,0,nat_ip,0,nat_port)` would never match.
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
        // DSR-encode. Capture the ORIGINAL LB address (the packet's current inner dst, BEFORE
        // rewriting) into the Geneve DSR option, then rewrite the inner dst -> the backend's OWN
        // overlay IP (the guest only accepts its own IP as a dst). The inner SRC is left as the
        // real client so the backend can key its own DSR conntrack/reverse-SNAT on the real client
        // flow, not the LB address. The `dsr` option travels on `WanRxOut` (not `TunnelEncap` — only this
        // edge encode ever sets it); `try_wan_rx` stamps it on the wire as a Geneve TLV AFTER the
        // tunnel key, via `set_tunnel_opt`.
        let is_v6 = ethertype == 0x86DD;
        let dsr = if is_v6 {
            let lb_ip = match pkt.read_array::<16>(ETH_LEN + 24) {
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
            // Rewrite the inner dst LB address -> the backend's own overlay IP, folding the TCP/UDP
            // checksum (no IPv6 header checksum to fix).
            crate::conntrack::rewrite_v6_addr(
                pkt,
                ETH_LEN,
                ETH_LEN + 24,
                nexthdr,
                &lb_ip,
                &backend.overlay_ip,
            );
            flowplane_common::DsrOpt {
                family: 1,
                _pad: 0,
                port,
                lb_ip,
            }
        } else {
            let lb_ip4 = match pkt.read_array::<4>(ETH_LEN + 16) {
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
            floating_ip_dnat_rewrite(pkt, ETH_LEN, &lb_ip4, &be4);
            let mut lb_ip16 = [0u8; 16];
            lb_ip16[0..4].copy_from_slice(&lb_ip4);
            flowplane_common::DsrOpt {
                family: 0,
                _pad: 0,
                port,
                lb_ip: lb_ip16,
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
            // An ICMP error addressed to a nat_ip has no port of its own — the one that names the
            // owning port block is the SOURCE port of the packet it quotes. Prefer that, so PMTUD
            // and unreachables reach the owner instead of being dropped here on a garbage port
            // (`l4_ports`' ICMP arm reads the unused/next-hop-MTU field as an "id"). Only a quote
            // of this very dst is honoured — see `nat_return_key` on why that check matters.
            let relay_port = nat_icmp_error_relay_port(&*pkt, ETH_LEN, &dst)
                .or_else(|| l4_ports(&*pkt, ETH_LEN).map(|(_proto, _sport, dport)| dport));
            if let Some(port) = relay_port {
                if let Some(owner) = maps.nat_owner(&dst, port) {
                    return WanRxOut {
                        action: Action::Redirect(in_.local.uplink_ifindex),
                        tunnel: Some(TunnelEncap {
                            vni: owner.vni,
                            remote: owner.underlay,
                        }),
                        dsr: None,
                    };
                }
            }
        }
    }
    // Mechanism #3 (WAN-edge sub-case), v6: a plain WAN-arriving IPv6 packet destined to a nat_ip6
    // block owned by some node, relayed toward the owner WITH the owner's real VNI. Mirror of the v4
    // arm above via `Maps::nat_owner6`.
    if ethertype == 0x86DD {
        if let Some(dst) = pkt.read_array::<16>(ETH_LEN + 24) {
            // Same ICMPv6-error preference as the v4 arm above: the owning port block is named by
            // the SOURCE port of the quoted packet, not by the error's own header.
            let relay_port = nat_icmp_error_relay_port6(&*pkt, ETH_LEN, &dst)
                .or_else(|| l4_ports_v6(&*pkt, ETH_LEN).map(|(_proto, _sport, dport)| dport));
            if let Some(dport) = relay_port {
                if let Some(owner) = maps.nat_owner6(&dst, dport) {
                    return WanRxOut {
                        action: Action::Redirect(in_.local.uplink_ifindex),
                        tunnel: Some(TunnelEncap {
                            vni: owner.vni,
                            remote: owner.underlay,
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
