use std::collections::HashMap;
use xdp_dp_core::encap::ETH_LEN;
use xdp_dp_core::pkt::Action;

use crate::sim::SimNode;

pub type NodeId = &'static str;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Prog {
    WanRx,
    UplinkRx,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Delivered { node: NodeId, tap: u32 },
    Dropped { node: NodeId },
    Passed { node: NodeId },
    LoopHalted,
}

pub struct Hop {
    pub node: NodeId,
    pub prog: Prog,
    pub action: Action,
    pub pkt: Vec<u8>,
}

pub struct Trace {
    pub hops: Vec<Hop>,
    pub outcome: Outcome,
}

pub struct Fabric {
    nodes: HashMap<NodeId, SimNode>,
    routes: HashMap<[u8; 16], NodeId>,
}

impl Default for Fabric {
    fn default() -> Self {
        Self::new()
    }
}

impl Fabric {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            routes: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, id: NodeId, node: SimNode) {
        self.nodes.insert(id, node);
    }

    pub fn node_mut(&mut self, id: NodeId) -> &mut SimNode {
        self.nodes.get_mut(id).expect("unknown node")
    }

    /// Register that `underlay` /128 is owned by node `id` (its uplink_rx handles frames for it).
    pub fn route(&mut self, underlay: [u8; 16], id: NodeId) {
        self.routes.insert(underlay, id);
    }

    /// Run `prog` on `ingress`, then follow encap/redirect across the fabric until the frame is
    /// delivered to a guest tap, dropped, or passed. Cap at 8 hops (reforward-loop guard).
    pub fn deliver(&mut self, ingress: NodeId, prog: Prog, pkt: &[u8]) -> Trace {
        let mut hops = Vec::new();
        let mut cur = ingress;
        let mut cur_prog = prog;
        let mut buf = pkt.to_vec();
        for _ in 0..8 {
            let out = self
                .nodes
                .get_mut(cur)
                .expect("unknown node")
                .run(cur_prog, &buf);
            let action = out.action;
            let outpkt = out.pkt.clone();
            hops.push(Hop {
                node: cur,
                prog: cur_prog,
                action,
                pkt: outpkt.clone(),
            });
            match action {
                Action::Drop => {
                    return Trace {
                        hops,
                        outcome: Outcome::Dropped { node: cur },
                    }
                }
                Action::Pass => {
                    return Trace {
                        hops,
                        outcome: Outcome::Passed { node: cur },
                    }
                }
                Action::Redirect(tap) => {
                    // Ethertype at byte 12: 0x0800 => delivered inner frame (guest tap);
                    // 0x86DD => still encapped on the fabric, route by outer IPv6 dst.
                    // NOTE: this assumes an IPv4 inner (0x0800). A delivered IPv6-inner frame would
                    // itself be 0x86DD and be misclassified as still-encapped — fine for the current
                    // LB/N-S coverage (all inner-IPv4); revisit when the sim grows IPv6-inner paths.
                    let ethertype = u16::from_be_bytes([
                        outpkt.get(12).copied().unwrap_or(0),
                        outpkt.get(13).copied().unwrap_or(0),
                    ]);
                    if ethertype == 0x0800 {
                        return Trace {
                            hops,
                            outcome: Outcome::Delivered { node: cur, tap },
                        };
                    }
                    // Still encapped: route by outer IPv6 dst at ETH_LEN+24..ETH_LEN+40.
                    let mut od = [0u8; 16];
                    if outpkt.len() >= ETH_LEN + 40 {
                        od.copy_from_slice(&outpkt[ETH_LEN + 24..ETH_LEN + 40]);
                    }
                    match self.routes.get(&od).copied() {
                        Some(next) => {
                            cur = next;
                            cur_prog = Prog::UplinkRx;
                            buf = outpkt;
                        }
                        None => {
                            return Trace {
                                hops,
                                outcome: Outcome::Passed { node: cur },
                            }
                        }
                    }
                }
            }
        }
        Trace {
            hops,
            outcome: Outcome::LoopHalted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use xdp_dp_common::{LbKey, LbValue, Local, MaglevKey, UnderlayValue};

    const EDGE_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xed, 0xee];
    const BACKEND_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xba, 0xcc];
    const VIP: [u8; 4] = [203, 0, 113, 1];
    const BACKEND_GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0xba, 0xcc];
    const TAP: u32 = 42;

    /// Build a plain `[Eth][IPv4][TCP]` WAN frame as arrives at the edge (dst = VIP, dport = 443).
    fn wan_frame() -> Vec<u8> {
        let src_ip = [203u8, 0, 113, 9]; // external client
        let builder = PacketBuilder::ethernet2([0xaa; 6], [0xbb; 6])
            .ipv4(src_ip, VIP, 64)
            .tcp(50000, 443, 0, 1024);
        let mut out = Vec::new();
        builder.write(&mut out, &[]).unwrap();
        out
    }

    #[test]
    fn two_node_wan_lb_delivers_to_backend() {
        let mut fabric = Fabric::new();

        // Edge node: knows this WAN VIP (vni=0) and routes to backend_ul via Maglev.
        let mut edge = SimNode::with_local(Local {
            uplink_ifindex: 7,
            uplink_mac: [0x02; 6],
            gateway_mac: [0x01; 6],
            underlay_ipv6: EDGE_UL,
        });
        edge.maps.lb.insert(
            LbKey {
                vni: 0,
                ipv4: VIP,
                port: 443,
                proto: 6,
                _pad: 0,
            },
            LbValue {
                table_id: 1,
                size: 1,
            },
        );
        // size=1 => slot 0 always selected regardless of hash
        edge.maps.maglev.insert(
            MaglevKey {
                table_id: 1,
                slot: 0,
            },
            BACKEND_UL,
        );

        // Backend node: UNDERLAY[backend_ul] = vni 100, tap 42, guest MAC.
        // fw_enforcing=false so the ingress firewall accepts without any explicit rule.
        let mut backend = SimNode::with_local(Local {
            uplink_ifindex: 8,
            uplink_mac: [0x03; 6],
            gateway_mac: [0x01; 6],
            underlay_ipv6: BACKEND_UL,
        });
        backend.maps.underlay.insert(
            BACKEND_UL,
            UnderlayValue {
                vni: 100,
                tap_ifindex: TAP,
                guest_mac: BACKEND_GUEST_MAC,
                _pad: [0; 2],
            },
        );
        // fw_enforcing=false (default): ingress firewall returns ACCEPT when no meta entry exists,
        // so LB traffic is delivered without needing explicit rules on the backend.
        backend.maps.fw_enforcing = false;

        fabric.add_node("edge", edge);
        fabric.add_node("backend", backend);
        // Register backend's underlay address so the fabric can route the encapped frame to it.
        fabric.route(BACKEND_UL, "backend");

        let frame = wan_frame();
        let trace = fabric.deliver("edge", Prog::WanRx, &frame);

        // Debug aid: dump hops if the assertion fails.
        for (i, h) in trace.hops.iter().enumerate() {
            eprintln!(
                "hop[{}] node={} prog={:?} action={:?} pkt_len={}",
                i,
                h.node,
                h.prog,
                h.action,
                h.pkt.len()
            );
        }

        assert_eq!(
            trace.outcome,
            Outcome::Delivered {
                node: "backend",
                tap: TAP
            },
            "frame must be delivered to the backend guest tap"
        );
        assert_eq!(
            trace.hops.len(),
            2,
            "exactly 2 hops: edge wan_rx + backend uplink_rx"
        );
    }
}
