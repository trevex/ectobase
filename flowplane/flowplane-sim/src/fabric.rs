use flowplane_core::pkt::Action;
use std::collections::HashMap;

use crate::sim::SimNode;

pub type NodeId = &'static str;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Prog {
    WanRx,
    /// The VNI this hop resolves the delivery target under. Under Geneve `collect_md` the VNI
    /// rides the tunnel key (`get_tunnel_key().tunnel_id`), out-of-band from the packet bytes — the
    /// Fabric threads it explicitly from the PREVIOUS hop's `TunnelEncap.vni` (or the caller, for a
    /// fresh entry) instead of re-deriving it by parsing an outer destination address.
    UplinkRx(u32),
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
    ///
    /// Hop routing keys off the node's `TunnelEncap` decision (`SimOut::tunnel`), NOT packet bytes:
    /// production egress no longer writes an outer header (see `flowplane_core::encap`), so a
    /// `Redirect` with `tunnel: None` is always FINAL local delivery (decap already ran, or same-node
    /// `Deliver::Local`), while `tunnel: Some(t)` means the frame is still crossing the fabric toward
    /// `t.remote`. This harness stands in for the kernel `collect_md` Geneve device (P2 Task 5): it
    /// carries the frame across hops EXACTLY as the kernel would deliver it to the next node's tcx
    /// ingress program — no outer bytes are ever built or stripped. `t.vni` rides out-of-band (as the
    /// tunnel key would), and `t.remote` is used only to look up which node owns that underlay.
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
            let tunnel = out.tunnel;
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
                // `RedirectPeer` is a local delivery via bpf_redirect_peer (inject at the pod-netns
                // peer's ingress) — the peer hop is a kernel-datapath detail the fabric model doesn't
                // simulate, so it is delivery to `tap` exactly like `Redirect` (and never carries a
                // tunnel: peer-redirect is only ever the same-node/decapped local arm).
                Action::Redirect(tap) | Action::RedirectPeer(tap) => {
                    let t = match tunnel {
                        None => {
                            // No tunnel decision: local delivery to a guest tap (decap already ran,
                            // or a same-node `Deliver::Local`) — this IS the final hop.
                            return Trace {
                                hops,
                                outcome: Outcome::Delivered { node: cur, tap },
                            };
                        }
                        Some(t) => t,
                    };
                    // Still crossing the fabric. `outpkt` is ALREADY the frame to hand the next hop's
                    // ingress program, byte-unchanged, in BOTH cases: a fresh egress hop (WanRx /
                    // GuestTx-style Encap arm) never writes outer bytes (see `TunnelEncap`), and a
                    // reforward hop (UplinkRx re-targeting a remote LB backend / neighbor-NAT owner)
                    // doesn't touch bytes either — the frame it received (already the decapped inner,
                    // per the post-decap ingress contract) is exactly what should cross to the next
                    // node. No wrap, no strip: the VNI/remote ride entirely on `t`, not on wire bytes.
                    match self.routes.get(&t.remote).copied() {
                        Some(next) => {
                            buf = outpkt.clone();
                            cur = next;
                            cur_prog = Prog::UplinkRx(t.vni);
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
    use flowplane_common::{
        FwMeta, FwRule, IfaceValue, LbBackend, LbKey, LbValue, Local, FW_ACTION_ACCEPT,
        FW_DIR_INGRESS,
    };

    const EDGE_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xed, 0xee];
    const BACKEND_UL: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xba, 0xcc];
    const VIP: [u8; 4] = [203, 0, 113, 1];
    // The backend's own concrete overlay IP (distinct from the VIP): local LB-backend delivery
    // resolves via `INTERFACES[(vni, backend's overlay ip)]`, never the VIP itself (DSR keeps the
    // inner dst as the VIP).
    const BACKEND_OVERLAY_IP: [u8; 4] = [10, 0, 0, 181];
    const BACKEND_GUEST_MAC: [u8; 6] = [0x66, 0x66, 0x66, 0x66, 0xba, 0xcc];
    const TAP: u32 = 42;

    /// Left-justify a v4 addr into the 16-byte `LbBackend.overlay_ip` representation (`is_v6 == 0`).
    const fn v4_in_16(ip: [u8; 4]) -> [u8; 16] {
        [
            ip[0], ip[1], ip[2], ip[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    }

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
        edge.maps.add_maglev(
            1,
            0,
            LbBackend {
                node_vtep: BACKEND_UL,
                overlay_ip: v4_in_16(BACKEND_OVERLAY_IP),
                vni: 100,
                is_v6: 0,
                _pad: [0; 3],
            },
        );

        // Backend node: an `INTERFACES` local-delivery row for its own overlay IP, tap 42, guest MAC.
        let mut backend = SimNode::with_local(Local {
            uplink_ifindex: 8,
            uplink_mac: [0x03; 6],
            gateway_mac: [0x01; 6],
            underlay_ipv6: BACKEND_UL,
        });
        backend.maps.add_iface(
            100,
            BACKEND_OVERLAY_IP,
            IfaceValue {
                tap_ifindex: TAP,
                is_local: 1,
                underlay_ipv6: BACKEND_UL,
                guest_mac: BACKEND_GUEST_MAC,
                peer_capable: 0,
                _pad: [0; 1],
            },
        );
        // Mesh-replicated LB state: a REAL Maglev backend carries the SAME (vni=0) WAN LB config the
        // edge does (mirrored via mesh gossip — `create_lb`/`add_lb_target` program every
        // participating node identically), so its OWN `uplink_rx` re-selects itself via
        // `lb_select_forward` (`be.node_vtep == local.underlay_ipv6`) and resolves the delivery tap
        // via `INTERFACES[(vni, be.overlay_ip)]` — this does NOT depend on the ingress
        // delivery-target reconstruction (`ROUTES` self-route) at all, which covers ordinary guest
        // delivery, not anycast/VIP delivery. Without this, the backend has no way to recognize "I
        // own this VIP" on ingress (WAN VIPs are anycast, not a guest's own overlay IP, so they have
        // no ROUTES self-route).
        backend.maps.lb.insert(
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
        backend.maps.add_maglev(
            1,
            0,
            LbBackend {
                node_vtep: BACKEND_UL,
                overlay_ip: v4_in_16(BACKEND_OVERLAY_IP),
                vni: 100,
                is_v6: 0,
                _pad: [0; 3],
            },
        );
        // Always-on deny-by-default: the backend needs an explicit allow rule to deliver.
        backend.maps.fw_meta.insert(
            TAP,
            FwMeta {
                ingress_count: 1,
                egress_count: 0,
            },
        );
        backend.maps.fw_rules.insert(
            (TAP, 0),
            FwRule {
                src_ip: [0; 4],
                src_mask: [0; 4],
                dst_ip: [0; 4],
                dst_mask: [0; 4],
                src_port_min: 0,
                src_port_max: 65535,
                dst_port_min: 0,
                dst_port_max: 65535,
                icmp_type: 0xffff,
                icmp_code: 0xffff,
                proto: 0,
                action: FW_ACTION_ACCEPT,
                direction: FW_DIR_INGRESS,
                enabled: 1,
            },
        );

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
