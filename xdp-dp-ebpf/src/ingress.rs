use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};
use xdp_dp_common::{RouteValue, VipKey, CT_F_NAT64, CT_REWRITE_DST, UNDERLAY_LOCAL_DELIVER};

use crate::arp_nd::GW_MAC;
use crate::maps::{LOCAL, NAT_IPS};
use crate::parse::{
    l4_ports, write16, write6, ETH_LEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_ICMP, IPPROTO_IPIP,
    IPPROTO_IPV6, IPV6_LEN,
};

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// When an ICMP echo request arrives on the uplink destined to a NAT IP (tap≠0) or LB VNF
/// (tap=0), the dataplane generates the ICMP reply itself and re-encaps it back out the uplink.
/// Returns Some(xdp_action) if handled, None to continue normal processing.
#[inline(always)]
fn try_icmp_echo_reply(
    ctx: &XdpContext,
    vni: u32,
    tap_ifindex: u32,
    outer_src: [u8; 16], // outer IPv6 src (sender's underlay)
    outer_dst: [u8; 16], // outer IPv6 dst (our underlay / lb_underlay)
) -> Option<u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let ip_off = ETH_LEN + IPV6_LEN;

    // Need at least inner IPv4 header (20 bytes) + ICMP echo header (8 bytes).
    if data + ip_off + 28 > data_end {
        return None;
    }
    let p = data as *mut u8;

    // Require IHL == 5 (no IP options) so L4 offset is constant.
    if unsafe { *p.add(ip_off) } & 0x0f != 5 {
        return None;
    }
    if unsafe { *p.add(ip_off + 9) } != IPPROTO_ICMP {
        return None;
    }
    let l4 = ip_off + 20;
    if unsafe { *p.add(l4) } != ICMP_ECHO_REQUEST {
        return None;
    }

    let inner_dst = unsafe { core::ptr::read_unaligned(p.add(ip_off + 16) as *const [u8; 4]) };

    // For LB VNF (tap=0): always intercept — the LB VIP has no associated VM to reply.
    // For regular interface (tap≠0): intercept only if inner_dst is a registered NAT IP.
    if tap_ifindex != 0 {
        if unsafe {
            NAT_IPS.get(&VipKey {
                vni,
                ipv4: inner_dst,
            })
        }
        .is_none()
        {
            return None;
        }
    }

    // Generate ICMP echo reply in-place:
    // 1. Flip ICMP type 8→0 and update checksum incrementally.
    let old_cksum = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(l4 + 2) as *const u16) });
    // RFC 1624: new_cksum = ~(~old_cksum + ~old_val + new_val)
    // old_val = 0x0800 (type=8, code=0 as big-endian u16), new_val = 0x0000 (type=0).
    let mut sum = !old_cksum as u32 + !(0x0800u16) as u32 + 0u32;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    let new_cksum = !(sum as u16);
    unsafe {
        *p.add(l4) = ICMP_ECHO_REPLY;
        core::ptr::write_unaligned(p.add(l4 + 2) as *mut u16, new_cksum.to_be());
    }

    // 2. Swap inner IPv4 src/dst (IP checksum is commutative — no change needed).
    let inner_src = unsafe { core::ptr::read_unaligned(p.add(ip_off + 12) as *const [u8; 4]) };
    unsafe {
        core::ptr::write_unaligned(p.add(ip_off + 12) as *mut [u8; 4], inner_dst);
        core::ptr::write_unaligned(p.add(ip_off + 16) as *mut [u8; 4], inner_src);
    }

    // 3. Swap outer IPv6 src/dst and rewrite outer Ethernet for uplink output.
    let local = LOCAL.get(0)?;
    unsafe {
        write6(p, &local.gateway_mac); // dst = gateway MAC
        write6(p.add(6), &local.uplink_mac); // src = our uplink MAC
        write16(p.add(ETH_LEN + 8), &outer_dst); // outer IPv6 src = our underlay
        write16(p.add(ETH_LEN + 24), &outer_src); // outer IPv6 dst = sender's underlay
    }

    Some(unsafe { bpf_redirect(local.uplink_ifindex, 0) } as u32)
}

pub fn try_uplink_rx(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    // Need outer Eth(14) + IPv6(40) + at least the inner IPv4 dst (ends at +20).
    if data + ETH_LEN + IPV6_LEN + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let p = data as *const u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype != ETH_P_IPV6 {
        return Ok(xdp_action::XDP_PASS);
    }
    let nexthdr = unsafe { *p.add(ETH_LEN + 6) };
    if nexthdr == crate::parse::IPPROTO_IPV6 {
        return crate::v6::v6_uplink_rx(ctx);
    }
    if nexthdr != IPPROTO_IPIP {
        return Ok(xdp_action::XDP_PASS);
    }
    // Resolve the destination interface from the OUTER IPv6 dst (uniquely identifies the iface and
    // its VNI). This disambiguates overlapping overlay IPv4 across VNIs.
    let outer_dst = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 24) as *const [u8; 16]) };
    let u = match unsafe { crate::maps::UNDERLAY.get(&outer_dst) } {
        Some(u) => *u,
        None => return Ok(xdp_action::XDP_PASS),
    };
    let vni = u.vni;
    // WAN-edge egress local-deliver: the edge registers its own underlay with a sentinel tap so a
    // fabric->WAN packet (source hypervisor SNAT'd + encapped toward the edge) is decapped and the
    // inner IPv4 handed to the local kernel (VyOS), which routes/masquerades it to the real WAN.
    if u.tap_ifindex == UNDERLAY_LOCAL_DELIVER {
        return edge_local_deliver(ctx);
    }
    // LB takes precedence: Maglev-select a backend underlay. If the backend is remote (not in
    // UNDERLAY), reforward the encapped packet directly to the backend node without decap.
    let lb_ul = crate::lb::lb_select_forward(ctx, ETH_LEN + IPV6_LEN, vni);

    // ICMP error relay: if the outer IPv4 carries an ICMP error (type 3/11/12) whose embedded
    // inner header targets an LB VIP, relay the encapped packet to the selected backend.
    // This runs when lb_select_forward returned None (outer ICMP proto didn't match LB's TCP/UDP
    // key) and handles the dpservice packet_relay_node ICMP-error forwarding semantics.
    if lb_ul.is_none() {
        if let Some(bul) = crate::lb::lb_select_forward_icmp_error(ctx, ETH_LEN + IPV6_LEN, vni) {
            let local = LOCAL.get(0).ok_or(())?;
            return Ok(crate::encap::reforward(ctx, local, &outer_dst, &bul));
        }
    }

    let deliver_u = match lb_ul {
        Some(bul) => match unsafe { crate::maps::UNDERLAY.get(&bul) } {
            Some(bu) => *bu,
            None => {
                let local = LOCAL.get(0).ok_or(())?;
                return Ok(crate::encap::reforward(ctx, local, &outer_dst, &bul));
            }
        },
        None => u,
    };
    // nat_guest: Some((guest_ipv4, orig_sport, is_nat64)) when a CT_REWRITE_DST entry matched.
    // orig_sport is the original guest L4 sport/id (stored in CT xlate_port), used by NAT64 to
    // restore the guest's ICMP identifier on the reply.
    let nat_guest: Option<([u8; 4], u16, bool)> = if lb_ul.is_none() {
        let d = ctx.data();
        let de = ctx.data_end();
        match crate::conntrack::ct_key(d, de, ETH_LEN + IPV6_LEN, vni) {
            Some(mut key) => {
                // NAT returns are demuxed peer-independently: if the inner dst is a registered
                // nat_ip, zero the external src ip+port so the key matches the globally-unique
                // (vni, 0, nat_ip, 0, nat_port) reverse entry the egress allocator stored.
                if unsafe {
                    NAT_IPS.get(&VipKey {
                        vni,
                        ipv4: key.dst_ip,
                    })
                }
                .is_some()
                {
                    key.src_ip = [0; 4];
                    key.src_port = 0;
                }
                match unsafe { crate::maps::CONNTRACK.get(&key) } {
                    Some(e) if e.flags & CT_REWRITE_DST != 0 => {
                        let mut e = *e;
                        let is_nat64 = e.flags & CT_F_NAT64 != 0;
                        let orig_sport = e.xlate_port;
                        crate::conntrack::ct_apply(
                            ctx.data(),
                            ctx.data_end(),
                            ETH_LEN + IPV6_LEN,
                            &e,
                        );
                        crate::conntrack::ct_touch(
                            ctx.data(),
                            ctx.data_end(),
                            ETH_LEN + IPV6_LEN,
                            &key,
                            &mut e,
                        );
                        Some((e.xlate_ip, orig_sport, is_nat64))
                    }
                    _ => None,
                }
            }
            None => None,
        }
    } else {
        None
    };
    let tap_ifindex = deliver_u.tap_ifindex;
    let guest_mac = deliver_u.guest_mac;

    // NAT64 reply path: CT_REWRITE_DST + CT_F_NAT64 → expand IPv4 reply to IPv6 for the guest.
    if let Some((nat_ipv4, orig_sport, true)) = nat_guest {
        return crate::nat64::nat64_ingress(ctx, tap_ifindex, guest_mac, nat_ipv4, orig_sport)
            .map(|r| r.unwrap_or(xdp_action::XDP_PASS));
    }

    // Neighbor NAT: if this inbound packet is destined to a nat_ip owned by ANOTHER node (and we
    // are not the LB target / local NAT owner), re-forward it to the owner's underlay.
    if lb_ul.is_none() && nat_guest.is_none() {
        let d = ctx.data();
        let de = ctx.data_end();
        let off = ETH_LEN + IPV6_LEN;
        if d + off + 20 <= de {
            let q = d as *const u8;
            let inner_dst = unsafe { core::ptr::read_unaligned(q.add(off + 16) as *const [u8; 4]) };
            if let Some((_proto, _sport, dport)) = crate::parse::l4_ports(d, de, off) {
                if let Some(owner_ul) = crate::nat::neighbor_nat_lookup(vni, inner_dst, dport) {
                    let local = LOCAL.get(0).ok_or(())?;
                    return Ok(crate::encap::reforward(ctx, local, &outer_dst, &owner_ul));
                }
            }
        }
    }

    // ICMP echo reply generation: if an ICMP echo request arrives for a NAT IP (tap≠0) or an LB
    // VNF (tap=0), the dataplane generates the reply in-place and sends it back out the uplink,
    // without involving the VM. This matches dpservice's packet_relay_node behaviour.
    if lb_ul.is_none() && nat_guest.is_none() {
        let outer_src = unsafe { core::ptr::read_unaligned(p.add(ETH_LEN + 8) as *const [u8; 16]) };
        if let Some(act) = try_icmp_echo_reply(ctx, vni, tap_ifindex, outer_src, outer_dst) {
            return Ok(act);
        }
    }

    // Ingress firewall: enforce the DESTINATION interface's INGRESS rules on NEW inbound flows
    // (established flows — including seeded returns — already have a conntrack entry, so they are
    // allowed without re-evaluation). Runs on the post-LB/NAT-DNAT inner 5-tuple.
    if let Some(key) = crate::conntrack::ct_key(ctx.data(), ctx.data_end(), ETH_LEN + IPV6_LEN, vni)
    {
        if unsafe { crate::maps::CONNTRACK.get(&key) }.is_none()
            && xdp_dp_core::firewall::fw_eval_dir(
                &crate::coreimpl::CtxPkt { ctx },
                &crate::coreimpl::GlobalMaps,
                ETH_LEN + IPV6_LEN,
                tap_ifindex,
                xdp_dp_common::FW_DIR_INGRESS,
            ) == xdp_dp_common::FW_ACTION_DROP
        {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Track every flow: refresh an existing inbound DEFAULT entry, or create one on miss.
    // Only for non-LB/non-NAT flows; the inner IPv4 is at ETH_LEN + IPV6_LEN pre-adjust_head.
    if lb_ul.is_none() && nat_guest.is_none() {
        if let Some(key) =
            crate::conntrack::ct_key(ctx.data(), ctx.data_end(), ETH_LEN + IPV6_LEN, vni)
        {
            match unsafe { crate::maps::CONNTRACK.get(&key) } {
                Some(e) => {
                    let mut e = *e;
                    crate::conntrack::ct_touch(
                        ctx.data(),
                        ctx.data_end(),
                        ETH_LEN + IPV6_LEN,
                        &key,
                        &mut e,
                    );
                }
                None => crate::conntrack::ct_ensure_default(
                    ctx.data(),
                    ctx.data_end(),
                    ETH_LEN + IPV6_LEN,
                    &key,
                ),
            }
        }
    }
    // Strip outer Eth+IPv6 and rewrite the inner Ethernet for the guest via the shared core seam
    // (byte-identical to the old inline decap+rewrite; also drives the native SimNode).
    match xdp_dp_core::uplink::decap_and_rewrite(
        &mut crate::coreimpl::CtxPkt { ctx },
        tap_ifindex,
        guest_mac,
    ) {
        Err(()) => Err(()),
        Ok(_) => {
            // DNAT: rewrite inner IPv4 dest if inner_dst was a VIP (V->G). Skip for LB packets
            // (already forwarded to the backend VF which owns the LB IP).
            if lb_ul.is_none() && nat_guest.is_none() {
                crate::vip::dnat_ingress(ctx, ETH_LEN, vni);
            }
            // Deliver to the guest via the GUEST_DEV devmap (keyed by tap ifindex), NOT a plain
            // bpf_redirect: on containerlab veths a plain XDP_REDIRECT into the guest veth is
            // silently dropped (veth ndo_xdp_xmit peer requirement); the devmap path delivers.
            // Fall back to a plain redirect if the tap isn't in the devmap (real-NIC / not yet set).
            Ok(crate::maps::GUEST_DEV
                .redirect(tap_ifindex, 0)
                .unwrap_or_else(|_| unsafe { bpf_redirect(tap_ifindex, 0) } as u32))
        }
    }
}

/// WAN-edge egress delivery: strip the outer Eth+IPv6 from a decapped fabric->WAN packet and hand
/// the inner IPv4 to the local kernel (VyOS) via XDP_PASS, which routes/masquerades it to the real
/// WAN. The inner Ethernet dst is set to our uplink MAC so the kernel L3-accepts the frame on the
/// fabric iface after PASS (src = GW_MAC, a locally-generated placeholder).
#[inline(always)]
fn edge_local_deliver(ctx: &XdpContext) -> Result<u32, ()> {
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, IPV6_LEN as i32) } != 0 {
        return Err(());
    }
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN > data_end {
        return Err(());
    }
    let local = LOCAL.get(0).ok_or(())?;
    let q = data as *mut u8;
    unsafe {
        write6(q, &local.uplink_mac);
        write6(q.add(6), &GW_MAC);
        core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IP.to_be());
    }
    Ok(xdp_action::XDP_PASS)
}

/// WAN-edge return path (`wan_rx`, attached to the WAN uplink). A plain IPv4 packet arriving from
/// the internet, destined to a `nat_ip` (no overlay VNI), is matched by `(nat_ip, dport)` against
/// NEIGHBOR_NAT and re-encapped IP-in-IPv6 toward the owning hypervisor's underlay, redirected out
/// the fabric uplink. The owner's reverse-conntrack key `(vni,0,nat_ip,0,nat_port)` — where vni is
/// derived from UNDERLAY[owner_underlay] on the owner — then reverse-SNATs to the source VM.
/// Anything not matching a nat_ip block is XDP_PASSed to the local kernel (VyOS routing/BGP).
pub fn try_wan_rx(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    // Need Eth(14) + at least the inner IPv4 header (ends at +20).
    if data + ETH_LEN + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let p = data as *const u8;
    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(p.add(12) as *const u16) });
    if ethertype == ETH_P_IPV6 {
        // External-LB VIP ingress (vip_rx) for v6: a plain IPv6 WAN frame whose dst+port is a
        // registered WAN LB VIP (vni=0) → Maglev-select an overlay backend and encap IPv6-in-IPv6
        // straight to its underlay. v6 WAN has no neighbor-NAT path (that is IPv4-only), so a miss
        // falls through to XDP_PASS.
        if data + ETH_LEN + 40 > data_end {
            return Ok(xdp_action::XDP_PASS);
        }
        if let Some(backend) = crate::lb::lb_select_forward_v6(ctx, ETH_LEN, 0) {
            let local = LOCAL.get(0).ok_or(())?;
            let route = RouteValue {
                nexthop_vni: 0,
                nexthop_ipv6: backend,
                is_external: 0,
                _pad: [0; 3],
            };
            return crate::encap::encap_and_redirect_via_devmap(
                ctx,
                local,
                &local.underlay_ipv6,
                &route,
                IPPROTO_IPV6, // inner is an IPv6 packet (NOT IPPROTO_IPIP)
            );
        }
        return Ok(xdp_action::XDP_PASS);
    } else if ethertype != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip_off = ETH_LEN;
    let inner_dst = unsafe { core::ptr::read_unaligned(p.add(ip_off + 16) as *const [u8; 4]) };
    let dport = match l4_ports(data, data_end, ip_off) {
        Some((_proto, _sport, dp)) => dp,
        None => return Ok(xdp_action::XDP_PASS),
    };
    // External-LB VIP ingress (vip_rx): if the plain IPv4 dst+port is a registered WAN LB VIP
    // (vni=0), Maglev-select an overlay backend and encap IP-in-IPv6 straight to its underlay,
    // exactly like the neighbor-nat return path below. Falls through to neighbor-nat on a miss.
    if let Some(backend) = crate::lb::lb_select_forward(ctx, ip_off, 0) {
        let local = LOCAL.get(0).ok_or(())?;
        let route = RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: backend,
            is_external: 0,
            _pad: [0; 3],
        };
        return crate::encap::encap_and_redirect_via_devmap(
            ctx,
            local,
            &local.underlay_ipv6,
            &route,
            IPPROTO_IPIP,
        );
    }
    let (owner_ul, _vni) = match crate::nat::neighbor_nat_lookup_any(inner_dst, dport) {
        Some(v) => v,
        None => return Ok(xdp_action::XDP_PASS),
    };
    let local = LOCAL.get(0).ok_or(())?;
    // Encap the plain IPv4 (the outer L2 header is consumed like a guest inner eth) into IP-in-IPv6
    // toward the owner.
    let route = RouteValue {
        nexthop_vni: 0,
        nexthop_ipv6: owner_ul,
        is_external: 0,
        _pad: [0; 3],
    };
    crate::encap::encap_and_redirect_via_devmap(
        ctx,
        local,
        &local.underlay_ipv6,
        &route,
        IPPROTO_IPIP,
    )
}
