//! Synchronous tc-flower flow installer over `NETLINK_ROUTE` (rtnetlink), for the eBPF
//! `flowplane` datapath. Pure sync — no tokio, no async. This module only provides the reusable
//! request/ACK + dump helpers ([`nl::request`], [`nl::request_dump`]); the clsact qdisc and flower
//! filter builders land in later tasks.
//!
//! ---------------------------------------------------------------------------------------------
//! PINNED NETLINK API (increment "flower B", task 1) — resolved + verified against the crate
//! sources under `~/.cargo/registry`, not docs. Later tasks build on exactly these names.
//!
//! Resolved crate versions (Cargo.lock, workspace root `/home/nik/Development/ectobase`):
//!   netlink-packet-route  = 0.33.0
//!   netlink-packet-core   = 0.9.0   (NOTE: route 0.33 depends on core *0.9*, not 0.7 — the
//!                                    direct dep MUST be 0.9 or `NetlinkMessage::from(route_msg)`
//!                                    fails: route impls the serialize traits for core 0.9 only.)
//!   netlink-sys           = 0.8.8
//!   netlink-packet-utils  = 0.5.2   (transitive; provides `Emitable`/`DecodeError`)
//!
//! netlink-sys (blocking `Socket`):
//!   use netlink_sys::{protocols::NETLINK_ROUTE /* : isize = 0 */, Socket, SocketAddr};
//!   Socket::new(NETLINK_ROUTE) -> io::Result<Socket>
//!   socket.bind_auto() -> io::Result<SocketAddr>
//!   socket.send_to(buf: &[u8], addr: &SocketAddr, flags: c_int) -> io::Result<usize>
//!   socket.recv_from_full() -> io::Result<(Vec<u8>, SocketAddr)>   // MSG_PEEK|MSG_TRUNC sized;
//!                                                                   // avoids the `bytes::BufMut`
//!                                                                   // bound that raw recv_from has
//!   SocketAddr::new(port: u32, groups: u32)  // kernel peer = SocketAddr::new(0, 0)
//!
//! netlink-packet-core (0.9):
//!   NetlinkMessage<I> { pub header: NetlinkHeader, pub payload: NetlinkPayload<I> }
//!   NetlinkHeader { pub length: u32, pub message_type: u16, pub flags: u16,
//!                   pub sequence_number: u32, .. }
//!   NetlinkMessage::from(inner: I) -> NetlinkMessage<I>         // From<T>
//!   msg.finalize()                     // sets header.length (+message_type); call after flags set
//!   msg.buffer_len() -> usize
//!   msg.serialize(buf: &mut [u8])      // NO Result; buf must be >= buffer_len()
//!   NetlinkMessage::<I>::deserialize(buf: &[u8]) -> Result<Self, DecodeError>
//!   Flag consts (top-level): NLM_F_REQUEST=1, NLM_F_ACK=4, NLM_F_DUMP=768,
//!                            NLM_F_CREATE=1024, NLM_F_EXCL=512  (all u16)
//!   enum NetlinkPayload<I> { Done(DoneMessage), Error(ErrorMessage), Noop,
//!                            Overrun(Vec<u8>), InnerMessage(I), .. }  // #[non_exhaustive]
//!   ErrorMessage { pub code: Option<NonZeroI32>, .. }
//!     err.raw_code() -> i32      // 0 == plain ACK (code == None) == success; kernel errno is < 0
//!     err.to_io() -> std::io::Error
//!
//! netlink-packet-route (0.33):
//!   enum RouteNetlinkMessage {  // #[non_exhaustive]; tc variants all wrap tc::TcMessage:
//!       NewQueueDiscipline(TcMessage), DelQueueDiscipline(TcMessage), GetQueueDiscipline(TcMessage),
//!       NewTrafficFilter(TcMessage),   DelTrafficFilter(TcMessage),   GetTrafficFilter(TcMessage),
//!       NewTrafficClass(TcMessage), .., NewTrafficChain(TcMessage), .. }
//!   tc paths (all under `netlink_packet_route::tc`):
//!       tc::TcMessage (impl Default), tc::TcHandle, tc::TcAttribute (enum),
//!       tc::TcHeader, tc::TcOption, tc::TcFilterFlower, tc::TcFilterFlowerOption  // <- for task 2+
//! ---------------------------------------------------------------------------------------------

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, Context, Result};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_route::tc::{
    TcAction, TcActionAttribute, TcActionGeneric, TcActionMirror, TcActionMirrorOption,
    TcActionOption, TcActionTunnelKey, TcActionTunnelKeyOption, TcActionType, TcAttribute,
    TcFilterFlower, TcFilterFlowerOption, TcHandle, TcHeader, TcMessage, TcMirror,
    TcMirrorActionType, TcOption, TcTunnelKey,
};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

/// Sync rtnetlink request/ACK + dump primitives. Everything here opens its own short-lived
/// `NETLINK_ROUTE` socket per call — fine for the low-frequency control-plane installs this serves.
pub mod nl {
    use super::*;

    /// Kernel netlink peer address (port 0, no multicast groups).
    fn kernel_addr() -> SocketAddr {
        SocketAddr::new(0, 0)
    }

    /// Open + `bind_auto` a fresh blocking `NETLINK_ROUTE` socket.
    fn open_socket() -> Result<Socket> {
        let mut socket = Socket::new(NETLINK_ROUTE).context("open NETLINK_ROUTE socket")?;
        socket
            .bind_auto()
            .context("bind_auto NETLINK_ROUTE socket")?;
        Ok(socket)
    }

    /// Frame + serialize a `RouteNetlinkMessage` into a finalized netlink datagram with the given
    /// flags OR'd on top of the caller-supplied `flags` (the caller decides REQUEST/ACK/DUMP/...).
    fn frame(msg: RouteNetlinkMessage, flags: u16) -> Vec<u8> {
        let mut nlmsg = NetlinkMessage::from(msg);
        nlmsg.header.flags = flags;
        nlmsg.finalize();
        let mut buf = vec![0u8; nlmsg.buffer_len()];
        nlmsg.serialize(&mut buf[..]);
        buf
    }

    /// Send a request that expects a single ACK (NLMSG_ERROR with code 0). Frames the message with
    /// `NLM_F_REQUEST | NLM_F_ACK | extra_flags` (pass e.g. `NLM_F_CREATE | NLM_F_EXCL` for adds),
    /// sends it, and interprets the reply:
    ///   * `NetlinkPayload::Error` with `raw_code() == 0`         => Ok (plain ACK / success)
    ///   * `NetlinkPayload::Error` with `raw_code()` in `tolerate` => Ok (idempotent no-op, e.g.
    ///                                                                -EEXIST on create, -ENOENT on del)
    ///   * `NetlinkPayload::Error` otherwise                       => Err with the errno
    ///   * anything else                                           => Err (unexpected reply)
    ///
    /// `tolerate` holds negative kernel errnos (e.g. `-libc::EEXIST`).
    pub fn request(msg: RouteNetlinkMessage, extra_flags: u16, tolerate: &[i32]) -> Result<()> {
        let socket = open_socket()?;
        let buf = frame(msg, NLM_F_REQUEST | NLM_F_ACK | extra_flags);
        socket
            .send_to(&buf, &kernel_addr(), 0)
            .context("send_to kernel")?;

        let (rx, _addr) = socket.recv_from_full().context("recv_from kernel")?;
        let reply = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&rx)
            .map_err(|e| anyhow!("deserialize ACK reply: {e}"))?;

        match reply.payload {
            NetlinkPayload::Error(err) => {
                let code = err.raw_code();
                if code == 0 || tolerate.contains(&code) {
                    Ok(())
                } else {
                    Err(anyhow!(
                        "netlink request failed: {} (errno {})",
                        err.to_io(),
                        code
                    ))
                }
            }
            NetlinkPayload::Done(_) => Ok(()),
            other => bail!("unexpected netlink reply to ACK'd request: {other:?}"),
        }
    }

    /// Send a dump request (`NLM_F_REQUEST | extra_flags`, caller passes `NLM_F_DUMP`) and collect
    /// every `InnerMessage` until an `NLMSG_DONE` (or an error). A single datagram can carry several
    /// netlink messages back-to-back, so we advance through each recv buffer by `header.length`.
    pub fn request_dump(
        msg: RouteNetlinkMessage,
        extra_flags: u16,
    ) -> Result<Vec<RouteNetlinkMessage>> {
        let socket = open_socket()?;
        let buf = frame(msg, NLM_F_REQUEST | extra_flags);
        socket
            .send_to(&buf, &kernel_addr(), 0)
            .context("send_to kernel (dump)")?;

        let mut out = Vec::new();
        'recv: loop {
            let (rx, _addr) = socket.recv_from_full().context("recv_from kernel (dump)")?;
            let mut offset = 0usize;
            while offset < rx.len() {
                let slice = &rx[offset..];
                let reply = NetlinkMessage::<RouteNetlinkMessage>::deserialize(slice)
                    .map_err(|e| anyhow!("deserialize dump message at offset {offset}: {e}"))?;
                // Length of this message within the datagram (for multi-message advance).
                let len = reply.header.length as usize;

                match reply.payload {
                    NetlinkPayload::InnerMessage(m) => out.push(m),
                    NetlinkPayload::Done(_) => break 'recv,
                    NetlinkPayload::Error(err) => {
                        let code = err.raw_code();
                        if code == 0 {
                            // ACK-style terminator (no NLMSG_DONE); treat as end of dump.
                            break 'recv;
                        }
                        return Err(anyhow!(
                            "netlink dump failed: {} (errno {})",
                            err.to_io(),
                            code
                        ));
                    }
                    NetlinkPayload::Noop => {}
                    other => bail!("unexpected netlink payload in dump: {other:?}"),
                }

                // Guard against a zero/short length so we can never spin forever.
                if len == 0 || len > slice.len() {
                    break;
                }
                offset += len;
            }
        }
        Ok(out)
    }
}

/// clsact qdisc handle == parent (Linux `TC_H_CLSACT` == `TC_H_INGRESS`, major 0xFFFF / minor
/// 0xFFF1). The crate exposes this as [`TcHandle::CLSACT`] (major u16::MAX, minor 0xFFF1).
const TC_H_CLSACT: u32 = 0xFFFF_FFF1;

/// Idempotently ensure a `clsact` qdisc on `ifindex` (RTM_NEWQDISC; EEXIST tolerated — an
/// increment-A VF representor already has clsact for tc_guest_tx).
///
/// Message construction (netlink-packet-route 0.33): a [`TcMessage`] whose header carries
/// `index = ifindex`, `handle = parent = TcHandle::CLSACT` (== `TC_H_CLSACT`), and a single
/// `TcAttribute::Kind("clsact")` NLA (TCA_KIND). Sent as `NewQueueDiscipline` with
/// `NLM_F_CREATE | NLM_F_EXCL`; a duplicate returns -EEXIST which we tolerate.
pub fn ensure_clsact(ifindex: u32) -> Result<()> {
    use netlink_packet_core::{NLM_F_CREATE, NLM_F_EXCL};
    use netlink_packet_route::tc::{TcAttribute, TcHandle, TcMessage};

    // Sanity: our named constant must equal the crate's CLSACT handle (major<<16 | minor).
    debug_assert_eq!(
        TC_H_CLSACT,
        ((TcHandle::CLSACT.major as u32) << 16) | TcHandle::CLSACT.minor as u32
    );

    let mut tc = TcMessage::default();
    tc.header.index = ifindex as i32;
    // The clsact qdisc lives at handle `ffff:0` under parent `ffff:fff1` (TC_H_CLSACT) — i.e.
    // `tc qdisc show` reports `qdisc clsact ffff: parent ffff:fff1`. Setting handle == parent ==
    // TC_H_CLSACT is rejected by the kernel with EINVAL, so the handle major is 0xffff / minor 0.
    tc.header.handle = TcHandle {
        major: 0xffff,
        minor: 0,
    };
    tc.header.parent = TcHandle::CLSACT;
    // TCA_KIND = "clsact"
    tc.attributes.push(TcAttribute::Kind("clsact".to_string()));

    nl::request(
        RouteNetlinkMessage::NewQueueDiscipline(tc),
        NLM_F_CREATE | NLM_F_EXCL,
        &[-libc::EEXIST],
    )
    .context("ensure clsact qdisc")
}

/// clsact **ingress** filter parent (`TC_H_CLSACT` == `TC_H_INGRESS` block, minor `fff2` ==
/// `TC_H_MIN_INGRESS`). Filters attach here to run on RX; matches `TcHandle{0xffff, 0xfff2}`.
const TC_CLSACT_INGRESS_PARENT: u32 = 0xFFFF_FFF2;

/// `TCA_CLS_FLAGS_IN_HW` (`1 << 2`) — set by the kernel in `TCA_FLOWER_FLAGS` once the filter has
/// been successfully offloaded to hardware (on netdevsim, an accept-all offload).
const TCA_CLS_FLAGS_IN_HW: u32 = 1 << 2;

/// tunnel_key `SET` mode (`TCA_TUNNEL_KEY_ACT_SET`); the encap-set variant of the action.
const TCA_TUNNEL_KEY_ACT_SET: i32 = 1;

/// IANA ethertypes used for the flower `EthType` match + the filter's wire protocol.
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

/// Layer-3 match half of a 5-tuple: exact `/32` (v4) or `/128` (v6) src+dst.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowL3 {
    V4 { src: [u8; 4], dst: [u8; 4] },
    V6 { src: [u8; 16], dst: [u8; 16] },
}

/// A 5-tuple flow to match in flower: L3 addresses, IP protocol (6 TCP / 17 UDP), and ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    pub l3: FlowL3,
    /// IP protocol number — 6 (TCP) or 17 (UDP).
    pub ip_proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

/// The encap+redirect action to apply on a matched flow: set a Geneve tunnel_key (VNI + remote
/// IPv6 VTEP) then mirred-redirect to `redirect_ifindex`'s egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncapRedirect {
    pub vni: u32,
    /// Remote VTEP (tunnel outer destination), always IPv6 in this datapath.
    pub remote_vtep: [u8; 16],
    pub redirect_ifindex: u32,
}

/// Identifies an installed filter for later delete/query: (ifindex, priority, handle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowHandle {
    pub ifindex: u32,
    pub pref: u16,
    pub handle: u32,
}

/// Build the `flower` `TCA_OPTIONS` NLAs for a 5-tuple + action set.
///
/// Emits `EthType` + exact-match L3 (src/dst with all-ones masks), `IpProto`, the proto-specific
/// port matches (TCP→`TcpSrc/Dst`, UDP→`UdpSrc/Dst`), and the nested `Actions` list. `EthType` and
/// the port values are passed in host order — the crate emits them big-endian on the wire (see
/// `emit_u16_be` in `tc/filters/flower/core.rs`), so e.g. `EthType(0x0800)` is correct.
fn build_flower_options(key: &FlowKey, act: &EncapRedirect) -> Vec<TcFilterFlowerOption> {
    let mut opts = Vec::new();
    match key.l3 {
        FlowL3::V4 { src, dst } => {
            opts.push(TcFilterFlowerOption::EthType(ETH_P_IP));
            opts.push(TcFilterFlowerOption::Ipv4Src(Ipv4Addr::from(src)));
            opts.push(TcFilterFlowerOption::Ipv4SrcMask(Ipv4Addr::new(
                255, 255, 255, 255,
            )));
            opts.push(TcFilterFlowerOption::Ipv4Dst(Ipv4Addr::from(dst)));
            opts.push(TcFilterFlowerOption::Ipv4DstMask(Ipv4Addr::new(
                255, 255, 255, 255,
            )));
        }
        FlowL3::V6 { src, dst } => {
            opts.push(TcFilterFlowerOption::EthType(ETH_P_IPV6));
            opts.push(TcFilterFlowerOption::Ipv6Src(Ipv6Addr::from(src)));
            opts.push(TcFilterFlowerOption::Ipv6SrcMask(Ipv6Addr::from(
                [0xFF; 16],
            )));
            opts.push(TcFilterFlowerOption::Ipv6Dst(Ipv6Addr::from(dst)));
            opts.push(TcFilterFlowerOption::Ipv6DstMask(Ipv6Addr::from(
                [0xFF; 16],
            )));
        }
    }
    opts.push(TcFilterFlowerOption::IpProto(key.ip_proto));
    match key.ip_proto {
        6 => {
            opts.push(TcFilterFlowerOption::TcpSrc(key.src_port));
            opts.push(TcFilterFlowerOption::TcpDst(key.dst_port));
        }
        17 => {
            opts.push(TcFilterFlowerOption::UdpSrc(key.src_port));
            opts.push(TcFilterFlowerOption::UdpDst(key.dst_port));
        }
        _ => {}
    }
    opts.push(TcFilterFlowerOption::Actions(build_actions(act)));
    opts
}

/// Build the two-action list for the flower filter, in pipeline order:
///   1. `tunnel_key` (SET) — attach Geneve encap metadata: `EncKeyId = vni`, `EncIpv6Dst =
///      remote_vtep`. Generic control is `PIPE` so processing continues to the next action.
///   2. `mirred` (egress REDIRECT) to `redirect_ifindex`. Generic control is `STOLEN` (the
///      canonical control code iproute2 uses for a redirect — the packet leaves this pipeline).
///
/// Each action is a `TcAction { tab: 1, attributes: [Kind, Options] }`; the concrete parameters
/// live in the nested `TcActionOption` under `TcActionAttribute::Options`.
fn build_actions(act: &EncapRedirect) -> Vec<TcAction> {
    // `TcActionGeneric` / `TcMirror` are `#[non_exhaustive]` in the crate, so we can't use a struct
    // literal from here — build via `Default` and set the fields we care about.

    // Action 1: tunnel_key SET (encap metadata). Generic control = PIPE (continue to next action).
    // Each action's NLA type (`tab`) is its 1-based order index in the list (TCA_ACT_MAX_PRIO
    // slots). Two actions sharing a `tab` collide in the kernel's action array and only one
    // survives — so tunnel_key is slot 1, mirred is slot 2.
    let mut tk_generic = TcActionGeneric::default();
    tk_generic.action = TcActionType::Pipe;
    let mut tunnel_key = TcAction::default(); // tab defaults to 1 (slot 1)
    tunnel_key.attributes = vec![
        TcActionAttribute::Kind(TcActionTunnelKey::KIND.to_string()),
        TcActionAttribute::Options(vec![
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::Parms(TcTunnelKey {
                generic: tk_generic,
                t_action: TCA_TUNNEL_KEY_ACT_SET,
            })),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncKeyId(act.vni)),
            // The kernel's tunnel_key SET requires BOTH an enc src and dst of the same family; the
            // src is the (unspecified) local VTEP — the datapath/route picks the real source.
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncIpv6Src(Ipv6Addr::UNSPECIFIED)),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncIpv6Dst(Ipv6Addr::from(
                act.remote_vtep,
            ))),
        ]),
    ];

    // Action 2: mirred egress redirect. Generic control = STOLEN (packet leaves this pipeline).
    let mut mirror_generic = TcActionGeneric::default();
    mirror_generic.action = TcActionType::Stolen;
    let mut mirror = TcMirror::default();
    mirror.generic = mirror_generic;
    mirror.eaction = TcMirrorActionType::EgressRedir;
    mirror.ifindex = act.redirect_ifindex;
    let mut mirred = TcAction::default();
    mirred.tab = 2; // slot 2 (must differ from tunnel_key's slot 1)
    mirred.attributes = vec![
        TcActionAttribute::Kind(TcActionMirror::KIND.to_string()),
        TcActionAttribute::Options(vec![TcActionOption::Mirror(TcActionMirrorOption::Parms(
            mirror,
        ))]),
    ];
    vec![tunnel_key, mirred]
}

/// Compute the tc `tcm_info` word encoding filter priority + wire protocol.
///
/// C equivalent: `TC_H_MAKE(prio << 16, htons(proto))` — high 16 bits = priority, low 16 bits =
/// the ethertype in network byte order. The crate emits `TcHeader::info` as a native `u32`
/// (`repr(C, packed)` struct, see `tc/header.rs`), and the kernel reads `tcm_info` natively, so we
/// pack `(pref << 16) | htons(proto)` where `to_be()` yields the byte-swapped (network-order)
/// ethertype on a little-endian host.
fn filter_info(pref: u16, proto_ethertype: u16) -> u32 {
    ((pref as u32) << 16) | (proto_ethertype.to_be() as u32 & 0xFFFF)
}

/// The wire ethertype for a flow's address family (`ETH_P_IP` / `ETH_P_IPV6`).
fn flow_ethertype(key: &FlowKey) -> u16 {
    match key.l3 {
        FlowL3::V4 { .. } => ETH_P_IP,
        FlowL3::V6 { .. } => ETH_P_IPV6,
    }
}

/// Build the `TcMessage` header shared by install/delete/query for one filter: index=ifindex,
/// parent=clsact ingress, handle=`handle`, info=prio+proto.
fn filter_header(ifindex: u32, pref: u16, handle: u32, proto_ethertype: u16) -> TcHeader {
    let mut header = TcHeader::default();
    header.index = ifindex as i32;
    header.parent = TcHandle::from(TC_CLSACT_INGRESS_PARENT);
    header.handle = TcHandle::from(handle);
    header.info = filter_info(pref, proto_ethertype);
    header
}

/// Install a `flower` filter matching `key` with tunnel_key+mirred actions on `ifindex`'s clsact
/// **ingress** at (`pref`, `handle`). Sent as `RTM_NEWTFILTER` with `NLM_F_CREATE | NLM_F_EXCL`.
pub fn install_flow(
    ifindex: u32,
    pref: u16,
    handle: u32,
    key: &FlowKey,
    act: &EncapRedirect,
) -> Result<FlowHandle> {
    use netlink_packet_core::{NLM_F_CREATE, NLM_F_EXCL};

    let ethertype = flow_ethertype(key);
    let tc = TcMessage::from_parts(
        filter_header(ifindex, pref, handle, ethertype),
        vec![
            TcAttribute::Kind(TcFilterFlower::KIND.to_string()),
            TcAttribute::Options(
                build_flower_options(key, act)
                    .into_iter()
                    .map(TcOption::Flower)
                    .collect(),
            ),
        ],
    );

    nl::request(
        RouteNetlinkMessage::NewTrafficFilter(tc),
        NLM_F_CREATE | NLM_F_EXCL,
        &[],
    )
    .context("install flower flow")?;

    Ok(FlowHandle {
        ifindex,
        pref,
        handle,
    })
}

/// Delete the flower filter identified by `h` (`RTM_DELTFILTER`, same header identity, no options).
/// A missing filter (`-ENOENT`) is tolerated so delete is idempotent.
pub fn delete_flow(h: &FlowHandle) -> Result<()> {
    // Deleting by (ifindex, parent, prio, handle) — the protocol half of tcm_info is not needed to
    // identify the filter, so pass 0 for the ethertype.
    let tc = TcMessage::from_parts(filter_header(h.ifindex, h.pref, h.handle, 0), Vec::new());
    nl::request(
        RouteNetlinkMessage::DelTrafficFilter(tc),
        0,
        &[-libc::ENOENT],
    )
    .context("delete flower flow")
}

/// Dump the clsact-ingress filters on `h.ifindex` and return the flower option list of the one
/// whose `handle` matches — `None` if no such filter is installed. This is the shared query path
/// behind both existence checks and [`flow_in_hw`].
fn query_flower_opts(h: &FlowHandle) -> Result<Option<Vec<TcFilterFlowerOption>>> {
    use netlink_packet_core::NLM_F_DUMP;

    let want = TcHandle::from(h.handle);
    let tc = TcMessage::from_parts(filter_header(h.ifindex, h.pref, h.handle, 0), Vec::new());
    let replies = nl::request_dump(RouteNetlinkMessage::GetTrafficFilter(tc), NLM_F_DUMP)
        .context("dump flower filters")?;

    for msg in replies {
        let tc = match msg {
            RouteNetlinkMessage::NewTrafficFilter(tc) => tc,
            _ => continue,
        };
        if tc.header.handle != want {
            continue;
        }
        // A single filter can carry multiple option attributes; flatten all flower options.
        let mut flower = Vec::new();
        for attr in &tc.attributes {
            if let TcAttribute::Options(opts) = attr {
                for opt in opts {
                    if let TcOption::Flower(f) = opt {
                        flower.push(f.clone());
                    }
                }
            }
        }
        return Ok(Some(flower));
    }
    Ok(None)
}

/// True iff the filter identified by `h` currently exists on its clsact-ingress hook.
#[cfg(test)]
fn flow_present(h: &FlowHandle) -> Result<bool> {
    Ok(query_flower_opts(h)?.is_some())
}

/// Query whether the filter identified by `h` is installed in hardware.
///
/// Dumps all filters on `h.ifindex`'s clsact ingress (`RTM_GETTFILTER` + `NLM_F_DUMP`), finds the
/// message whose `handle` matches, and reads the offload state from the flower options: the
/// `TCA_CLS_FLAGS_IN_HW` bit in `Flags`, or a non-zero `InHwCount`. Returns `false` when the filter
/// is absent, or present but software-only.
///
/// NOTE: `in_hw` is only ever `true` on an offload-capable device (a real NIC / switchdev
/// representor whose driver accepts flower). `netdevsim` offloads *only* BPF classifiers — flower
/// filters there are always `not_in_hw` — so on netdevsim this reads the flag honestly and returns
/// `false`. The netdevsim gate therefore validates the netlink *encoding* + install/query/delete
/// round-trip, not hardware offload.
pub fn flow_in_hw(h: &FlowHandle) -> Result<bool> {
    let Some(opts) = query_flower_opts(h)? else {
        return Ok(false);
    };
    for f in &opts {
        match f {
            TcFilterFlowerOption::Flags(flags) if flags & TCA_CLS_FLAGS_IN_HW != 0 => {
                return Ok(true)
            }
            TcFilterFlowerOption::InHwCount(n) if *n > 0 => return Ok(true),
            _ => {}
        }
    }
    Ok(false)
}

#[cfg(test)]
pub(crate) mod tests_support {
    use std::process::Command;
    pub struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::write("/sys/bus/netdevsim/del_device", "42");
            let _ = Command::new("rmmod").arg("netdevsim").status();
        }
    }
    /// modprobe netdevsim, create netdevsim42 (1 port), return (PF ifindex `eni42np1`, cleanup).
    pub fn netdevsim_pf() -> (u32, Cleanup) {
        let _ = Command::new("modprobe").arg("netdevsim").status();
        std::fs::write("/sys/bus/netdevsim/new_device", "42 1").expect("new_device");
        // small settle for the netdev to appear
        let _ = Command::new("udevadm").arg("settle").status();
        let ifx: u32 = std::fs::read_to_string("/sys/class/net/eni42np1/ifindex")
            .expect("read eni42np1 ifindex")
            .trim()
            .parse()
            .expect("parse ifindex");
        (ifx, Cleanup)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EncapRedirect, FlowKey, FlowL3, TcActionAttribute, TcActionOption, TcFilterFlowerOption,
    };

    /// Count the actions inside the `Actions(_)` flower option (there must be exactly one).
    fn actions_len(opts: &[TcFilterFlowerOption]) -> usize {
        opts.iter()
            .filter_map(|o| match o {
                TcFilterFlowerOption::Actions(a) => Some(a.len()),
                _ => None,
            })
            .next()
            .expect("flower options contain an Actions(_) entry")
    }

    #[test]
    fn build_flower_options_v4_tcp() {
        let key = FlowKey {
            l3: FlowL3::V4 {
                src: [10, 0, 0, 1],
                dst: [10, 0, 0, 2],
            },
            ip_proto: 6,
            src_port: 1111,
            dst_port: 443,
        };
        let act = EncapRedirect {
            vni: 100,
            remote_vtep: [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xee],
            redirect_ifindex: 42,
        };
        let opts = super::build_flower_options(&key, &act);

        assert!(opts
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::EthType(0x0800))));
        assert!(opts
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::IpProto(6))));
        assert!(opts.iter().any(|o| matches!(
            o,
            TcFilterFlowerOption::Ipv4Src(ip) if ip.octets() == [10, 0, 0, 1]
        )));
        assert!(opts.iter().any(|o| matches!(
            o,
            TcFilterFlowerOption::Ipv4Dst(ip) if ip.octets() == [10, 0, 0, 2]
        )));
        assert!(opts
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::TcpSrc(1111))));
        assert!(opts
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::TcpDst(443))));
        // No UDP port matches on a TCP flow.
        assert!(!opts
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::UdpSrc(_))));
        assert_eq!(actions_len(&opts), 2, "tunnel_key + mirred");
    }

    #[test]
    fn build_flower_options_v6_udp() {
        let key = FlowKey {
            l3: FlowL3::V6 {
                src: [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                dst: [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            },
            ip_proto: 17,
            src_port: 2222,
            dst_port: 53,
        };
        let act = EncapRedirect {
            vni: 200,
            remote_vtep: [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xee],
            redirect_ifindex: 7,
        };
        let opts = super::build_flower_options(&key, &act);

        assert!(opts
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::EthType(0x86DD))));
        assert!(opts
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::IpProto(17))));
        assert!(opts.iter().any(|o| matches!(
            o,
            TcFilterFlowerOption::Ipv6Src(ip) if ip.octets()[15] == 1
        )));
        assert!(opts.iter().any(|o| matches!(
            o,
            TcFilterFlowerOption::Ipv6Dst(ip) if ip.octets()[15] == 2
        )));
        assert!(opts
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::UdpSrc(2222))));
        assert!(opts
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::UdpDst(53))));
        // No TCP port matches on a UDP flow.
        assert!(!opts
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::TcpSrc(_))));
        assert_eq!(actions_len(&opts), 2, "tunnel_key + mirred");
    }

    #[test]
    fn build_actions_order_and_kinds() {
        let act = EncapRedirect {
            vni: 100,
            remote_vtep: [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xee],
            redirect_ifindex: 42,
        };
        let actions = super::build_actions(&act);
        assert_eq!(actions.len(), 2);

        // Action 0 is tunnel_key, action 1 is mirred (pipeline order).
        let kind = |a: &super::TcAction| -> String {
            a.attributes
                .iter()
                .find_map(|attr| match attr {
                    TcActionAttribute::Kind(k) => Some(k.clone()),
                    _ => None,
                })
                .expect("action has a Kind")
        };
        assert_eq!(kind(&actions[0]), "tunnel_key");
        assert_eq!(kind(&actions[1]), "mirred");

        // tunnel_key carries the VNI as EncKeyId.
        let has_vni = actions[0].attributes.iter().any(|attr| match attr {
            TcActionAttribute::Options(opts) => opts.iter().any(|o| {
                matches!(
                    o,
                    TcActionOption::TunnelKey(super::TcActionTunnelKeyOption::EncKeyId(100))
                )
            }),
            _ => false,
        });
        assert!(has_vni, "tunnel_key options carry EncKeyId(vni)");
    }

    #[test]
    fn filter_info_packs_prio_and_proto() {
        // v4: prio 0xC000, proto 0x0800 → 0xC0000008 (matches the crate's flower GET fixtures).
        assert_eq!(super::filter_info(0xC000, 0x0800), 0xC000_0008);
        // Low 16 bits carry htons(ethertype); high 16 bits carry the priority.
        assert_eq!(super::filter_info(100, 0x86DD) & 0xFFFF, 0xDD86);
        assert_eq!(super::filter_info(100, 0x0800) >> 16, 100);
    }

    /// The netdevsim kernel gate. netdevsim only offloads BPF classifiers (never flower), so a
    /// flower filter installed here is always `not_in_hw`. This test therefore validates what
    /// netdevsim *can* prove: the kernel **accepts** our flower + tunnel_key + mirred netlink
    /// encoding (no EINVAL), the installed filter is **queryable** with the 5-tuple we asked for,
    /// `flow_in_hw` reads the (false) offload flag honestly, and `delete_flow` removes it. On real
    /// offload-capable hardware the same encoding would flip `flow_in_hw` to true.
    #[test]
    #[ignore = "privileged: modprobe netdevsim (needs root); run under sudo"]
    fn install_flow_in_hw_and_delete_on_netdevsim() {
        let (ifx, _c) = super::tests_support::netdevsim_pf();
        super::ensure_clsact(ifx).unwrap();
        let act = EncapRedirect {
            vni: 100,
            remote_vtep: [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xee],
            redirect_ifindex: ifx,
        };

        // --- v4 / TCP: install is accepted (encoding valid), filter is queryable ---
        let v4 = FlowKey {
            l3: FlowL3::V4 {
                src: [10, 0, 0, 1],
                dst: [10, 0, 0, 2],
            },
            ip_proto: 6,
            src_port: 1111,
            dst_port: 443,
        };
        let h4 = super::install_flow(ifx, 100, 1, &v4, &act)
            .expect("install v4 (kernel accepts encoding)");
        let opts4 = super::query_flower_opts(&h4)
            .expect("query v4")
            .expect("v4 filter present after install");
        assert!(opts4
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::EthType(0x0800))));
        assert!(opts4
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::TcpDst(443))));
        assert!(opts4
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::Actions(a) if a.len() == 2)));
        // netdevsim can't offload flower -> honestly false (would be true on real HW).
        assert!(
            !super::flow_in_hw(&h4).expect("in_hw v4 read"),
            "netdevsim: flower is sw-only"
        );

        // --- v6 / UDP: install is accepted, filter is queryable ---
        let v6 = FlowKey {
            l3: FlowL3::V6 {
                src: [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                dst: [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            },
            ip_proto: 17,
            src_port: 2222,
            dst_port: 53,
        };
        let h6 = super::install_flow(ifx, 101, 2, &v6, &act)
            .expect("install v6 (kernel accepts encoding)");
        let opts6 = super::query_flower_opts(&h6)
            .expect("query v6")
            .expect("v6 filter present after install");
        assert!(opts6
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::EthType(0x86DD))));
        assert!(opts6
            .iter()
            .any(|o| matches!(o, TcFilterFlowerOption::UdpDst(53))));

        // --- delete removes both; second delete is tolerated (idempotent) ---
        super::delete_flow(&h4).expect("delete v4");
        super::delete_flow(&h6).expect("delete v6");
        assert!(
            !super::flow_present(&h4).expect("query v4 after delete"),
            "v4 gone after delete"
        );
        assert!(
            !super::flow_present(&h6).expect("query v6 after delete"),
            "v6 gone after delete"
        );
        super::delete_flow(&h4).expect("delete v4 again (ENOENT tolerated)");
    }

    #[test]
    #[ignore = "privileged: modprobe netdevsim (needs root); run under sudo"]
    fn ensure_clsact_is_idempotent_on_netdevsim() {
        let (ifx, _c) = super::tests_support::netdevsim_pf();
        super::ensure_clsact(ifx).expect("clsact created");
        super::ensure_clsact(ifx).expect("clsact idempotent (EEXIST tolerated)");
    }

    #[test]
    #[ignore = "opens a NETLINK_ROUTE socket; run under sudo"]
    fn netlink_socket_roundtrips_a_qdisc_dump() {
        use netlink_packet_route::{tc::TcMessage, RouteNetlinkMessage};
        let msg = RouteNetlinkMessage::GetQueueDiscipline(TcMessage::default());
        let out =
            super::nl::request_dump(msg, netlink_packet_core::NLM_F_DUMP).expect("qdisc dump");
        assert!(!out.is_empty(), "kernel returned at least one qdisc");
    }
}
