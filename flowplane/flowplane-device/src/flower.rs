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

use anyhow::{anyhow, bail, Context, Result};
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST,
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
        let mut socket =
            Socket::new(NETLINK_ROUTE).context("open NETLINK_ROUTE socket")?;
        socket.bind_auto().context("bind_auto NETLINK_ROUTE socket")?;
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
    pub fn request(
        msg: RouteNetlinkMessage,
        extra_flags: u16,
        tolerate: &[i32],
    ) -> Result<()> {
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
                    Err(anyhow!("netlink request failed: {} (errno {})", err.to_io(), code))
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
        let out = super::nl::request_dump(msg, netlink_packet_core::NLM_F_DUMP)
            .expect("qdisc dump");
        assert!(!out.is_empty(), "kernel returned at least one qdisc");
    }
}
