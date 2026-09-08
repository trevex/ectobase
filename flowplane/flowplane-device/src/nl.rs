// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

//! Sync rtnetlink request/ACK + dump primitives. Everything here opens its own short-lived
//! `NETLINK_ROUTE` socket per call — fine for the low-frequency control-plane installs this serves.
//!
//! Generic netlink plumbing with no flower/tc specifics; the flower filter installer
//! ([`crate::flower`]) is the current caller.

use anyhow::{anyhow, bail, Context, Result};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

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
