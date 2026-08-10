//! DE-RISK GATE for the DPDK `TapBackend` datapath slice: prove that DPDK's `net_af_xdp`
//! PMD can bind a **tap kernel netdev** (`fptaphp0`) and that a frame written to the tap's
//! **char-device fd** (`/dev/net/tun` after `TUNSETIFF`) round-trips through af_xdp in BOTH
//! directions:
//!   * fd write (guest egress) -> af_xdp RX on the netdev, and
//!   * af_xdp TX on the netdev  -> fd read (guest ingress).
//!
//! af_xdp-on-veth is proven on this host; af_xdp-on-tap (copy mode) is very likely but was
//! UNPROVEN. This is the go/no-go gate for the whole TapBackend model: if af_xdp cannot bind the
//! tap netdev (Port::configure fails) or a frame does not cross the fd<->netdev seam, the model is
//! invalid and the feature STOPs here.
//!
//! Model: a tap = one kernel netdev (`fptaphp0`) + one char-device fd. af_xdp binds the NETDEV;
//! whoever holds the fd is the "application" (= qemu, or here this test). Traffic written to the fd
//! egresses the netdev -> af_xdp rx's it; af_xdp tx on the netdev -> readable on the fd.
//!
//! SKIPS (passes) when unprivileged: tap creation + af_xdp bind need root/CAP_NET_ADMIN. If EAL
//! init or Port::configure fails on a root host, that is a REAL blocker for the feature and PANICs
//! (it is the whole point of the gate) rather than masking it as a skip. EAL runs `--no-huge` with
//! a unique `--file-prefix` (EAL is once-per-process; keep this in its OWN `--test` binary).
//!
//! Run: `sudo -E $(command -v cargo) test -p nfkit --test afxdp_tap -- --test-threads=1 --nocapture`
use nfkit::{Eal, Mempool, Port};
use std::process::Command;

/// The tap netdev this test creates + af_xdp-binds. Unique to avoid colliding with other harnesses.
const TAP: &str = "fptaphp0";

// tuntap ioctl constants (Linux ABI, arch-stable on x86_64/aarch64 — see <linux/if_tun.h>).
const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// Run an `ip` command, returning whether it succeeded (stderr surfaced on failure).
fn ip(args: &[&str]) -> bool {
    match Command::new("ip").args(args).output() {
        Ok(o) => {
            if !o.status.success() {
                eprintln!(
                    "  ip {:?} failed: {}",
                    args,
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            o.status.success()
        }
        Err(e) => {
            eprintln!("  spawn ip {args:?} failed: {e}");
            false
        }
    }
}

/// Idempotently delete the persistent tap netdev (ignores "not found").
fn del_tap() {
    let _ = ip(&["tuntap", "del", "dev", TAP, "mode", "tap"]);
}

/// RAII cleanup: delete the tap on drop, even if the test panics mid-way.
struct TapGuard;
impl Drop for TapGuard {
    fn drop(&mut self) {
        del_tap();
    }
}

/// Open `/dev/net/tun` and attach the fd to the EXISTING persistent tap `TAP` via `TUNSETIFF`
/// (`IFF_TAP | IFF_NO_PI` — no 4-byte packet-info prefix, so what we read/write is the raw frame).
/// Returns the guest-facing fd. Panics with a clear message on failure.
fn open_tap_fd() -> libc::c_int {
    // SAFETY: opening a device node with a NUL-terminated path; O_RDWR is valid for /dev/net/tun.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    assert!(fd >= 0, "open(/dev/net/tun) failed: {}", errno());

    // SAFETY: ifreq is a plain C struct; zero-init then fill name + flags.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name = TAP.as_bytes();
    assert!(name.len() < ifr.ifr_name.len(), "tap name too long");
    for (dst, &b) in ifr.ifr_name.iter_mut().zip(name.iter()) {
        *dst = b as libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;

    // SAFETY: fd is a valid /dev/net/tun fd; TUNSETIFF reads the ifreq we just built. Attaches the
    // fd to the existing persistent tap (name matches) rather than creating a new one.
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF as _, &ifr) };
    if rc != 0 {
        let e = errno();
        // SAFETY: closing our own fd.
        unsafe { libc::close(fd) };
        panic!("ioctl(TUNSETIFF, {TAP}) failed: rc={rc} {e}");
    }
    fd
}

fn errno() -> String {
    // SAFETY: __errno_location returns a valid pointer to the thread-local errno.
    let e = unsafe { *libc::__errno_location() };
    format!("(errno={e})")
}

/// Set an fd non-blocking so a `read` on an empty tap returns EAGAIN instead of hanging.
fn set_nonblocking(fd: libc::c_int) {
    // SAFETY: fd is valid; F_GETFL/F_SETFL take/return the flag word.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        assert!(flags >= 0, "fcntl(F_GETFL) failed {}", errno());
        let rc = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        assert!(rc == 0, "fcntl(F_SETFL, O_NONBLOCK) failed {}", errno());
    }
}

/// Build a ~64B Ethernet frame with `payload_marker` copied into the start of the payload so a
/// received/read frame can be recognized. `[dst mac 6][src mac 6][0x08,0x00][payload...]`.
fn make_frame(dst: [u8; 6], src: [u8; 6], payload_marker: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4 (arbitrary; we don't parse it)
    f.extend_from_slice(payload_marker);
    // Pad to 64B so it's a plausible minimum-size frame.
    while f.len() < 64 {
        f.push(0);
    }
    f
}

#[test]
fn afxdp_binds_tap_netdev_and_fd_roundtrips() {
    // ── privilege gate ──────────────────────────────────────────────────────────
    // SAFETY: geteuid is always safe (no args, reads the process's effective uid).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SKIP afxdp_binds_tap_netdev_and_fd_roundtrips: not root (needs CAP_NET_ADMIN)");
        return;
    }

    // ── create a PERSISTENT tap netdev (before EAL init) ─────────────────────────
    // The guard deletes it on any exit path (success, panic, early return).
    let _guard = TapGuard;
    del_tap(); // clear any stale tap first
    if !ip(&["tuntap", "add", "dev", TAP, "mode", "tap"]) {
        // add failing is almost certainly a CAP_NET_ADMIN issue — treat like unprivileged skip.
        eprintln!(
            "SKIP afxdp_binds_tap_netdev_and_fd_roundtrips: could not create tap (CAP_NET_ADMIN?)"
        );
        return;
    }
    assert!(ip(&["link", "set", TAP, "up"]), "failed to bring {TAP} up");

    // ── open the guest-facing char-device fd, attached to the persistent tap ──────
    let fd = open_tap_fd();
    struct FdGuard(libc::c_int);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            // SAFETY: closing our own fd.
            unsafe { libc::close(self.0) };
        }
    }
    let _fd_guard = FdGuard(fd);
    set_nonblocking(fd);

    // ── EAL init with the af_xdp vdev bound to the TAP netdev ─────────────────────
    // `--no-huge -m 512` avoids hugepage reservation; unique `--file-prefix` isolates this EAL.
    let vdev = format!("net_af_xdp0,iface={TAP},start_queue=0,queue_count=1");
    let eal = Eal::init([
        "fp-afxdp-tap",
        "-l",
        "0-1",
        "--no-huge",
        "-m",
        "512",
        "--vdev",
        &vdev,
        "--file-prefix",
        "fp_afxdp_tap",
    ]);
    let eal = match eal {
        Ok(e) => e,
        Err(e) => panic!(
            "EAL init with an af_xdp vdev bound to a tap netdev FAILED: {e}. \
             This would invalidate the TapBackend model — GATE BLOCKED (EAL init)."
        ),
    };
    assert!(
        eal.port_count() >= 1,
        "af_xdp vdev on tap probed no ethdev port — GATE BLOCKED (probe)"
    );

    // ── configure the af_xdp port (this is the bind) ─────────────────────────────
    let pool = Mempool::new("afxdp_tap_pool", 8191, 250, 0).expect("mempool create");
    let port = match Port::configure(0, 1, &pool) {
        Ok(p) => p,
        Err(e) => panic!(
            "Port::configure on the tap-bound af_xdp port FAILED: {e}. \
             af_xdp cannot bind the tap netdev — GATE BLOCKED (bind/configure)."
        ),
    };
    assert!(
        port.n_queues() >= 1,
        "tap-bound af_xdp port configured with no queues — GATE BLOCKED (configure)"
    );
    eprintln!(
        "OK: af_xdp bound tap netdev {TAP} -> ethdev port 0 with {} queue(s)",
        port.n_queues()
    );
    let (mut rxq, mut txq) = port.queue(0);

    // ── DIRECTION 1: guest -> pool (fd write -> af_xdp rx) ────────────────────────
    // Write the frame several times: af_xdp copy-mode on tap/veth drops warmup frames, so inject
    // repeatedly and accept the first that arrives byte-exact.
    let g2p = make_frame([0xff; 6], [0x02; 6], b"GUEST->POOL-marker");
    let mut rx_ok = false;
    'rx: for round in 0..40 {
        // Re-inject on every round to keep frames flowing during the copy-mode warmup.
        for _ in 0..8 {
            // SAFETY: writing g2p.len() bytes from a valid slice to our tap fd.
            let n = unsafe { libc::write(fd, g2p.as_ptr().cast(), g2p.len()) };
            assert!(n >= 0, "write(tap fd) failed {}", errno());
        }
        // Poll rx a few times per round.
        for _ in 0..25 {
            let mut burst = nfkit::MbufBurst::new();
            let got = rxq.rx(&mut burst);
            for m in burst.iter().take(got) {
                let data = m.data();
                // The NIC/af_xdp may pad to 60B; compare the meaningful prefix (our full 64B frame).
                if data.len() >= g2p.len() && data[..g2p.len()] == g2p[..] {
                    rx_ok = true;
                    eprintln!(
                        "OK: DIRECTION 1 (fd write -> af_xdp rx): received {}B mbuf matching the \
                         written {}B frame (round {round})",
                        data.len(),
                        g2p.len()
                    );
                    break 'rx;
                }
            }
            // brief backoff between polls (~1ms) — bounded total ~a few seconds.
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    assert!(
        rx_ok,
        "GATE BLOCKED (rx): no fd-written frame ever appeared on af_xdp rx after many injects — \
         the fd->netdev->af_xdp path does not work for a tap on this host."
    );

    // ── DIRECTION 2: pool -> guest (af_xdp tx -> fd read) ─────────────────────────
    let p2g = make_frame([0x0a; 6], [0x0b; 6], b"POOL->GUEST-marker");
    let mut tx_ok = false;
    'tx: for round in 0..40 {
        // (Re)transmit via af_xdp each round; copy-mode may drop warmup frames.
        {
            let mut m = pool.alloc().expect("alloc mbuf from pool");
            let dst = m
                .append(p2g.len() as u16)
                .expect("append into mbuf tailroom");
            dst.copy_from_slice(&p2g);
            let mut burst = nfkit::MbufBurst::new();
            burst.push(m);
            let sent = txq.tx(&mut burst);
            assert!(sent >= 1 || round > 0, "first af_xdp tx sent nothing");
            // Any unsent mbuf drops here (freed back to the pool).
        }
        // Drain the fd looking for our frame.
        for _ in 0..25 {
            let mut buf = [0u8; 2048];
            // SAFETY: reading into a valid, sized buffer from our non-blocking tap fd.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                let got = &buf[..n as usize];
                if got.len() >= p2g.len() && got[..p2g.len()] == p2g[..] {
                    tx_ok = true;
                    eprintln!(
                        "OK: DIRECTION 2 (af_xdp tx -> fd read): read {}B from the tap fd matching \
                         the tx'd {}B frame (round {round})",
                        got.len(),
                        p2g.len()
                    );
                    break 'tx;
                }
                // Not ours (e.g. kernel-generated noise); keep draining.
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    assert!(
        tx_ok,
        "GATE BLOCKED (tx): af_xdp-tx'd frame never became readable on the tap fd — \
         the af_xdp->netdev->fd path does not work for a tap on this host."
    );

    eprintln!(
        "GATE PASSED: af_xdp binds a tap netdev and frames round-trip fd<->af_xdp both ways."
    );

    // ── teardown: drop the Port (stop+close) BEFORE deleting the netdev ──────────
    drop(port);
    drop(pool);
    drop(eal);
    // _fd_guard closes fd, _guard deletes the tap.
}
