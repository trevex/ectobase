//! Persistent tap-device lifecycle for the DPDK af_xdp guest-port pool (VM backend). The tap's
//! KERNEL NETDEV is af_xdp-bound as a pool port; its char-device FD (`open_tap_fd`) is the
//! guest-facing side handed to qemu. Mirrors `veth.rs`'s ip-command style; reuses run/ifindex_of/
//! mac_of/link_exists. A persistent tap SURVIVES an fd close AND process exit (unlike a veth pair,
//! which dies with its peer) — the VF-like property TapBackend relies on.
use crate::veth::{fmt_mac, ifindex_of, run, DeviceInfo};
use anyhow::{bail, Context, Result};
use std::os::fd::{FromRawFd, OwnedFd};

/// Create a PERSISTENT tap netdev (survives fd close + process exit): `ip tuntap add ... mode tap`
/// → mac/mtu/up. Idempotent (deletes a stale same-named tap first). Returns resolved facts.
pub fn create_persistent_tap(name: &str, mac: [u8; 6], mtu: u32) -> Result<DeviceInfo> {
    delete_tap(name);
    run(&["ip", "tuntap", "add", "dev", name, "mode", "tap"]).context("ip tuntap add")?;
    let macs = fmt_mac(mac);
    run(&["ip", "link", "set", name, "address", &macs]).context("set tap mac")?;
    run(&["ip", "link", "set", name, "mtu", &mtu.to_string()]).context("set tap mtu")?;
    run(&["ip", "link", "set", name, "up"]).context("tap up")?;
    let host_ifindex = ifindex_of(name)?;
    Ok(DeviceInfo {
        host_ifindex,
        host_name: name.to_string(),
        mac,
    })
}

/// Open the guest-facing char-device fd for an EXISTING persistent tap (`/dev/net/tun` +
/// `TUNSETIFF(name, IFF_TAP|IFF_NO_PI)`). The fd handed to qemu (the VM's NIC backend); in the
/// datapath slice the test holds it to simulate the VM.
///
/// The ifreq/ioctl sequence is lifted verbatim from the proven gate test
/// `nfkit/tests/afxdp_tap.rs` (`IFF_NO_PI` = no 4-byte packet-info prefix, so read/write is the raw
/// frame; `name` is NUL-padded into `ifr_name`, asserting it fits with room for the terminator).
pub fn open_tap_fd(name: &str) -> Result<OwnedFd> {
    // tuntap ioctl constants (Linux ABI, arch-stable on x86_64/aarch64 — see <linux/if_tun.h>).
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TAP: i16 = 0x0002;
    const IFF_NO_PI: i16 = 0x1000;

    // SAFETY: opening a device node with a NUL-terminated path; O_RDWR is valid for /dev/net/tun.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        bail!("open(/dev/net/tun) failed: {}", errno());
    }

    // SAFETY: ifreq is a plain C struct; zero-init then fill name + flags.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let nb = name.as_bytes();
    // Keep a room for the NUL terminator so the name stays C-string-valid.
    assert!(nb.len() < ifr.ifr_name.len(), "tap name too long");
    for (dst, &b) in ifr.ifr_name.iter_mut().zip(nb.iter()) {
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
        bail!("ioctl(TUNSETIFF, {name}) failed: rc={rc} {e}");
    }
    // SAFETY: fd is a valid, owned file descriptor we just successfully set up; OwnedFd takes over
    // ownership and closes it on drop.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Idempotent delete: `ip tuntap del dev <name> mode tap` (ignores "not found").
pub fn delete_tap(name: &str) {
    let _ = run(&["ip", "tuntap", "del", "dev", name, "mode", "tap"]);
}

/// Format the thread-local errno for context strings (mirrors the gate test's helper).
fn errno() -> String {
    // SAFETY: __errno_location returns a valid pointer to the thread-local errno.
    let e = unsafe { *libc::__errno_location() };
    format!("(errno={e})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::veth::{link_exists, mac_of};

    #[test]
    #[ignore = "privileged: creates a persistent tap + opens /dev/net/tun (needs CAP_NET_ADMIN); run under sudo"]
    fn tap_create_persist_open_delete_roundtrips() {
        let name = "fpdevtap0";
        let mac = [0x02, 0, 0, 0, 0x0f, 0x00];
        // Ensure a clean slate + always clean up (even on a mid-test panic).
        delete_tap(name);
        struct Guard(&'static str);
        impl Drop for Guard {
            fn drop(&mut self) {
                delete_tap(self.0);
            }
        }
        let _guard = Guard(name);

        let info = create_persistent_tap(name, mac, 1400).expect("create persistent tap");
        assert!(info.host_ifindex >= 2, "resolved a real host ifindex");
        assert_eq!(info.host_name, name);
        assert_eq!(info.mac, mac);
        assert!(link_exists(name), "tap netdev present after create");
        assert!(ifindex_of(name).is_ok(), "ifindex resolves");
        assert_eq!(mac_of(name).unwrap(), mac, "kernel netdev has the set MAC");

        // Open the guest-facing fd and write a frame-sized byte buffer — no error expected.
        let fd = open_tap_fd(name).expect("open tap fd");
        let frame = [0u8; 64];
        // SAFETY: writing frame.len() bytes from a valid slice to our tap fd.
        let n = unsafe {
            libc::write(
                std::os::fd::AsRawFd::as_raw_fd(&fd),
                frame.as_ptr().cast(),
                frame.len(),
            )
        };
        assert!(n >= 0, "write(tap fd) failed {}", errno());

        // Persistent tap SURVIVES the fd close (unlike a veth pair, which dies with its peer).
        drop(fd);
        assert!(
            link_exists(name),
            "persistent tap survives fd close (VF-like property)"
        );

        // Explicit delete removes it.
        delete_tap(name);
        assert!(!link_exists(name), "tap gone after delete_tap");
    }

    #[test]
    fn open_tap_fd_bogus_name_errs() {
        // A tap named this cannot exist. Either /dev/net/tun open fails (unprivileged) or TUNSETIFF
        // fails on the nonexistent device — either way `open_tap_fd` must return Err.
        assert!(
            open_tap_fd("fpdev-nope-xyz").is_err(),
            "opening a bogus tap must error"
        );
    }
}
