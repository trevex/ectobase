//! Deterministic device-name / MAC / overlay-address derivation for interface attach.
//!
//! These are the pure, side-effect-free helpers `AttachState::attach`/`detach` lean on to turn a
//! CNI-supplied `interface_id` (and the requested IPs / MAC string) into concrete kernel device
//! names and addresses: the host-veth / tap / KubeVirt-tap names (IFNAMSIZ-bounded, hashed when the
//! id is too long), the deterministic guest MAC, the sanitized guest link name, and the MAC/IP
//! parsers. Determinism matters for correctness — a detach+re-attach of the SAME id must re-derive
//! the SAME names + MAC so the re-created device agrees with the `learned_macs` cache and the maps
//! (see `mac_for`). Split out of `mod.rs` (review P1.2); the bulk of attach's unit tests live here.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Context};

use super::AttachState;

impl AttachState {
    /// Host-side veth name for an interface. Kept short and stable so detach can delete it and so
    /// the datapath tap is discoverable. Kernel IFNAMSIZ caps names at 15 chars, and
    /// `flowplane_device::create_veth_pair` derives the temporary peer name as `<host>p` (one char
    /// longer) — so the host name itself must be <= 14 chars for the pair to create. Longer ids are
    /// hashed to a fixed 13-char name.
    pub(super) fn host_veth_name(interface_id: &str) -> String {
        // "veth-<id>" when it (plus the +1 peer suffix) fits; otherwise a stable short hash.
        let candidate = format!("veth-{interface_id}");
        if candidate.len() <= 14 {
            candidate
        } else {
            let mut h: u32 = 2166136261;
            for b in interface_id.as_bytes() {
                h = (h ^ *b as u32).wrapping_mul(16777619);
            }
            format!("veth-{h:08x}")
        }
    }

    /// Guest-side (in-netns) device name for a veth interface. The `interface_id` the CNI passes is
    /// `<pod-uid>/<cni-ifname>` (e.g. `3889a54a-.../net1`) — a fine map key but NOT a valid Linux
    /// device name (it contains `/` and exceeds IFNAMSIZ), so using it verbatim as the guest link
    /// name made `ip link set … name <id>` fail ("rename guest veth") for every real CNI-driven pod.
    /// We derive a valid name from the id: the component after the last `/` (the CNI's own ifname,
    /// e.g. `net1`) when it is a valid <=15-char device name, else a stable FNV hash (`g-<hash>`).
    /// The map key + the response `ifname` stay the full `interface_id`; only the actual link name is
    /// sanitized. gRPC callers that pass a clean id (`nic-a`) are unaffected (the whole id is valid).
    pub(super) fn guest_ifname(interface_id: &str) -> String {
        let last = interface_id.rsplit('/').next().unwrap_or(interface_id);
        if is_valid_ifname(last) {
            last.to_string()
        } else if is_valid_ifname(interface_id) {
            interface_id.to_string()
        } else {
            let mut h: u32 = 2166136261;
            for b in interface_id.as_bytes() {
                h = (h ^ *b as u32).wrapping_mul(16777619);
            }
            format!("g-{h:08x}")
        }
    }

    /// Root-netns tap device name for an interface (the tap analogue of `host_veth_name`). A tap is a
    /// single device with no `<host>p` peer suffix, so it may use the full IFNAMSIZ (15); longer ids
    /// are hashed to a stable short name. qemu is pointed at this name (or handed its fd).
    pub(super) fn tap_name(interface_id: &str) -> String {
        let candidate = format!("tap-{interface_id}");
        if candidate.len() <= 15 {
            candidate
        } else {
            let mut h: u32 = 2166136261;
            for b in interface_id.as_bytes() {
                h = (h ^ *b as u32).wrapping_mul(16777619);
            }
            format!("tap-{h:08x}")
        }
    }

    /// The tap device name KubeVirt's `domainAttachmentType: tap` derives for a SECONDARY-network
    /// binding: `GenerateTapDeviceName` returns `"tap" + podInterfaceName[3:]` (strip the 3-char
    /// `pod`/`net` prefix, prepend `tap`), e.g. `pod9404eea3257` -> `tap9404eea3257`. virt-launcher
    /// looks up THIS exact name in the launcher pod netns and points the domain `<target dev=…>` at it
    /// (`managed='no'`), so the pod-netns tap MUST carry it. `tap0` — the PRIMARY-only name — is never
    /// looked up for a secondary network and was the cause of the "Link not found" boot failure. The
    /// pod link (`pod<hash>`, ≤14 chars) always has a 3+ char prefix; guard the tiny-name case anyway.
    pub(super) fn kubevirt_secondary_tap_name(pod_link: &str) -> String {
        if pod_link.len() > 3 {
            format!("tap{}", &pod_link[3..])
        } else {
            format!("tap-{pod_link}")
        }
    }

    /// A locally-administered unicast MAC (02:xx:...) derived DETERMINISTICALLY from the
    /// interface_id (FNV-1a, same idiom as `host_veth_name`). Determinism is a correctness
    /// requirement, not a nicety: on detach the datapath's current guest MAC is cached in
    /// `learned_macs` (control.rs) so a detach+re-attach of the SAME interface preserves it; a
    /// per-attach counter would hand the re-created veth a NEW MAC while the maps kept the cached
    /// OLD one, so `uplink_rx` would deliver returns to the stale MAC and the guest would drop them.
    /// Deriving from the id makes the re-attached veth, the cache, and the maps all agree.
    pub(super) fn mac_for(interface_id: &str) -> [u8; 6] {
        let mut h: u32 = 2166136261;
        for b in interface_id.as_bytes() {
            h = (h ^ *b as u32).wrapping_mul(16777619);
        }
        let s = h.to_be_bytes();
        [0x02, 0x00, s[0], s[1], s[2], s[3]]
    }
}

/// True iff `s` is a usable Linux network device name: non-empty, at most IFNAMSIZ-1 (15) bytes, and
/// free of `/`, whitespace, and the `.`/`..` special names (which `ip link set … name` rejects). Used
/// by `guest_ifname` to decide whether the CNI-supplied name can be used verbatim.
fn is_valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s != "."
        && s != ".."
        && !s
            .bytes()
            .any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace())
}

/// First valid IPv4 address in `requested_ips`, as raw octets.  Returns `None` if none is present
/// (caller should `.context("requires at least one IPv4")`).
pub(super) fn primary_ipv4(requested_ips: &[String]) -> Option<[u8; 4]> {
    requested_ips
        .iter()
        .find_map(|s| s.parse::<Ipv4Addr>().ok())
        .map(|a| a.octets())
}

/// First valid IPv6 address in `requested_ips`, as raw octets.  Returns `[0u8; 16]` when none is
/// present — dual-stack is optional, so an IPv4-only guest is valid.
pub(super) fn primary_ipv6(requested_ips: &[String]) -> [u8; 16] {
    requested_ips
        .iter()
        .find_map(|s| s.parse::<Ipv6Addr>().ok())
        .map(|a| a.octets())
        .unwrap_or([0u8; 16])
}

/// Parse `"aa:bb:cc:dd:ee:ff"` into 6 bytes.
pub(super) fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0usize;
    for (i, part) in s.split(':').enumerate() {
        if i >= 6 {
            bail!("too many octets in MAC {s}");
        }
        out[i] = u8::from_str_radix(part, 16).with_context(|| format!("bad MAC octet {part}"))?;
        n += 1;
    }
    if n != 6 {
        bail!("MAC {s} must have 6 octets");
    }
    Ok(out)
}

pub(super) fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_veth_name_short_passthrough() {
        assert_eq!(AttachState::host_veth_name("t0"), "veth-t0");
    }

    #[test]
    fn is_valid_ifname_accepts_and_rejects() {
        assert!(is_valid_ifname("net1"));
        assert!(is_valid_ifname("eth0"));
        assert!(is_valid_ifname("nic-a"));
        assert!(is_valid_ifname("012345678901234")); // 15 bytes
        assert!(!is_valid_ifname("")); // empty
        assert!(!is_valid_ifname("0123456789012345")); // 16 bytes > IFNAMSIZ-1
        assert!(!is_valid_ifname("uid/net1")); // contains '/'
        assert!(!is_valid_ifname("a:b")); // contains ':'
        assert!(!is_valid_ifname("a b")); // whitespace
        assert!(!is_valid_ifname(".")); // special
        assert!(!is_valid_ifname("..")); // special
    }

    #[test]
    fn guest_ifname_extracts_cni_ifname_from_uid_slash_ifname() {
        // The CNI passes `<pod-uid>/<cni-ifname>` — the guest link must be the valid trailing name.
        assert_eq!(
            AttachState::guest_ifname("3889a54a-a2a8-4bb9-a5c0-6e0a1c24f4a9/net1"),
            "net1"
        );
        assert_eq!(
            AttachState::guest_ifname("3889a54a-a2a8-4bb9-a5c0-6e0a1c24f4a9/eth0"),
            "eth0"
        );
    }

    #[test]
    fn guest_ifname_passes_through_clean_ids() {
        // A gRPC-driven caller with a clean, valid id keeps it verbatim (no `/`, <=15 chars).
        assert_eq!(AttachState::guest_ifname("nic-a"), "nic-a");
        assert_eq!(AttachState::guest_ifname("t0"), "t0");
    }

    #[test]
    fn guest_ifname_hashes_when_trailing_component_is_invalid() {
        // A trailing component that is itself too long / invalid falls back to a stable hash.
        let long_tail = "uid/this-name-is-way-too-long-for-ifnamsiz";
        let n = AttachState::guest_ifname(long_tail);
        assert!(is_valid_ifname(&n), "{n} must be a valid device name");
        assert!(n.starts_with("g-"));
        // Deterministic (same id -> same name), so detach/re-attach agree.
        assert_eq!(n, AttachState::guest_ifname(long_tail));
    }

    #[test]
    fn host_veth_name_long_is_hashed_and_fits() {
        let n = AttachState::host_veth_name("a-very-long-interface-id-way-over-ifnamsiz");
        // The host name PLUS the +1 peer suffix (`<host>p`) must fit IFNAMSIZ (15).
        assert!(
            n.len() <= 14,
            "{n} leaves no room for the +1 veth peer suffix"
        );
        assert!(n.starts_with("veth-"));
    }

    #[test]
    fn host_veth_name_15char_boundary_is_hashed() {
        // "blue-guest" -> "veth-blue-guest" is exactly 15 chars; verbatim it would make a 16-char
        // peer ("veth-blue-guestp") that exceeds IFNAMSIZ, so it must be hashed instead.
        let n = AttachState::host_veth_name("blue-guest");
        assert_eq!(
            n.len(),
            13,
            "{n} should be the 13-char hashed form, not verbatim"
        );
        assert!(n.starts_with("veth-"));
    }

    /// The pod-tap tap name MUST match KubeVirt's `GenerateTapDeviceName` for a secondary network:
    /// "tap" + podInterfaceName[3:] (strip the `pod`/`net` prefix). virt-launcher looks this up by
    /// name; a mismatch (e.g. the old literal "tap0") is the "Link not found" boot failure.
    #[test]
    fn kubevirt_secondary_tap_name_matches_virtlauncher() {
        // pod<hash> pod link -> tap<hash> (KubeVirt strips "pod", prepends "tap").
        assert_eq!(
            AttachState::kubevirt_secondary_tap_name("pod9404eea3257"),
            "tap9404eea3257"
        );
        // Ordinal net<N> pod link -> tap<N> (same strip-3 rule).
        assert_eq!(AttachState::kubevirt_secondary_tap_name("net2"), "tap2");
        // Fits IFNAMSIZ (pod<hash> is 14 chars -> tap<hash> is 14).
        assert!(AttachState::kubevirt_secondary_tap_name("pod9404eea3257").len() <= 15);
        // Never the primary-only "tap0", which KubeVirt does not look up on a secondary network.
        assert_ne!(
            AttachState::kubevirt_secondary_tap_name("pod9404eea3257"),
            "tap0"
        );
    }

    #[test]
    fn tap_name_short_passthrough_and_distinct_from_veth() {
        assert_eq!(AttachState::tap_name("t0"), "tap-t0");
        // A tap and a veth for the same id must never collide (both live in the root netns).
        assert_ne!(
            AttachState::tap_name("t0"),
            AttachState::host_veth_name("t0")
        );
    }

    #[test]
    fn tap_name_long_is_hashed_and_fits_ifnamsiz() {
        let n = AttachState::tap_name("a-very-long-interface-id-way-over-ifnamsiz");
        // A tap has no +1 peer suffix, so the full IFNAMSIZ (15) is available.
        assert!(n.len() <= 15, "{n} exceeds IFNAMSIZ");
        assert!(n.starts_with("tap-"));
    }

    #[test]
    fn parse_mac_roundtrips() {
        assert_eq!(parse_mac("02:00:00:00:00:0a").unwrap(), [2, 0, 0, 0, 0, 10]);
        assert_eq!(fmt_mac([2, 0, 0, 0, 0, 10]), "02:00:00:00:00:0a");
    }

    #[test]
    fn mac_for_is_deterministic_laa_unicast_and_distinct() {
        let a1 = AttachState::mac_for("natpod");
        let a2 = AttachState::mac_for("natpod");
        // Determinism is the whole point: a detach+re-attach of the SAME id must reuse the SAME MAC
        // so the re-created veth agrees with the learned_macs cache + the datapath maps (else
        // uplink_rx delivers returns to a stale MAC and the guest silently drops them).
        assert_eq!(
            a1, a2,
            "mac_for must be stable across re-attach of the same interface_id"
        );
        // Locally-administered (bit 1 set) unicast (bit 0 clear).
        assert_eq!(
            a1[0] & 0x03,
            0x02,
            "must be a locally-administered unicast MAC"
        );
        // Different ids get different MACs (no aliasing between endpoints on a node).
        assert_ne!(a1, AttachState::mac_for("web"));
        assert_ne!(a1, AttachState::mac_for("natpod2"));
    }

    #[test]
    fn parse_mac_rejects_bad() {
        assert!(parse_mac("zz:00:00:00:00:00").is_err());
        assert!(parse_mac("02:00:00").is_err());
    }

    // ── primary_ipv4 / primary_ipv6 ──────────────────────────────────────────

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn requested_ips_v4_only() {
        let ips = strs(&["10.1.0.7"]);
        assert_eq!(primary_ipv4(&ips), Some([10, 1, 0, 7]));
        assert_eq!(primary_ipv6(&ips), [0u8; 16]);
    }

    #[test]
    fn requested_ips_dual_stack() {
        let ips = strs(&["10.1.0.7", "2001:db8:1::7"]);
        assert_eq!(primary_ipv4(&ips), Some([10, 1, 0, 7]));
        // 2001:0db8:0001:0000:0000:0000:0000:0007
        assert_eq!(
            primary_ipv6(&ips),
            [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x07
            ]
        );
    }

    #[test]
    fn requested_ips_v6_only() {
        let ips = strs(&["2001:db8::1"]);
        assert_eq!(primary_ipv4(&ips), None);
        // 2001:0db8:0000:0000:0000:0000:0000:0001
        assert_eq!(
            primary_ipv6(&ips),
            [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01
            ]
        );
    }

    #[test]
    fn requested_ips_empty() {
        let ips: Vec<String> = vec![];
        assert_eq!(primary_ipv4(&ips), None);
        assert_eq!(primary_ipv6(&ips), [0u8; 16]);
    }

    #[test]
    fn requested_ips_malformed_skipped_first_valid_wins() {
        // Garbage entries are skipped; the first parseable address of each family wins.
        let ips = strs(&["garbage", "10.1.0.7", "::not-ip", "192.168.1.1"]);
        assert_eq!(primary_ipv4(&ips), Some([10, 1, 0, 7]));
        assert_eq!(primary_ipv6(&ips), [0u8; 16]);
    }

    #[test]
    fn requested_ips_multiple_v6_first_wins() {
        // When multiple valid IPv6 addresses are present, the FIRST one is picked (mirrors v4
        // "first wins" convention — `find_map` stops at the first `Ok`).
        let ips = strs(&["fd00::1", "2001:db8::2"]);
        // fd00::1 = fd00:0000:...:0001
        assert_eq!(
            primary_ipv6(&ips),
            [
                0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01
            ]
        );
        // Ensure the second address is NOT returned.
        assert_ne!(
            primary_ipv6(&ips),
            [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02
            ]
        );
    }
}
