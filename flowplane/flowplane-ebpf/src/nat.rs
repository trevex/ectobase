//! The out-lined `NAT_OWNERS6` lookup. Network SNAT lives in `flowplane_core::nat`, shared with
//! the native sim and the `BPF_PROG_TEST_RUN` anchors.

use aya_ebpf::maps::lpm_trie::Key;
use flowplane_common::{NatOwner, NatOwnerKey6, NAT_OWNER_ADDR_BITS6};

use crate::maps::NAT_OWNERS6;

/// `NAT_OWNERS6` longest-prefix lookup. `#[inline(never)]`: packet-free, so out-lining cannot lose
/// packet-pointer provenance, and it keeps the 22-byte trie key off `process_uplink_v6`'s frame,
/// which sits close to the verifier's combined-stack limit.
#[inline(never)]
pub fn nat_owner6(nat_ip: &[u8; 16], port: u16) -> Option<NatOwner> {
    let key = Key::new(
        NAT_OWNER_ADDR_BITS6 + 16,
        NatOwnerKey6 {
            nat_ip6: *nat_ip,
            port: port.to_be_bytes(),
        },
    );
    NAT_OWNERS6.get(&key).copied()
}
