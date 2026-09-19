use aya_ebpf::maps::lpm_trie::Key;
use flowplane_common::{NatOwner, NatOwnerKey6, NAT_OWNER_ADDR_BITS6};

use crate::maps::NAT_OWNERS6;

// The egress network-SNAT rewriter now lives in `flowplane_core::nat::snat_egress` — the SINGLE
// source shared by the eBPF `guest_tx` path (called from `egress::forward_decision_v4` over a
// `RawPkt`/`GlobalMaps` seam), the native `SimNode::guest_tx`, and the `BPF_PROG_TEST_RUN` byte-parity
// anchor. The former eBPF-local `nat_snat_egress` copy was deleted so there is exactly one impl.

/// `NAT_OWNERS6` longest-prefix lookup. `#[inline(never)]`: packet-free (an 18-byte key), so
/// out-lining cannot lose packet-pointer provenance, and it keeps the key and value off
/// `process_uplink_v6`'s frame, which sits close to the verifier's combined-stack limit.
#[inline(never)]
pub fn nat_owner6(nat_ip: [u8; 16], port: u16) -> Option<NatOwner> {
    let key = Key::new(
        NAT_OWNER_ADDR_BITS6 + 16,
        NatOwnerKey6 {
            nat_ip6: nat_ip,
            port: port.to_be_bytes(),
        },
    );
    NAT_OWNERS6.get(&key).copied()
}
