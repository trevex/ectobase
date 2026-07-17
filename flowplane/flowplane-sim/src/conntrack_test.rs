use crate::firewall_test::tcp_v4; // pub(crate) helper
use crate::{MemMaps, VecPkt};
use flowplane_core::conntrack::{ct_create_default, ct_key};
use flowplane_core::maps::Maps;

#[test]
fn conntrack_entry_created_for_new_flow() {
    let vni = 100u32;
    let mut m = MemMaps::default();
    let pkt = VecPkt::from_bytes(&tcp_v4([10, 0, 0, 5], [10, 0, 0, 10], 5000, 443));
    let key = ct_key(&pkt, 0, vni).expect("ct key");
    assert!(m.conntrack_get(&key).is_none());
    // `now: u64` is 0 in the native path (no bpf_ktime_get_ns).
    ct_create_default(&pkt, &mut m, 0, vni, 0);
    assert!(m.conntrack_get(&key).is_some(), "forward CT entry inserted");
}
