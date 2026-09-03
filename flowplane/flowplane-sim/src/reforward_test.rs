//! Sim oracle: the LB remote-backend re-forward decision (East-West DSR, no decap). Drives the REAL
//! `flowplane_core::encap::reforward` — production code, the same fn `process_uplink`'s LB-remote
//! arm calls — and asserts the emitted `TunnelEncap{vni, remote}`. Under Geneve `collect_md` the
//! kernel re-stamps the tunnel key; the datapath never rewrites outer bytes (contrast the old
//! byte-rewriting `encap::reforward`, which mutated the outer Ethernet + IPv6 src/dst in place).

use flowplane_core::encap::{reforward, TunnelEncap};

#[test]
fn reforward_emits_tunnel_encap_toward_the_backend_at_the_same_vni() {
    let vni = 100;
    let backend = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];

    assert_eq!(
        reforward(vni, &backend),
        TunnelEncap {
            vni,
            remote: backend
        },
        "reforward re-targets the SAME vni at the new backend underlay, no decap"
    );
}
