//! Interface map-programming + QoS + DHCP config (backend-agnostic core).
//!
//! Moved verbatim out of the eBPF `Control` (control/mod.rs), applying the MapWriter transform:
//! `g.ports`/`g.ifaces`/`g.meter`/`g.iface_meta`/`g.vips` map ops -> `self.w.<map>_<op>`,
//! `g.core.writer_mut().<underlay|route|route6|nat|neigh_nat>_<op>` -> `self.w.<...>`,
//! `g.core.neigh_nats`/`g.core.routes_shadow`/`g.core.routes6_shadow` -> `self.<...>`, and
//! `Self::meter_state(...)` -> the pure `meter_state(...)` free fn.
//!
//! The `create_interface`/`detach_interface` DEVICE work (name/ifindex/mac resolve, tc/XDP attach,
//! GuestLink, guest_dev devmap, links/by_id bookkeeping) stays on `Control`; only the MAP half is
//! here (`program_interface` / `purge_vni`). Values the device path resolves (tap ifindex, the
//! effective/learned guest MAC) are passed in via `IfaceParams` so no observable map-vs-device
//! write ordering changes.

use crate::{ControlCore, MapWriter};
use flowplane_common::{
    DhcpConfig, IfaceKey, IfaceMetaKey, IfaceMetaVal, IfaceValue, MeterState, NatKey, PortMeta,
    RouteValue, VipKey, IFACE_DEV_MAX,
};

/// Per-interface addressing + rate-limit parameters for `program_interface`. The agnostic subset of
/// the eBPF `Control::IfaceParams` PLUS the values the device path already resolved (`tap`,
/// `effective_mac`) and the journal identity (`interface_id`, `device`).
pub struct IfaceParams {
    pub interface_id: Vec<u8>,
    pub device: String,
    /// Tap ifindex, resolved on the device side (`crate::ifindex`).
    pub tap: u32,
    /// The MAC to program: the shadow-cached learned MAC if present, else the device MAC. Resolved
    /// on the device side (reads `Control::Inner.learned_macs`).
    pub effective_mac: [u8; 6],
    pub vni: u32,
    pub ipv4: [u8; 4],
    pub ipv6: [u8; 16],
    pub gateway_ipv4: [u8; 4],
    pub gateway_ipv6: [u8; 16],
    pub underlay_ipv6: [u8; 16],
    pub total_mbps: u64,
    pub public_mbps: u64,
}

/// Build a `MeterState` from per-lane caps in Mbit/s. Egress total is EDT-shaped: only
/// `total_bps` + the schedule cursor (`total_last_ns`, seeded 0) matter — no token bucket.
/// Public + ingress are token-bucket policers (burst = 1/8 s of rate, min 2000B). All 0 =>
/// unlimited. Single source of truth shared by program_interface, the CLI, and ConfigureQoS.
pub fn meter_state(egress_mbps: u64, public_mbps: u64, ingress_mbps: u64) -> MeterState {
    let e = egress_mbps.saturating_mul(1_000_000) / 8;
    let p = public_mbps.saturating_mul(1_000_000) / 8;
    let i = ingress_mbps.saturating_mul(1_000_000) / 8;
    MeterState {
        total_bps: e,
        total_burst: 0,
        total_tokens: 0,
        total_last_ns: 0,
        public_bps: p,
        public_burst: (p / 8).max(2000),
        public_tokens: p / 8,
        public_last_ns: 0,
        ingress_bps: i,
        ingress_burst: (i / 8).max(2000),
        ingress_tokens: i / 8,
        ingress_last_ns: 0,
    }
}

impl<W: MapWriter> ControlCore<W> {
    /// Set the guest DHCP config (MTU + DNS servers). Assembles the fixed-width `DhcpConfig` and
    /// writes it via the config-map surface.
    pub fn set_dhcp_config(
        &mut self,
        mtu: u16,
        dns4: &[[u8; 4]],
        dns6: &[[u8; 16]],
    ) -> anyhow::Result<()> {
        let mut cfg = DhcpConfig {
            mtu,
            dns4_len: dns4.len().min(flowplane_common::DHCP_MAX_DNS) as u8,
            dns6_len: dns6.len().min(flowplane_common::DHCP_MAX_DNS) as u8,
            dns4: [[0; 4]; flowplane_common::DHCP_MAX_DNS],
            dns6: [[0; 16]; flowplane_common::DHCP_MAX_DNS],
        };
        for (i, a) in dns4.iter().take(flowplane_common::DHCP_MAX_DNS).enumerate() {
            cfg.dns4[i] = *a;
        }
        for (i, a) in dns6.iter().take(flowplane_common::DHCP_MAX_DNS).enumerate() {
            cfg.dns6[i] = *a;
        }
        self.w.dhcp_config_set(&cfg)
    }

    /// Set (or clear) the per-interface QoS meter. All-zero caps clear the METER entry (pass);
    /// otherwise program the three-lane `MeterState`. Resolves the tap ifindex through the agnostic
    /// interface metadata (`ifaces_meta[id].ifindex`, formerly `Inner.by_ifindex[id]`).
    pub fn set_qos(
        &mut self,
        interface_id: &[u8],
        egress_mbps: u64,
        public_mbps: u64,
        ingress_mbps: u64,
    ) -> anyhow::Result<()> {
        let tap = self
            .ifaces_meta
            .get(interface_id)
            .map(|m| m.ifindex)
            .ok_or_else(|| anyhow::anyhow!("NO_VM: unknown interface"))?;
        if egress_mbps == 0 && public_mbps == 0 && ingress_mbps == 0 {
            let _ = self.w.meter_remove(&tap);
            Ok(())
        } else {
            let state = meter_state(egress_mbps, public_mbps, ingress_mbps);
            self.w.meter_upsert(tap, state)
        }
    }

    /// Program PORT_META / INTERFACES / UNDERLAY / METER / local self-route(s) + the IFACE_META
    /// restart journal for one interface. The device-side attach + bookkeeping stays on `Control`.
    pub fn program_interface(&mut self, params: IfaceParams) -> anyhow::Result<()> {
        let IfaceParams {
            interface_id,
            device,
            tap,
            effective_mac,
            vni,
            ipv4,
            ipv6,
            gateway_ipv4,
            gateway_ipv6,
            underlay_ipv6,
            total_mbps,
            public_mbps,
        } = params;
        self.w.ports_upsert(
            tap,
            PortMeta {
                vni,
                guest_ipv4: ipv4,
                gateway_ipv4,
                guest_mac: effective_mac,
                _pad: [0; 2],
                underlay_ipv6,
                gateway_ipv6,
                guest_ipv6: ipv6,
            },
        )?;
        self.w.ifaces_upsert(
            IfaceKey::new(vni, ipv4),
            IfaceValue {
                tap_ifindex: tap,
                is_local: 1,
                underlay_ipv6,
                guest_mac: effective_mac,
                _pad: [0; 2],
            },
        )?;
        self.w.underlay_upsert(
            underlay_ipv6,
            flowplane_common::UnderlayValue {
                vni,
                tap_ifindex: tap,
                guest_mac: effective_mac,
                _pad: [0; 2],
            },
        )?;
        // Local self-route: a same-host guest reaches this interface by its overlay IP. Program a
        // /32 (and /128 when dual-stack) route to this interface's OWN underlay so tc_guest_tx's
        // LPM resolves a local destination to a local underlay, and the local fast path delivers it
        // without a wire round-trip. These are NOT added to routes_shadow (not user-visible routes).
        self.w.route_upsert(
            vni,
            ipv4,
            32,
            RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6: underlay_ipv6,
                is_external: 0,
                _pad: [0; 3],
            },
        )?;
        if ipv6 != [0u8; 16] {
            self.w.route6_upsert(
                vni,
                ipv6,
                128,
                RouteValue {
                    nexthop_vni: vni,
                    nexthop_ipv6: underlay_ipv6,
                    is_external: 0,
                    _pad: [0; 3],
                },
            )?;
        }
        if total_mbps != 0 || public_mbps != 0 {
            self.w
                .meter_upsert(tap, meter_state(total_mbps, public_mbps, 0))?;
        }
        // Restart journal (never read by the datapath): persist what a restart needs to rebuild
        // bookkeeping and re-attach the guest program. Lengths are guarded in create_interface, so
        // `from_id` is `Some` and the device fits.
        if let Some(key) = IfaceMetaKey::from_id(&interface_id) {
            let n = device.len().min(IFACE_DEV_MAX);
            let mut dev = [0u8; IFACE_DEV_MAX];
            dev[..n].copy_from_slice(&device.as_bytes()[..n]);
            self.w.iface_meta_upsert(
                key,
                IfaceMetaVal {
                    vni,
                    tap_ifindex: tap,
                    ipv4,
                    id_len: interface_id.len().min(flowplane_common::IFACE_ID_MAX) as u16,
                    device_len: n as u16,
                    ipv6,
                    underlay: underlay_ipv6,
                    device: dev,
                },
            )?;
        }
        Ok(())
    }

    /// Auto-reset a VNI when its last local interface is removed: purge neighbor NATs, the removed
    /// interface's VIP mapping (and its reverse), its NAT config, and the VNI's routes. Mirrors
    /// dpservice's async-deletion model. Called by the eBPF `detach_interface` after it has decided
    /// the VNI is no longer in use; `ipv4` is the removed interface's guest IPv4.
    pub fn purge_vni(&mut self, vni: u32, ipv4: [u8; 4]) -> anyhow::Result<()> {
        // Purge neighbor NATs for this VNI.
        let before = self.neigh_nats.len();
        self.neigh_nats.retain(|e| e.vni != vni);
        if self.neigh_nats.len() != before {
            let n = self.neigh_nats.len() as u32;
            let remaining: Vec<flowplane_common::NeighborNatEntry> = self.neigh_nats.clone();
            for (i, e) in remaining.iter().enumerate() {
                let _ = self.w.neigh_nat_upsert(i as u32, *e);
            }
            let _ = self.w.neigh_nat_count_set(n);
        }
        // Purge VIP entries for the removed interface's guest IP (and its reverse).
        let maybe_vip = self.w.vips_get(&VipKey { vni, ipv4 });
        if let Some(vip) = maybe_vip {
            let _ = self.w.vips_remove(&VipKey { vni, ipv4: vip });
        }
        let _ = self.w.vips_remove(&VipKey { vni, ipv4 });
        // Purge NAT config for the removed interface's guest IP.
        let _ = self.w.nat_remove(&NatKey { vni, ipv4 });
        // Purge routes for this VNI (same as reset_vni).
        let routes_to_del: Vec<([u8; 4], u32)> = self
            .routes_shadow
            .iter()
            .filter(|&&(v, _, _, _, _)| v == vni)
            .map(|&(_, p, l, _, _)| (p, l))
            .collect();
        for (p, l) in &routes_to_del {
            let _ = self.w.route_remove(vni, *p, *l);
        }
        self.routes_shadow.retain(|&(v, p, l, _, _)| {
            !routes_to_del
                .iter()
                .any(|&(rp, rl)| v == vni && rp == p && rl == l)
        });
        let routes6_to_del: Vec<([u8; 16], u32)> = self
            .routes6_shadow
            .iter()
            .filter(|&&(v, _, _, _, _)| v == vni)
            .map(|&(_, p, l, _, _)| (p, l))
            .collect();
        for (p, l) in &routes6_to_del {
            let _ = self.w.route6_remove(vni, *p, *l);
        }
        self.routes6_shadow.retain(|&(v, p, l, _, _)| {
            !routes6_to_del
                .iter()
                .any(|&(rp, rl)| v == vni && rp == p && rl == l)
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{meter_state, IfaceParams};
    use crate::{mem::MemMapWriter, shadow::IfaceMeta, ControlCore, MapWriter};
    use flowplane_common::{IfaceKey, NatKey, VipKey};

    /// Three-lane mbps->MeterState conversion: egress=EDT (no token bucket, burst=0),
    /// public/ingress=token-bucket policers (burst = bps/8, min 2000B). 0 mbps = pass sentinel.
    /// Ported verbatim from the eBPF `control/mod.rs::meter_state_conversion` onto the pure fn.
    #[test]
    fn meter_state_conversion() {
        let m = meter_state(100, 40, 50);
        assert_eq!(m.total_bps, 100 * 1_000_000 / 8); // 12_500_000 B/s
        assert_eq!(m.public_bps, 40 * 1_000_000 / 8); // 5_000_000 B/s
        assert_eq!(m.ingress_bps, 50 * 1_000_000 / 8); // 6_250_000 B/s
                                                       // EDT total: no token bucket
        assert_eq!(m.total_burst, 0);
        assert_eq!(m.total_tokens, 0);
        // Public policer
        assert_eq!(m.public_burst, (m.public_bps / 8).max(2000));
        assert_eq!(m.public_tokens, m.public_bps / 8);
        // Ingress policer
        assert_eq!(m.ingress_burst, (m.ingress_bps / 8).max(2000));
        assert_eq!(m.ingress_tokens, m.ingress_bps / 8);
        assert_eq!(m.total_last_ns, 0);
        assert_eq!(m.public_last_ns, 0);
        assert_eq!(m.ingress_last_ns, 0);

        // 0 mbps = unlimited sentinel (bps==0).
        let z = meter_state(0, 0, 0);
        assert_eq!(z.total_bps, 0);
        assert_eq!(z.public_bps, 0);
        assert_eq!(z.ingress_bps, 0);
        assert_eq!(z.total_burst, 0);
        assert_eq!(z.public_burst, 2000);
        assert_eq!(z.ingress_burst, 2000);
    }

    fn reg(c: &mut ControlCore<MemMapWriter>, id: &[u8], vni: u32, ipv4: [u8; 4], ifindex: u32) {
        c.register_iface_meta(
            id.to_vec(),
            IfaceMeta {
                vni,
                ipv4,
                ipv6: [0u8; 16],
                underlay: [0u8; 16],
                ifindex,
            },
        );
    }

    #[test]
    fn set_qos_three_lane_programs_meter() {
        let mut c = ControlCore::new(MemMapWriter::default());
        reg(&mut c, b"if1", 5, [10, 0, 0, 2], 42);
        c.set_qos(b"if1", 100, 40, 50).unwrap();
        let m = c.w.meter.get(&42).unwrap();
        assert_eq!(m.total_bps, 100 * 1_000_000 / 8);
        assert_eq!(m.public_bps, 40 * 1_000_000 / 8);
        assert_eq!(m.ingress_bps, 50 * 1_000_000 / 8);
        // All-zero clears the meter entry.
        c.set_qos(b"if1", 0, 0, 0).unwrap();
        assert!(!c.w.meter.contains_key(&42));
        // Unknown interface errors.
        assert!(c.set_qos(b"nope", 1, 0, 0).is_err());
    }

    #[test]
    fn set_dhcp_config_writes_config() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.set_dhcp_config(1400, &[[8, 8, 8, 8]], &[[0x20; 16]])
            .unwrap();
        let cfg = c.w.dhcp_config.expect("dhcp config set");
        assert_eq!(cfg.mtu, 1400);
        assert_eq!(cfg.dns4_len, 1);
        assert_eq!(cfg.dns6_len, 1);
        assert_eq!(cfg.dns4[0], [8, 8, 8, 8]);
        assert_eq!(cfg.dns6[0], [0x20; 16]);
    }

    #[test]
    fn program_interface_writes_ports_ifaces_underlay_routes_meter() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.program_interface(IfaceParams {
            interface_id: b"if1".to_vec(),
            device: "dtapvf_0".to_string(),
            tap: 7,
            effective_mac: [1, 2, 3, 4, 5, 6],
            vni: 5,
            ipv4: [10, 0, 0, 2],
            ipv6: [0x20; 16],
            gateway_ipv4: [10, 0, 0, 1],
            gateway_ipv6: [0x20; 16],
            underlay_ipv6: [0xfd; 16],
            total_mbps: 100,
            public_mbps: 40,
        })
        .unwrap();
        let pm = c.w.ports.get(&7).unwrap();
        assert_eq!(pm.vni, 5);
        assert_eq!(pm.guest_mac, [1, 2, 3, 4, 5, 6]);
        let iv = c.w.ifaces.get(&IfaceKey::new(5, [10, 0, 0, 2])).unwrap();
        assert_eq!(iv.tap_ifindex, 7);
        assert_eq!(iv.is_local, 1);
        assert!(c.w.underlay.contains_key(&[0xfd; 16]));
        // self-routes (v4 /32 + v6 /128)
        assert!(c.w.routes.contains_key(&(5, [10, 0, 0, 2], 32)));
        assert!(c.w.routes6.contains_key(&(5, [0x20; 16], 128)));
        // meter programmed (total or public non-zero)
        let m = c.w.meter.get(&7).unwrap();
        assert_eq!(m.total_bps, 100 * 1_000_000 / 8);
        assert_eq!(m.public_bps, 40 * 1_000_000 / 8);
        // journal written
        assert_eq!(c.w.iface_meta.len(), 1);
    }

    #[test]
    fn purge_vni_clears_neigh_vips_nat_routes() {
        let mut c = ControlCore::new(MemMapWriter::default());
        let vni = 5u32;
        let gip = [10, 0, 0, 2];
        reg(&mut c, b"if1", vni, gip, 7);

        // Seed a neighbor-NAT for this VNI.
        c.add_neighbor_nat(vni, [203, 0, 113, 1], 1024, 2048, [2u8; 16])
            .unwrap();
        assert_eq!(c.w.neigh_nat_count, 1);
        // Seed a VIP (gip -> vip) and its reverse.
        let vip = [10, 0, 0, 9];
        c.w.vips_upsert(VipKey { vni, ipv4: gip }, vip).unwrap();
        c.w.vips_upsert(VipKey { vni, ipv4: vip }, gip).unwrap();
        // Seed a NAT for gip.
        c.w.nat_upsert(
            NatKey { vni, ipv4: gip },
            flowplane_common::NatValue {
                nat_ipv4: [1, 2, 3, 4],
                port_min: 1,
                port_max: 2,
            },
        )
        .unwrap();
        // Seed a route in this VNI (shadow + map).
        c.routes_shadow
            .push((vni, [192, 168, 0, 0], 24, vni, [0u8; 16]));
        c.w.route_upsert(
            vni,
            [192, 168, 0, 0],
            24,
            flowplane_common::RouteValue {
                nexthop_vni: vni,
                nexthop_ipv6: [0u8; 16],
                is_external: 0,
                _pad: [0; 3],
            },
        )
        .unwrap();

        c.purge_vni(vni, gip).unwrap();

        // neigh-NAT purged
        assert!(c.neigh_nats.is_empty());
        assert_eq!(c.w.neigh_nat_count, 0);
        // VIPs (both directions) purged
        assert!(c.w.vips_get(&VipKey { vni, ipv4: gip }).is_none());
        assert!(c.w.vips_get(&VipKey { vni, ipv4: vip }).is_none());
        // NAT purged
        assert!(!c.w.nat.contains_key(&NatKey { vni, ipv4: gip }));
        // routes purged (map + shadow)
        assert!(!c.w.routes.contains_key(&(vni, [192, 168, 0, 0], 24)));
        assert!(c.routes_shadow.is_empty());
    }
}
