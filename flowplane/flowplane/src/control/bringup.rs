//! Datapath startup + attach: `bring_up` (load uplink_rx, take map handles,
//! adopt on restart), plus the WAN-edge and extra-uplink attach entry points.
//! Split out of `control/mod.rs` (review P1.2); pure code movement. The methods
//! stay inherent `impl Control` methods reached via `super`, so all callers are
//! unchanged.

use super::*;

impl Control {
    /// Load + attach uplink_rx, set LOCAL, take the map handles. The uplink identity + pinning policy
    /// are all distinct one-shot init inputs, so this constructor takes them positionally.
    #[allow(clippy::too_many_arguments)]
    pub fn bring_up(
        uplink: &str,
        uplink_ifindex: u32,
        uplink_mac: [u8; 6],
        gateway_mac: [u8; 6],
        underlay_ipv6: [u8; 16],
        pin_dir: &Path,
        adopt: bool,
        pin_links: bool,
    ) -> anyhow::Result<Self> {
        let mut ebpf = loader::load_ebpf(pin_dir)?;
        loader::maybe_install_logger(&mut ebpf);
        // Bring up the node-wide `collect_md` Geneve device (the overlay encap target). Idempotent
        // (delete-if-exists then add), so this is safe on both a fresh bring-up AND an adopt
        // restart — unlike the pinned BPF maps/links, this netdev is NOT torn down on graceful
        // shutdown (see the `Serve` shutdown handler in main.rs), so re-running `ensure_geneve_dev`
        // here just confirms/repairs it.
        let flowplane_device::GeneveDev {
            ifindex: geneve_ifindex,
            recreated: geneve_recreated,
        } = flowplane_device::ensure_geneve_dev(flowplane_device::GENEVE_DEV, gateway_mac)
            .context("bring up collect_md geneve device")?;
        let mut geneve_ifindex_map = GeneveIfindexMap::open(&mut ebpf)?;
        geneve_ifindex_map.set(geneve_ifindex)?;
        // If the geneve netdev was CREATED fresh this bring-up (new ifindex), any pinned tc link that
        // survived in the (host-mounted) bpffs from a prior process points at the OLD, now-gone device
        // — re-pointing it via `readopt_tc_link`/`bpf_link_update` can silently land on a dangling link
        // (program updated, attached to nothing), which is exactly how `uplink_rx` went missing on the
        // edge after a lab re-up. So only READOPT when the device was CONFIRMED (survived, links still
        // valid); a recreated device forces the fresh attach+pin path below (which clears the stale pin).
        let geneve_adopt = adopt && !geneve_recreated;
        // uplink_rx is tcx on the geneve `collect_md` DEVICE's ingress — NOT the physical uplink
        // NIC. The kernel decaps on the geneve device's own RX path (that is what `collect_md`
        // means); only once that has happened does our tcx program see the (now-inner) frame, VNI
        // recovered via `get_tunnel_key`. Attaching to the raw uplink NIC instead would see the
        // still-encapsulated wire bytes (no tunnel-key metadata yet) and get_tunnel_key would just
        // fail every time.
        if pin_links {
            let uplink_pin = "uplink-geneve".to_string();
            // Adopt: atomically re-point the surviving pinned link at the fresh program (no gap). A
            // missing/broken pin falls through to a fresh attach+pin.
            let readopted = geneve_adopt
                && loader::readopt_tc_link(&mut ebpf, "uplink_rx", pin_dir, &uplink_pin)
                    .unwrap_or_else(|e| {
                        eprintln!("re-adopt uplink link failed ({e:#}); attaching fresh");
                        loader::unpin_link(pin_dir, &uplink_pin);
                        false
                    });
            if !readopted {
                loader::attach_tc_pinned_at(
                    &mut ebpf,
                    "uplink_rx",
                    flowplane_device::GENEVE_DEV,
                    pin_dir,
                    &uplink_pin,
                )?;
            }
            // `uplink_dsr_note` is a SEPARATE tcx program on the SAME geneve ingress hook,
            // ordered to run BEFORE `uplink_rx` via `LinkOrder::first()` (see
            // `attach_tc_pinned_at_first`'s doc comment for the ordering guarantee — it is
            // independent of which of the two calls runs first). It does only the DSR-map note (its
            // own fresh 512B BPF stack), then always continues to `uplink_rx`; see
            // `flowplane-ebpf/src/ingress.rs::try_uplink_dsr_note`'s doc comment for why this is a
            // separate program at all. Attached unconditionally on every node (harmless no-op when no
            // DSR option is ever present, e.g. on a node that is never an LB backend).
            let dsr_note_pin = "uplink-dsr-note-geneve".to_string();
            let dsr_note_readopted = geneve_adopt
                && loader::readopt_tc_link(&mut ebpf, "uplink_dsr_note", pin_dir, &dsr_note_pin)
                    .unwrap_or_else(|e| {
                        eprintln!("re-adopt uplink_dsr_note link failed ({e:#}); attaching fresh");
                        loader::unpin_link(pin_dir, &dsr_note_pin);
                        false
                    });
            if !dsr_note_readopted {
                loader::attach_tc_pinned_at_first(
                    &mut ebpf,
                    "uplink_dsr_note",
                    flowplane_device::GENEVE_DEV,
                    pin_dir,
                    &dsr_note_pin,
                )?;
            }
        } else {
            // pin-links off: clear any stale pin from a previous pin-on run so the fresh (unpinned)
            // attach can't hit EBUSY against a link that survived the last process.
            loader::unpin_link(pin_dir, "uplink-geneve");
            loader::attach_tc_clsact_ingress(&mut ebpf, "uplink_rx", flowplane_device::GENEVE_DEV)?;
            loader::unpin_link(pin_dir, "uplink-dsr-note-geneve");
            loader::attach_tc_clsact_ingress_first(
                &mut ebpf,
                "uplink_dsr_note",
                flowplane_device::GENEVE_DEV,
            )?;
        }
        // The physical uplink NIC still needs the `fq` root qdisc for EDT egress shaping (unrelated
        // to the ingress attach above — this paces the departure time the guest-egress encap arm
        // stamps via `bpf_skb_set_tstamp`).
        loader::ensure_fq_qdisc(uplink);
        // Guest edge is tcx-only. Pre-load tc_guest_tx and register the tc DHCP/NAT64 tail-call
        // array (GUEST_PROGS_TC) once here; per-interface attach then only needs attach().
        let guest_progs = {
            let progs = loader::register_guest_dhcp_tc(&mut ebpf)?;
            loader::load_program_tc(&mut ebpf, "tc_guest_tx")?;
            progs
        };
        // Register the inner-IPv6 uplink tail-call target (xdp_uplink_v6, now tc) so uplink_rx's v6
        // tail call resolves; without this the daemon fails open to TC_ACT_OK on inner-v6 ingress.
        let uplink_progs = loader::register_uplink_v6_tc(&mut ebpf)?;
        let mut locals = LocalMap::open(&mut ebpf)?;
        locals.set(&Local {
            uplink_ifindex,
            uplink_mac,
            gateway_mac,
            underlay_ipv6,
        })?;
        let ports = PortMetaMap::open(&mut ebpf)?;
        let ifaces = Interfaces::open(&mut ebpf)?;
        let ifaces6 = Interfaces6::open(&mut ebpf)?;
        let routes = Routes::open(&mut ebpf)?;
        let routes6 = Routes6::open(&mut ebpf)?;
        let vips = Vips::open(&mut ebpf)?;
        let lb = Lb::open(&mut ebpf)?;
        let maglev = Maglev::open(&mut ebpf)?;
        let nat = Nat::open(&mut ebpf)?;
        let fw_rules = FwRules::open(&mut ebpf)?;
        let fw_meta = FwMetaMap::open(&mut ebpf)?;
        let fw_rules6 = FwRules6::open(&mut ebpf)?;
        let fw_meta6 = FwMetaMap6::open(&mut ebpf)?;
        let underlay = crate::maps::Underlay::open(&mut ebpf)?;
        let meter = Meter::open(&mut ebpf)?;
        let neigh_nat = NeighborNat::open(&mut ebpf)?;
        let neigh_nat_count = NeighborNatCount::open(&mut ebpf)?;
        let nat_ips = NatIps::open(&mut ebpf)?;
        // NAT66 (v6) config maps — siblings of the four v4 nat maps above.
        let nat6 = crate::maps::Nat6::open(&mut ebpf)?;
        let nat_ips6 = crate::maps::NatIps6::open(&mut ebpf)?;
        let neigh_nat6 = crate::maps::NeighborNat6::open(&mut ebpf)?;
        let neigh_nat6_count = crate::maps::NeighborNat6Count::open(&mut ebpf)?;
        let nat_ct6 = crate::maps::NatCt6::open(&mut ebpf)?;
        let dhcp_config = DhcpConfigMap::open(&mut ebpf)?;
        let dhcp_meta = DhcpMetaMap::open(&mut ebpf)?;
        let iface_meta = IfaceMetaMap::open(&mut ebpf)?;
        let conntrack = Arc::new(Mutex::new(Conntrack::open(&mut ebpf)?));
        // v6 firewall conntrack handle for the interface-detach flush. No userspace GC task holds it
        // (the LRU map self-evicts), so AyaWriter owns the sole handle — no Control field needed.
        let conntrack6 = Arc::new(Mutex::new(Conntrack6::open(&mut ebpf)?));
        let aya = AyaWriter {
            routes,
            routes6,
            nat,
            nat_ips,
            neigh_nat,
            neigh_nat_count,
            nat6,
            nat_ips6,
            neigh_nat6,
            neigh_nat6_count,
            nat_ct6,
            lb,
            maglev,
            underlay,
            fw_rules,
            fw_meta,
            fw_rules6,
            fw_meta6,
            ports,
            ifaces,
            ifaces6,
            vips,
            meter,
            dhcp_config,
            dhcp_meta,
            iface_meta,
            conntrack: Arc::clone(&conntrack),
            conntrack6,
        };
        let mut inner = Inner {
            ebpf,
            _guest_progs: guest_progs,
            _uplink_progs: uplink_progs,
            _locals: locals,
            _geneve_ifindex: geneve_ifindex_map,
            geneve_ifindex,
            core: ControlCore::new(aya),
            recovered: Vec::new(),
            pin_links,
            pin_dir: pin_dir.to_path_buf(),
            by_id: HashMap::new(),
            iface_underlay: HashMap::new(),
            links: HashMap::new(),
            learned_macs: HashMap::new(),
        };
        // Restart adopt: the pinned state maps were reused by map_pin_path, so rebuild the in-memory
        // bookkeeping (by_id/by_ifindex/iface_underlay) and the re-attach list from the surviving
        // IFACE_META journal. A fresh (non-adopt) bring-up starts empty.
        if adopt {
            let recovered = Self::rebuild_from_maps(&mut inner)?;
            eprintln!(
                "adopt: recovered {} interface(s) from pinned maps",
                recovered.len(),
            );
            inner.recovered = recovered;
        }
        Ok(Self {
            inner: Mutex::new(inner),
            conntrack,
        })
    }

    /// WAN-edge role: attach `wan_rx` to the WAN uplink and register the edge's own underlay /128
    /// as a local-deliver UNDERLAY entry (sentinel tap). Fabric->WAN egress then decaps and
    /// XDP_PASSes to the local kernel (VyOS), while WAN->fabric returns to a `nat_ip` are caught by
    /// `wan_rx` and re-encapped to the block owner. Call once, after `bring_up`.
    pub fn attach_edge(&self, wan_uplink: &str, edge_underlay: [u8; 16]) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let pin_links = g.pin_links;
        let pin_dir = g.pin_dir.clone();
        if pin_links {
            let name = format!("wan-{wan_uplink}");
            let readopted = loader::readopt_tc_link(&mut g.ebpf, "wan_rx", &pin_dir, &name)
                .unwrap_or_else(|e| {
                    eprintln!("re-adopt wan link failed ({e:#}); attaching fresh");
                    loader::unpin_link(&pin_dir, &name);
                    false
                });
            if !readopted {
                loader::attach_tc_pinned_at(&mut g.ebpf, "wan_rx", wan_uplink, &pin_dir, &name)?;
            }
        } else {
            loader::unpin_link(&pin_dir, &format!("wan-{wan_uplink}"));
            loader::attach_tc_clsact_ingress(&mut g.ebpf, "wan_rx", wan_uplink)?;
        }
        loader::ensure_fq_qdisc(wan_uplink);
        g.core.writer_mut().underlay_upsert(
            edge_underlay,
            flowplane_common::UnderlayValue {
                vni: 0,
                tap_ifindex: flowplane_common::UNDERLAY_LOCAL_DELIVER,
                guest_mac: [0; 6],
                _pad: [0; 2],
            },
        )?;
        println!(
            "edge role: wan_rx attached to {wan_uplink}; UNDERLAY[{}] = local-deliver",
            std::net::Ipv6Addr::from(edge_underlay)
        );
        Ok(())
    }

    /// Attach `uplink_rx` on an ADDITIONAL fabric uplink (a dual-homed host decaps returns arriving
    /// via either ToR). The program is already loaded by `bring_up`; this just attaches it to
    /// another interface. LOCAL stays the primary uplink (egress + wan_rx redirect use it).
    ///
    /// NOTE: under the geneve `collect_md` model, decap happens on the geneve device's OWN RX
    /// path regardless of which physical NIC the encapped packet arrived on (a single virtual
    /// device demuxes the tunnel), and `bring_up` attaches the "real" `uplink_rx` there — see its
    /// doc comment. So attaching `uplink_rx` directly to a raw extra physical NIC (as this fn does)
    /// now only ever sees still-encapsulated bytes: `get_tunnel_key` fails immediately and the
    /// program passes every frame through unchanged. Kept (converted to tcx) for CLI/mechanical
    /// parity rather than as something dual-homing still needs; a follow-up can retire
    /// `--extra-uplink` entirely once that is confirmed in practice.
    pub fn attach_extra_uplink(&self, iface: &str) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        let pin_links = g.pin_links;
        let pin_dir = g.pin_dir.clone();
        if pin_links {
            let name = format!("uplink-{iface}");
            let readopted = loader::readopt_tc_link(&mut g.ebpf, "uplink_rx", &pin_dir, &name)
                .unwrap_or_else(|e| {
                    eprintln!("re-adopt extra uplink {iface} failed ({e:#}); attaching fresh");
                    loader::unpin_link(&pin_dir, &name);
                    false
                });
            if !readopted {
                loader::attach_tc_pinned_at(&mut g.ebpf, "uplink_rx", iface, &pin_dir, &name)?;
            }
        } else {
            loader::unpin_link(&pin_dir, &format!("uplink-{iface}"));
            loader::attach_tc_clsact_ingress(&mut g.ebpf, "uplink_rx", iface)?;
        }
        loader::ensure_fq_qdisc(iface);
        println!("uplink_rx attached to extra uplink {iface}");
        Ok(())
    }
}
