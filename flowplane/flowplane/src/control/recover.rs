//! Crash-recovery / restart-adopt: rebuild the in-memory bookkeeping from the
//! surviving `IFACE_META` journal and re-attach guest programs. Split out of
//! `control/mod.rs` (review P1.2); pure code movement. The methods stay inherent
//! `impl Control` methods reached via `super`, so all callers are unchanged.

use super::*;

/// Whether `device` is a `netkit` link, by parsing `ip -d link show <device>` (the `-d` detail line
/// carries the link kind). Used ONLY on restart-adopt to pick the guest-program re-attach mechanism
/// (netkit `bpf(BPF_LINK_UPDATE)` vs tcx) — the device kind is authoritative there, since the
/// datapath L2/L3 semantics (which do not imply the device kind, since the VM pod-tap is a
/// netkit-L2 device) live in the PORT_META map. Best-effort: any error / missing device → false
/// (fall back to the tcx re-attach path).
fn device_is_netkit(device: &str) -> bool {
    std::process::Command::new("ip")
        .args(["-d", "link", "show", device])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("netkit"))
        .unwrap_or(false)
}

/// `(interface_id, device)` pairs whose guest program must be re-attached after a graceful restart
/// (their bpf-links died with the old process; the pinned maps survived).
// (interface_id, device, netkit): the bool tells the adopt caller whether to re-point the guest
// program's pinned link as a netkit link (bpf(BPF_LINK_UPDATE)) or a tcx link (readopt_tc_link). It
// is probed from the live device kind on adopt (device_is_netkit), NOT the journal l3 bit — the VM
// pod-tap is a netkit device with L2 semantics, so l3 does not imply the device kind.
pub(super) type ReattachList = Vec<(Vec<u8>, String, bool)>;

impl Control {
    /// After adopting pinned maps on restart, repopulate the in-memory bookkeeping from the surviving
    /// `IFACE_META` journal so subsequent AttachInterface/DetachInterface/get/list see the pre-restart
    /// state. Returns `reattach`: `(interface_id, device)` whose guest program must be RE-ATTACHED by
    /// the caller (their links died with the old process; the maps survived).
    pub(super) fn rebuild_from_maps(g: &mut Inner) -> anyhow::Result<ReattachList> {
        let journal = g.core.writer().iface_meta_entries();
        // Sanity cross-check: the journal should track the surviving INTERFACES map 1:1.
        let iface_count = g.core.writer().ifaces_count();
        if iface_count != journal.len() {
            eprintln!(
                "adopt: WARNING IFACE_META has {} entries but INTERFACES has {} — journal drift",
                journal.len(),
                iface_count
            );
        }
        let mut reattach = Vec::with_capacity(journal.len());
        for (k, v) in &journal {
            let (id, device, rec) = Self::decode_iface_meta(k, v);
            // Re-derive the CURRENT tap ifindex — the veth persists across the restart, but the
            // stored ifindex is only a cross-check. If the device is gone (pod deleted during the
            // downtime), skip re-attach; its stale maps are cleaned by a later DetachInterface.
            let tap = match crate::ifindex(&device) {
                Ok(ix) => ix,
                Err(e) => {
                    eprintln!("adopt: device {device} for a recovered interface is gone ({e}); skipping re-attach");
                    continue;
                }
            };
            if tap != v.tap_ifindex {
                eprintln!(
                    "adopt: {device} ifindex changed {} -> {tap} since attach; using live value",
                    v.tap_ifindex
                );
            }
            // Mirror the agnostic subset into the core so post-adopt NAT/LB conflict checks (which
            // live in ControlCore) see the recovered interface, exactly as they saw `by_id` before.
            g.core.register_iface_meta(
                id.clone(),
                flowplane_control::shadow::IfaceMeta {
                    vni: rec.vni,
                    ipv4: rec.ipv4,
                    ipv6: rec.ipv6,
                    underlay: rec.underlay,
                    ifindex: tap,
                },
            );
            g.by_id.insert(id.clone(), rec);
            g.iface_underlay.insert(id.clone(), v.underlay);
            // The re-attach mechanism (netkit BPF_LINK_UPDATE vs tcx) is decided by the DEVICE KIND,
            // not the journal `l3` bit: the VM pod-tap is a netkit device with L2 (l3=0) semantics, so
            // `l3` does not distinguish it from a veth/tap. Probe the live device (it survives a
            // flowplane restart — it lives in the node root netns / the still-running pod netns).
            let netkit = device_is_netkit(&device);
            reattach.push((id, device, netkit));
        }
        Ok(reattach)
    }

    /// Pure decode of one `IFACE_META` journal entry into `(interface_id, device, IfaceRecord)`.
    /// Factored out so the parsing is unit-testable without a live BPF map.
    fn decode_iface_meta(k: &IfaceMetaKey, v: &IfaceMetaVal) -> (Vec<u8>, String, IfaceRecord) {
        let id = k.id[..(v.id_len as usize).min(k.id.len())].to_vec();
        let device =
            String::from_utf8_lossy(&v.device[..(v.device_len as usize).min(v.device.len())])
                .into_owned();
        let rec = IfaceRecord {
            vni: v.vni,
            ipv4: v.ipv4,
            ipv6: v.ipv6,
            device: device.clone(),
            underlay: v.underlay,
        };
        (id, device, rec)
    }

    /// The `(interface_id, device)` list recovered on adopt, whose guest program the caller must
    /// re-attach. Empty after a fresh bring-up.
    pub fn recovered_interfaces(&self) -> ReattachList {
        self.inner.lock().recovered.clone()
    }

    /// Re-attach the guest datapath program to an ADOPTED interface's device after a restart. The
    /// pinned maps and in-memory bookkeeping already describe it (map_pin_path reuse +
    /// `rebuild_from_maps`); this ONLY re-creates the `GuestLink` (the old one died with the process)
    /// and stores it so a later DetachInterface can drop it — no map writes, no bookkeeping insert.
    /// Mirrors the attach half of `create_interface`.
    pub fn reattach_guest(
        &self,
        interface_id: &[u8],
        device: &str,
        netkit: bool,
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock();
        if g.pin_links {
            let pin_dir = g.pin_dir.clone();
            let gname = format!("guest-{}", hex_encode(interface_id));
            // Re-point the guest program's pinned link at the freshly-loaded program, atomically
            // (zero-gap). `netkit` (probed from the live device at adopt) selects the mechanism: a
            // netkit link (container L3 OR VM L2 pod-tap) MUST be re-pointed with bpf(BPF_LINK_UPDATE)
            // (readopt_netkit_link) — the tcx readopt path can't drive a netkit link and would unpin
            // the LIVE link + mis-attach a clsact/tcx program to the netkit primary. A veth/tap link
            // uses readopt_tc_link. (Independent of the L2/L3 datapath semantics, which live in the
            // surviving PORT_META map, not here.)
            let readopt = if netkit {
                loader::readopt_netkit_link(&mut g.ebpf, "tc_guest_tx", &pin_dir, &gname)
            } else {
                loader::readopt_tc_link(&mut g.ebpf, "tc_guest_tx", &pin_dir, &gname)
            };
            let readopted = readopt.unwrap_or_else(|e| {
                eprintln!("re-adopt guest link {gname} failed ({e:#}); attaching fresh");
                loader::unpin_link(&pin_dir, &gname);
                false
            });
            if !readopted {
                // No pin to adopt (or adopt failed): (re)attach fresh with the matching mechanism.
                if netkit {
                    let tap = crate::ifindex(device)
                        .with_context(|| format!("resolve netkit primary ifindex for {device}"))?;
                    loader::attach_netkit_pinned_at(
                        &mut g.ebpf,
                        "tc_guest_tx",
                        tap,
                        &pin_dir,
                        &gname,
                    )?;
                } else {
                    loader::attach_tc_pinned_at(
                        &mut g.ebpf,
                        "tc_guest_tx",
                        device,
                        &pin_dir,
                        &gname,
                    )?;
                }
            }
            g.links
                .insert(interface_id.to_vec(), GuestLink::Pinned(gname));
            return Ok(());
        }
        let link = GuestLink::Tc(
            loader::attach_tc_clsact_ingress_link(&mut g.ebpf, "tc_guest_tx", device)
                .with_context(|| format!("re-attach tc_guest_tx to {device}"))?,
        );
        g.links.insert(interface_id.to_vec(), link);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure (no-BPF) check that an IFACE_META journal entry round-trips back to the interface_id,
    /// device, and IfaceRecord the restart rebuild needs — the crux of the adopt path.
    #[test]
    fn rebuild_decode_roundtrip() {
        let id: &[u8] = b"550e8400-e29b-41d4-a716-446655440000/eth0";
        let key = IfaceMetaKey::from_id(id).expect("id fits IFACE_ID_MAX");
        let mut dev = [0u8; IFACE_DEV_MAX];
        dev[..8].copy_from_slice(b"dtapvf_3");
        let val = IfaceMetaVal {
            vni: 100,
            tap_ifindex: 42,
            ipv4: [10, 0, 0, 5],
            id_len: id.len() as u16,
            device_len: 8,
            ipv6: [0x20; 16],
            underlay: [0xfd; 16],
            device: dev,
            l3: 0,
            _pad: [0; 3],
        };
        let (got_id, got_dev, rec) = Control::decode_iface_meta(&key, &val);
        assert_eq!(
            got_id, id,
            "interface_id restored verbatim (not hashed/truncated)"
        );
        assert_eq!(got_dev, "dtapvf_3");
        assert_eq!(rec.vni, 100);
        assert_eq!(rec.ipv4, [10, 0, 0, 5]);
        assert_eq!(rec.ipv6, [0x20; 16]);
        assert_eq!(rec.underlay, [0xfd; 16]);
        assert_eq!(rec.device, "dtapvf_3");
    }

    /// An interface_id at the exact cap round-trips; one byte over is rejected (would alias on adopt).
    #[test]
    fn iface_meta_key_length_bounds() {
        let max = vec![b'x'; flowplane_common::IFACE_ID_MAX];
        let key = IfaceMetaKey::from_id(&max).expect("exactly IFACE_ID_MAX fits");
        assert_eq!(&key.id[..], &max[..]);
        let over = vec![b'x'; flowplane_common::IFACE_ID_MAX + 1];
        assert!(
            IfaceMetaKey::from_id(&over).is_none(),
            "over-cap id rejected"
        );
    }
}
