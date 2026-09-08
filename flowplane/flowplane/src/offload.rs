//! Pure offload-reconcile brain for the E/W flow-offload manager.
//!
//! No netlink, no maps, no async, no I/O: this module only diffs a "desired" set of flows to
//! offload against an "installed" bookkeeping map and computes install/reinstall/delete actions.
//! The async caller (a later task) owns netlink I/O, HW counter dumps, and orphan GC.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use flowplane_common::{CtEntry, CtKey, CtKey6};
use flowplane_core::conntrack::offload_eligible;
use flowplane_device::{flower, EncapRedirect, FlowHandle, FlowKey, FlowL3};

use crate::conntrack_gc::ktime_now_ns;
use crate::control::Control;
use crate::maps::{Conntrack, Conntrack6};

/// Unified offload map key (v4 and v6 flows must not collide).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OffKey {
    V4(CtKey),
    V6(CtKey6),
}

/// A flow the manager wants offloaded this pass: which representor + the flower match + action.
#[derive(Clone, PartialEq, Debug)]
pub struct Desired {
    pub rep_ifindex: u32,
    pub key: FlowKey,
    pub action: EncapRedirect,
}

/// Bookkeeping for one installed filter.
#[derive(Clone, Debug)]
pub struct InstalledFlow {
    pub handle: FlowHandle,
    pub action: EncapRedirect,
    pub last_pkts: u64,
    pub idle_since_ns: u64,
}

/// The reconcile diff for one pass.
#[derive(PartialEq, Debug)]
pub struct ReconcileOut<K> {
    pub to_install: Vec<(K, Desired)>,
    pub to_reinstall: Vec<(K, Desired)>,
    pub to_delete: Vec<K>,
}

/// Pure reconcile: desired vs installed → diff. Install for new; reinstall when the resolved action
/// changed (VTEP/route moved — prevents stale-destination forwarding); delete for no-longer-desired
/// (flow gone/closed). Idle-aging + orphan-GC are layered on by the async caller (they need HW
/// counters / a kernel dump).
pub fn compute_reconcile<K: Eq + Hash + Copy>(
    desired: &HashMap<K, Desired>,
    installed: &HashMap<K, InstalledFlow>,
) -> ReconcileOut<K> {
    let mut out = ReconcileOut {
        to_install: Vec::new(),
        to_reinstall: Vec::new(),
        to_delete: Vec::new(),
    };
    for (k, d) in desired {
        match installed.get(k) {
            None => out.to_install.push((*k, d.clone())),
            Some(inst) if inst.action != d.action => out.to_reinstall.push((*k, d.clone())),
            Some(_) => {}
        }
    }
    for k in installed.keys() {
        if !desired.contains_key(k) {
            out.to_delete.push(*k);
        }
    }
    out
}

/// True iff an installed flow is idle: HW packet counter hasn't advanced AND idle beyond the timeout.
/// The async caller passes the freshly-dumped `now_pkts` and resets `idle_since_ns` when pkts advance.
pub fn is_idle(inst: &InstalledFlow, now_pkts: u64, now_ns: u64, idle_timeout_ns: u64) -> bool {
    now_pkts == inst.last_pkts && now_ns.saturating_sub(inst.idle_since_ns) >= idle_timeout_ns
}

/// Tunables for the async offload manager loop.
pub struct OffloadCfg {
    /// Reconcile cadence (one snapshot + diff + install/GC pass per tick).
    pub interval: Duration,
    /// A flow with no HW packet advance for at least this long is torn down.
    pub idle_timeout_ns: u64,
    /// Hard cap on concurrently-installed filters (bounds the pref band + memory).
    pub max_flows: usize,
    /// First tc priority the manager owns; it installs within `[pref_base, pref_base+max_flows)`.
    pub pref_base: u16,
}

/// The tc-priority band this manager owns — every install/list/flush is scoped to it, so filters
/// installed by anything else (e.g. the increment-A guest programs) are never touched.
fn pref_band(cfg: &OffloadCfg) -> Range<u16> {
    cfg.pref_base..cfg.pref_base.saturating_add(cfg.max_flows as u16)
}

/// Resolve the set of flows the manager WANTS offloaded this pass from the conntrack snapshots.
///
/// A conntrack entry becomes a `Desired` only when: it is offload-eligible (plain established E/W —
/// see `offload_eligible`); its LOCAL source guest resolves to an offload-capable representor
/// (`INTERFACES[(vni, src)].is_local` + `PORT_META.offloaded`); and its inner destination routes to a
/// remote VTEP (`ROUTES` LPM with a non-zero underlay nexthop — a local/miss route is skipped, it
/// stays on the eBPF path). The action encaps to that VTEP's VNI and mirred-redirects out the geneve
/// device.
///
/// v6 note: `CONNTRACK6` (the firewall v6 mirror) stores `CtEntry`, so the v6 arm reuses
/// `offload_eligible` (same flag/tcp-state test; its `xlate_ip` v4 field is zero on a v6 entry).
fn resolve_desired(
    control: &Control,
    ct: &[(CtKey, CtEntry)],
    ct6: &[(CtKey6, CtEntry)],
    geneve: u32,
) -> HashMap<OffKey, Desired> {
    let mut out = HashMap::new();

    for (k, e) in ct {
        if !offload_eligible(e) {
            continue;
        }
        let Some(iv) = control.iface_lookup_v4(k.vni, k.src_ip) else {
            continue;
        };
        if iv.is_local == 0 || !control.port_offloaded(iv.tap_ifindex) {
            continue;
        }
        let Some(rt) = control.route_lookup_v4(k.vni, k.dst_ip) else {
            continue;
        };
        if rt.nexthop_ipv6 == [0u8; 16] {
            continue;
        }
        out.insert(
            OffKey::V4(*k),
            Desired {
                rep_ifindex: iv.tap_ifindex,
                key: FlowKey {
                    l3: FlowL3::V4 {
                        src: k.src_ip,
                        dst: k.dst_ip,
                    },
                    ip_proto: k.proto,
                    src_port: k.src_port,
                    dst_port: k.dst_port,
                },
                action: EncapRedirect {
                    vni: rt.nexthop_vni,
                    remote_vtep: rt.nexthop_ipv6,
                    redirect_ifindex: geneve,
                },
            },
        );
    }

    for (k, e) in ct6 {
        if !offload_eligible(e) {
            continue;
        }
        let Some(iv) = control.iface_lookup_v6(k.vni, k.src_ip) else {
            continue;
        };
        if iv.is_local == 0 || !control.port_offloaded(iv.tap_ifindex) {
            continue;
        }
        let Some(rt) = control.route_lookup_v6(k.vni, k.dst_ip) else {
            continue;
        };
        if rt.nexthop_ipv6 == [0u8; 16] {
            continue;
        }
        out.insert(
            OffKey::V6(*k),
            Desired {
                rep_ifindex: iv.tap_ifindex,
                key: FlowKey {
                    l3: FlowL3::V6 {
                        src: k.src_ip,
                        dst: k.dst_ip,
                    },
                    ip_proto: k.proto,
                    src_port: k.src_port,
                    dst_port: k.dst_port,
                },
                action: EncapRedirect {
                    vni: rt.nexthop_vni,
                    remote_vtep: rt.nexthop_ipv6,
                    redirect_ifindex: geneve,
                },
            },
        );
    }

    out
}

/// Install one desired flow, allocating a (pref, handle) within the owned band. `next` is a
/// monotonically-increasing cursor: pref = `pref_base + next`, handle = `next`. Once the cursor walks
/// off the end of the band we log + skip (the cap is also enforced by the caller); this keeps
/// allocation trivial and collision-free at the cost of not recycling freed slots — acceptable for a
/// band sized to `max_flows`.
fn install_one(
    installed: &mut HashMap<OffKey, InstalledFlow>,
    next: &mut u32,
    cfg: &OffloadCfg,
    band: &Range<u16>,
    now: u64,
    k: OffKey,
    d: Desired,
) {
    let handle = *next;
    let pref = cfg.pref_base.wrapping_add(handle as u16);
    if !band.contains(&pref) {
        log::warn!("offload pref band {band:?} exhausted (next={next}); skipping install");
        return;
    }
    *next = next.saturating_add(1);
    // clsact may already exist on an increment-A representor (tc_guest_tx) — EEXIST is tolerated.
    let _ = flower::ensure_clsact(d.rep_ifindex);
    match flower::install_flow(d.rep_ifindex, pref, handle, &d.key, &d.action) {
        Ok(fh) => {
            installed.insert(
                k,
                InstalledFlow {
                    handle: fh,
                    action: d.action,
                    last_pkts: 0,
                    idle_since_ns: now,
                },
            );
        }
        Err(e) => log::warn!(
            "offload install failed on rep {} pref {pref}: {e:#}",
            d.rep_ifindex
        ),
    }
}

/// HW-counter idle-aging + orphan/stale GC over the manager's pref band.
///
/// Dumps every representor we might own filters on (offload-capable reps ∪ reps present in
/// `installed`) and, per listed filter: a handle we do NOT own is an ORPHAN (leaked by a prior
/// crash) → deleted; a handle we own has its HW packet counter compared — advancing resets the idle
/// clock, flat-and-timed-out tears the flow down. Finally, any `installed` entry whose filter did not
/// appear in a SUCCESSFUL dump of its rep is stale bookkeeping (the kernel dropped it) → forgotten.
fn idle_age_and_gc(
    control: &Control,
    installed: &mut HashMap<OffKey, InstalledFlow>,
    band: &Range<u16>,
    now: u64,
    cfg: &OffloadCfg,
) {
    // Reps to scan: offload-capable reps plus any rep we currently hold a filter on.
    let mut reps: HashSet<u32> = control.offloaded_reps().into_iter().collect();
    for inst in installed.values() {
        reps.insert(inst.handle.ifindex);
    }

    // (ifindex, pref, handle) -> OffKey for the filters we own (correlate a dump back to bookkeeping).
    let owned: HashMap<(u32, u16, u32), OffKey> = installed
        .iter()
        .map(|(k, f)| ((f.handle.ifindex, f.handle.pref, f.handle.handle), *k))
        .collect();

    let mut seen: HashSet<OffKey> = HashSet::new();
    let mut dumped_reps: HashSet<u32> = HashSet::new();
    let mut orphans: Vec<FlowHandle> = Vec::new();
    let mut idle: Vec<OffKey> = Vec::new();

    for rep in reps {
        let fs = match flower::list_flows(rep, band.clone()) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("offload list_flows failed on rep {rep}: {e:#}");
                continue;
            }
        };
        dumped_reps.insert(rep);
        for f in fs {
            let tup = (f.handle.ifindex, f.handle.pref, f.handle.handle);
            match owned.get(&tup) {
                None => orphans.push(f.handle),
                Some(&key) => {
                    seen.insert(key);
                    if let Some(inst) = installed.get_mut(&key) {
                        if f.pkts > inst.last_pkts {
                            inst.last_pkts = f.pkts;
                            inst.idle_since_ns = now;
                        } else if is_idle(inst, f.pkts, now, cfg.idle_timeout_ns) {
                            idle.push(key);
                        }
                    }
                }
            }
        }
    }

    // Orphaned filters (not ours) — delete loudly on failure (a leak if it fails).
    for h in orphans {
        if let Err(e) = flower::delete_flow(&h) {
            log::error!("offload orphan delete FAILED (leak risk) {h:?}: {e:#}");
        }
    }

    // Idle flows — delete + forget.
    for key in idle {
        if let Some(inst) = installed.remove(&key) {
            if let Err(e) = flower::delete_flow(&inst.handle) {
                log::error!(
                    "offload idle delete FAILED (leak risk) {:?}: {e:#}",
                    inst.handle
                );
            }
        }
    }

    // Stale bookkeeping: a filter we think is installed on a SUCCESSFULLY-dumped rep but that the
    // kernel no longer lists (it dropped it) — drop our record so a later pass reinstalls it.
    let stale: Vec<OffKey> = installed
        .iter()
        .filter(|(k, f)| dumped_reps.contains(&f.handle.ifindex) && !seen.contains(k))
        .map(|(k, _)| *k)
        .collect();
    for key in stale {
        installed.remove(&key);
    }
}

/// The async E/W flow-offload manager: a leak-safe reconcile loop. On startup it FLUSHES any leaked
/// owned filters across every offload-capable representor (a prior crash could have left our band
/// populated), then every `interval` it snapshots conntrack, resolves the desired offload set, and
/// reconciles: deletes-first (frees pref slots) then installs/reinstalls (cap-bounded), finishing
/// with HW-counter idle-aging + orphan GC. All netlink I/O + counter dumps live here; the diff itself
/// is the pure `compute_reconcile`.
pub async fn run(
    control: Arc<Control>,
    ct: Arc<Mutex<Conntrack>>,
    ct6: Arc<Mutex<Conntrack6>>,
    cfg: OffloadCfg,
) {
    let geneve = control.geneve_ifindex();
    let band = pref_band(&cfg);
    let mut installed: HashMap<OffKey, InstalledFlow> = HashMap::new();
    let mut next: u32 = 1;

    // STARTUP FLUSH — clear any leaked owned filters across all offload-capable reps before we begin,
    // so a crash that left our band populated can't accumulate stale HW state.
    for rep in control.offloaded_reps() {
        if let Ok(fs) = flower::list_flows(rep, band.clone()) {
            for f in fs {
                let _ = flower::delete_flow(&f.handle);
            }
        }
    }

    loop {
        tokio::time::sleep(cfg.interval).await;
        let now = ktime_now_ns();
        let snap: Vec<_> = ct.lock().entries();
        let snap6: Vec<_> = ct6.lock().entries();
        let desired = resolve_desired(&control, &snap, &snap6, geneve);
        let diff = compute_reconcile(&desired, &installed);

        // Deletes first (frees pref slots), then installs/reinstalls (cap-bounded).
        for k in diff.to_delete {
            if let Some(f) = installed.remove(&k) {
                if let Err(e) = flower::delete_flow(&f.handle) {
                    log::error!("offload delete FAILED (leak risk) {:?}: {e:#}", f.handle);
                }
            }
        }
        for (k, d) in diff.to_reinstall {
            if let Some(f) = installed.remove(&k) {
                let _ = flower::delete_flow(&f.handle);
            }
            install_one(&mut installed, &mut next, &cfg, &band, now, k, d);
        }
        for (k, d) in diff.to_install {
            if installed.len() >= cfg.max_flows {
                log::warn!("offload cap {} reached", cfg.max_flows);
                break;
            }
            install_one(&mut installed, &mut next, &cfg, &band, now, k, d);
        }

        idle_age_and_gc(&control, &mut installed, &band, now, &cfg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowplane_device::FlowL3;

    fn fk() -> FlowKey {
        FlowKey {
            l3: FlowL3::V4 {
                src: [10, 0, 0, 1],
                dst: [10, 0, 0, 2],
            },
            ip_proto: 6,
            src_port: 1,
            dst_port: 443,
        }
    }
    fn act(v: u8) -> EncapRedirect {
        EncapRedirect {
            vni: 100,
            remote_vtep: [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, v],
            redirect_ifindex: 9,
        }
    }
    fn ck() -> OffKey {
        OffKey::V4(CtKey {
            vni: 100,
            src_ip: [10, 0, 0, 1],
            dst_ip: [10, 0, 0, 2],
            src_port: 1,
            dst_port: 443,
            proto: 6,
            _pad: [0; 3],
        })
    }
    fn inst(a: EncapRedirect) -> InstalledFlow {
        InstalledFlow {
            handle: FlowHandle {
                ifindex: 7,
                pref: 40000,
                handle: 1,
            },
            action: a,
            last_pkts: 0,
            idle_since_ns: 0,
        }
    }

    #[test]
    fn installs_new() {
        let d = HashMap::from([(
            ck(),
            Desired {
                rep_ifindex: 7,
                key: fk(),
                action: act(0xee),
            },
        )]);
        let o = compute_reconcile(&d, &HashMap::new());
        assert_eq!(o.to_install.len(), 1);
        assert!(o.to_delete.is_empty());
        assert!(o.to_reinstall.is_empty());
    }

    #[test]
    fn deletes_gone() {
        let i = HashMap::from([(ck(), inst(act(0xee)))]);
        let o = compute_reconcile(&HashMap::new(), &i);
        assert_eq!(o.to_delete, vec![ck()]);
    }

    #[test]
    fn reinstalls_on_action_change() {
        let d = HashMap::from([(
            ck(),
            Desired {
                rep_ifindex: 7,
                key: fk(),
                action: act(0xff),
            },
        )]);
        let i = HashMap::from([(ck(), inst(act(0xee)))]);
        let o = compute_reconcile(&d, &i);
        assert_eq!(o.to_reinstall.len(), 1);
        assert!(o.to_install.is_empty());
        assert!(o.to_delete.is_empty());
    }

    #[test]
    fn noop_when_unchanged() {
        let d = HashMap::from([(
            ck(),
            Desired {
                rep_ifindex: 7,
                key: fk(),
                action: act(0xee),
            },
        )]);
        let i = HashMap::from([(ck(), inst(act(0xee)))]);
        let o = compute_reconcile(&d, &i);
        assert!(o.to_install.is_empty() && o.to_reinstall.is_empty() && o.to_delete.is_empty());
    }

    #[test]
    fn idle_only_when_flat_and_timed_out() {
        let f = inst(act(0xee)); // last_pkts 0, idle_since 0
        assert!(!is_idle(&f, 5, 1000, 100), "pkts advanced -> not idle");
        assert!(!is_idle(&f, 0, 50, 100), "flat but not yet timed out");
        assert!(is_idle(&f, 0, 200, 100), "flat and past timeout -> idle");
    }
}
