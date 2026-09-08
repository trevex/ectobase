//! Pure offload-reconcile brain for the E/W flow-offload manager.
//!
//! No netlink, no maps, no async, no I/O: this module only diffs a "desired" set of flows to
//! offload against an "installed" bookkeeping map and computes install/reinstall/delete actions.
//! The async caller (a later task) owns netlink I/O, HW counter dumps, and orphan GC.

use std::collections::HashMap;
use std::hash::Hash;

use flowplane_common::{CtKey, CtKey6};
use flowplane_device::{EncapRedirect, FlowHandle, FlowKey};

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
