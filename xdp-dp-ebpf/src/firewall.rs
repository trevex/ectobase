use crate::maps::FW_CONFIG;

/// Whether firewall enforcement is enabled (FW_CONFIG[0] != 0). The datapath's *verdict* is
/// deny-by-default (see `xdp_dp_core::firewall::fw_eval_dir`), but the drop is only applied when
/// enforcement is ON. Enforcement defaults **OFF** when unset: it must stay off until the control
/// plane installs per-interface allow-all/policy rules (the CompiledNIC→agent→AddFwRule wiring),
/// otherwise ruleless interfaces would fail closed and drop all traffic. Once that wiring lands,
/// enforcement is enabled explicitly (FW_CONFIG[0]=1).
#[inline(always)]
pub fn fw_enforcing() -> bool {
    match FW_CONFIG.get(0) {
        Some(v) => *v != 0,
        None => false,
    }
}
