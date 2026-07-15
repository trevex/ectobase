use crate::maps::FW_CONFIG;

/// Whether enforcement is enabled (FW_CONFIG[0] != 0; default true when unset).
#[inline(always)]
pub fn fw_enforcing() -> bool {
    match FW_CONFIG.get(0) {
        Some(v) => *v != 0,
        None => true,
    }
}
