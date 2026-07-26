//! Safe wrappers over DPDK runtime device hotplug (`rte_eal_hotplug_add`/`_remove`) and
//! name→port-id resolution. Used by the guest-port pool's dead-slot recovery (flowplane-dpdk
//! `VethBackend::recover`): a vdev whose backing netdev died is hot-REMOVED then re-ADDED against
//! a freshly recreated veth, and its ethdev port id is re-resolved by device name.
//!
//! These are the ONE sanctioned runtime mutation to the otherwise-static af_xdp poll set; the
//! Port reconfigure + the worker's !Send queue-handle rebuild happen elsewhere (a generation
//! handshake) — this module only touches the process-global device registry (control-plane, Send).
use std::ffi::CString;

/// A hotplug / name-resolution failure. `rc` is the DPDK return code (negative on error); where a
/// distinct `rte_errno` is meaningful it is captured too (mirrors `PortError`/`EalError` style).
#[derive(Debug)]
pub enum HotplugError {
    /// A `busname`/`devname`/`devargs` argument contained an interior NUL byte.
    BadArg,
    /// `rte_eal_hotplug_add` returned non-zero.
    Add(i32),
    /// `rte_eal_hotplug_remove` returned non-zero.
    Remove(i32),
    /// `rte_eth_dev_get_port_by_name` failed (device not present after add).
    NoSuchPort(i32),
}

impl std::fmt::Display for HotplugError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HotplugError::BadArg => write!(f, "hotplug argument contains an interior NUL byte"),
            HotplugError::Add(rc) => {
                write!(f, "rte_eal_hotplug_add failed (rc={rc}; errno={})", errno())
            }
            HotplugError::Remove(rc) => {
                write!(
                    f,
                    "rte_eal_hotplug_remove failed (rc={rc}; errno={})",
                    errno()
                )
            }
            HotplugError::NoSuchPort(rc) => {
                write!(f, "rte_eth_dev_get_port_by_name failed (rc={rc})")
            }
        }
    }
}

impl std::error::Error for HotplugError {}

fn errno() -> i32 {
    // SAFETY: reads the per-lcore rte_errno via the C shim; no args, no aliasing.
    unsafe { dpdk_sys::nfkit_rte_errno() }
}

/// Hotplug-add a device to `busname` (e.g. `"vdev"`) with device name `devname` (e.g.
/// `"net_af_xdp3"`) and driver args `devargs` (e.g. `"iface=fpg3,start_queue=0,queue_count=1"`).
/// EAL identifies the driver from `devname` and probes it; the resulting ethdev port id is
/// resolved separately via [`port_by_name`].
///
/// # Errors
/// [`HotplugError::BadArg`] on an interior NUL; [`HotplugError::Add`] on a non-zero DPDK rc.
pub fn hotplug_add(busname: &str, devname: &str, devargs: &str) -> Result<(), HotplugError> {
    let bus = CString::new(busname).map_err(|_| HotplugError::BadArg)?;
    let dev = CString::new(devname).map_err(|_| HotplugError::BadArg)?;
    let args = CString::new(devargs).map_err(|_| HotplugError::BadArg)?;
    // SAFETY: three valid NUL-terminated C strings that outlive the call; DPDK only reads them
    // during the call. EAL must be initialized (caller holds the process-global EAL guard).
    let rc = unsafe { dpdk_sys::rte_eal_hotplug_add(bus.as_ptr(), dev.as_ptr(), args.as_ptr()) };
    if rc != 0 {
        return Err(HotplugError::Add(rc));
    }
    Ok(())
}

/// Hotplug-remove device `devname` from `busname`. Best-effort at the call site (recovery removes
/// a possibly-already-gone stale vdev before re-adding), but surfaces the rc for logging.
///
/// # Errors
/// [`HotplugError::BadArg`] on an interior NUL; [`HotplugError::Remove`] on a non-zero DPDK rc.
pub fn hotplug_remove(busname: &str, devname: &str) -> Result<(), HotplugError> {
    let bus = CString::new(busname).map_err(|_| HotplugError::BadArg)?;
    let dev = CString::new(devname).map_err(|_| HotplugError::BadArg)?;
    // SAFETY: two valid NUL-terminated C strings that outlive the call; DPDK only reads them
    // during the call. EAL must be initialized (caller holds the process-global EAL guard).
    let rc = unsafe { dpdk_sys::rte_eal_hotplug_remove(bus.as_ptr(), dev.as_ptr()) };
    if rc != 0 {
        return Err(HotplugError::Remove(rc));
    }
    Ok(())
}

/// Resolve the ethdev port id for a probed device `name` (the vdev's device name, e.g.
/// `"net_af_xdp3"`). Call after a successful [`hotplug_add`] to learn the port id to
/// `Port::configure`.
///
/// # Errors
/// [`HotplugError::BadArg`] on an interior NUL; [`HotplugError::NoSuchPort`] if no port matches.
pub fn port_by_name(name: &str) -> Result<u16, HotplugError> {
    let cname = CString::new(name).map_err(|_| HotplugError::BadArg)?;
    let mut port: u16 = 0;
    // SAFETY: `cname` is a valid NUL-terminated C string outliving the call; `port` is a valid
    // out-param. EAL must be initialized (caller holds the guard).
    let rc = unsafe { dpdk_sys::rte_eth_dev_get_port_by_name(cname.as_ptr(), &mut port) };
    if rc != 0 {
        return Err(HotplugError::NoSuchPort(rc));
    }
    Ok(port)
}
