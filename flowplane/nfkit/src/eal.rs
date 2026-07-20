//! Safe EAL lifecycle. `Eal::init` is the one entry point; the returned guard gates DPDK use
//! and calls `rte_eal_cleanup` on drop. Not `Send`/`Sync` (EAL is process-global, main-lcore).
use std::ffi::CString;
use std::marker::PhantomData;
use std::os::raw::c_char;

/// RAII guard proving EAL is initialized. `!Send + !Sync` via the `PhantomData` marker.
pub struct Eal {
    _not_send: PhantomData<*const ()>,
}

#[derive(Debug)]
pub enum EalError {
    /// rte_eal_init returned < 0 (see rte_errno).
    Init(i32),
    /// An arg contained an interior NUL.
    BadArg,
}

impl Eal {
    /// Initialize EAL with the given argv (including argv[0] program name). Safe wrapper:
    /// converts args, calls `rte_eal_init`, and on success returns a guard.
    pub fn init<I, S>(args: I) -> Result<Eal, EalError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let cstrings: Vec<CString> = args
            .into_iter()
            .map(|s| CString::new(s.as_ref()).map_err(|_| EalError::BadArg))
            .collect::<Result<_, _>>()?;
        let mut ptrs: Vec<*mut c_char> =
            cstrings.iter().map(|c| c.as_ptr() as *mut c_char).collect();

        // SAFETY: `ptrs` points to `ptrs.len()` valid, NUL-terminated C strings that outlive the
        // call (owned by `cstrings`). rte_eal_init only reads them during the call.
        let rc = unsafe { dpdk_sys::rte_eal_init(ptrs.len() as i32, ptrs.as_mut_ptr()) };
        if rc < 0 {
            return Err(EalError::Init(rc));
        }
        Ok(Eal {
            _not_send: PhantomData,
        })
    }

    /// Number of probed ethdev ports.
    pub fn port_count(&self) -> u16 {
        // SAFETY: EAL is initialized (we hold the guard); the fn takes no args and reads global state.
        unsafe { dpdk_sys::rte_eth_dev_count_avail() }
    }
}

impl Drop for Eal {
    fn drop(&mut self) {
        // SAFETY: EAL was initialized; cleanup is the documented teardown and is idempotent-safe here
        // because only one Eal exists at a time (single init in practice).
        unsafe {
            dpdk_sys::rte_eal_cleanup();
        }
    }
}
