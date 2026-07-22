//! Safe EAL lifecycle. `Eal::init` is the one entry point; the returned guard gates DPDK use
//! and calls `rte_eal_cleanup` on drop. Not `Send`/`Sync` (EAL is process-global, main-lcore).
use std::ffi::CString;
use std::marker::PhantomData;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};

/// Process-wide guard: set to `true` after the first successful `rte_eal_init` call.
/// DPDK does not support calling `rte_eal_init` more than once per process — a second call
/// is undefined behaviour. The flag lets the safe API reject it without touching DPDK.
/// NOTE: never reset after cleanup — DPDK does not support re-init after `rte_eal_cleanup`.
static EAL_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// RAII guard proving EAL is initialized.
///
/// `!Send + !Sync` (via the `PhantomData<*const ()>` marker) because:
///
/// * DPDK EAL init must run on the thread that becomes the **main lcore**. Moving this guard
///   to another thread after init would violate that invariant.
/// * Many `rte_*` fast-path APIs are lcore-affine and must be called from the lcore thread
///   they were configured for. `!Send + !Sync` prevents safe code from moving the guard to a
///   different thread and then calling lcore-sensitive APIs from there.
#[derive(Debug)]
pub struct Eal {
    _not_send: PhantomData<*const ()>,
}

#[derive(Debug)]
pub enum EalError {
    /// `rte_eal_init` returned < 0 (see rte_errno).
    Init(i32),
    /// An argument contained an interior NUL byte.
    BadArg,
    /// `Eal::init` was already called in this process (DPDK supports EAL init at most once).
    AlreadyInit,
}

impl std::fmt::Display for EalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EalError::Init(rc) => write!(f, "rte_eal_init failed (rc={rc}; check rte_errno)"),
            EalError::BadArg => write!(f, "EAL argument contains an interior NUL byte"),
            EalError::AlreadyInit => {
                write!(f, "EAL has already been initialized in this process")
            }
        }
    }
}

impl std::error::Error for EalError {}

impl Eal {
    /// Initialize EAL with the given argv (including argv[0] program name). Safe wrapper:
    /// converts args, calls `rte_eal_init`, and on success returns a guard.
    ///
    /// Returns `Err(EalError::AlreadyInit)` if called more than once per process.
    pub fn init<I, S>(args: I) -> Result<Eal, EalError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // Claim the process-wide init slot before touching DPDK at all.
        // On failure (flag was already true) another Eal is alive — reject immediately.
        if EAL_INITIALIZED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(EalError::AlreadyInit);
        }

        let cstrings: Result<Vec<CString>, EalError> = args
            .into_iter()
            .map(|s| CString::new(s.as_ref()).map_err(|_| EalError::BadArg))
            .collect();
        let cstrings = match cstrings {
            Ok(v) => v,
            Err(e) => {
                // Release the slot — we haven't touched DPDK yet, so a retry with valid args
                // is sensible.
                EAL_INITIALIZED.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };
        let mut ptrs: Vec<*mut c_char> =
            cstrings.iter().map(|c| c.as_ptr() as *mut c_char).collect();

        // SAFETY: `ptrs` points to `ptrs.len()` valid, NUL-terminated C strings that outlive the
        // call (owned by `cstrings`). rte_eal_init only reads them during the call.
        let rc = unsafe { dpdk_sys::rte_eal_init(ptrs.len() as i32, ptrs.as_mut_ptr()) };
        if rc < 0 {
            // Release the slot so the caller can retry (DPDK documents EAGAIN as retryable
            // when rc < 0 and rte_errno == EAGAIN).
            EAL_INITIALIZED.store(false, Ordering::SeqCst);
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
        // SAFETY: `Eal` is only constructed by `Eal::init` after `rte_eal_init` returned rc >= 0,
        // so Drop runs only after a successful init. The process-wide EAL_INITIALIZED guard ensures
        // at most one live `Eal`, so this is the sole owner performing teardown. rte_eal_cleanup is
        // not reset in the guard because DPDK does not support re-init after cleanup.
        let rc = unsafe { dpdk_sys::rte_eal_cleanup() };
        if rc != 0 {
            eprintln!("nfkit: rte_eal_cleanup failed (rc={rc})");
        }
    }
}
