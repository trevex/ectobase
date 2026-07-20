//! Per-lcore run-to-completion launcher. `for_each_worker` runs a closure on the first `n_workers`
//! WORKER lcores (all EAL lcores except the main one), passing a 0-based `queue_id`, and joins
//! before returning.
use std::os::raw::c_void;

/// The trampoline the C worker thread calls. `arg` points to a `WorkerArg`.
extern "C" fn trampoline(arg: *mut c_void) -> i32 {
    // SAFETY: `arg` is a `*mut WorkerArg` we passed to rte_eal_remote_launch; it lives on the
    // launching thread's stack for the whole scope (we join before returning), and exactly one
    // worker thread reads it. We must NOT unwind across the C boundary — catch any panic + abort.
    let wa = unsafe { &*(arg as *const WorkerArg) };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (wa.func)(wa.queue_id);
    }));
    if result.is_err() {
        eprintln!(
            "nfkit: worker lcore (queue {}) panicked; aborting",
            wa.queue_id
        );
        std::process::abort();
    }
    0
}

struct WorkerArg<'a> {
    func: &'a (dyn Fn(u16) + Sync),
    queue_id: u16,
}

/// Launcher for per-lcore workers.
pub struct LcoreRuntime;

impl LcoreRuntime {
    /// Run `func(queue_id)` on the first `n_workers` worker lcores (0-based `queue_id`), then join
    /// all. Blocks until every launched worker returns. `func` must be `Sync`. Callers pass
    /// `n_workers = port.n_queues()` so each worker owns a distinct queue.
    pub fn for_each_worker<F: Fn(u16) + Sync>(n_workers: u16, func: F) {
        // WorkerArgs live on THIS stack frame for the whole call; we join (mp_wait_lcore) before
        // returning, so the references stay valid for every worker.
        let dynf: &(dyn Fn(u16) + Sync) = &func;
        let mut args: Vec<WorkerArg> = Vec::new();
        let mut lcores: Vec<u32> = Vec::new();
        // SAFETY: enumerate EAL worker lcores (skip main): rte_get_next_lcore(prev, skip_main=1, wrap=0).
        unsafe {
            let mut q: u16 = 0;
            let mut lc = dpdk_sys::rte_get_next_lcore(u32::MAX, 1, 0);
            while lc < dpdk_sys::RTE_MAX_LCORE && q < n_workers {
                lcores.push(lc);
                args.push(WorkerArg {
                    func: dynf,
                    queue_id: q,
                });
                q += 1;
                lc = dpdk_sys::rte_get_next_lcore(lc, 1, 0);
            }
            // args is fully built (no realloc) before we take pointers into it.
            for (i, &lc) in lcores.iter().enumerate() {
                let ptr = &args[i] as *const WorkerArg as *mut c_void;
                let rc = dpdk_sys::rte_eal_remote_launch(Some(trampoline), ptr, lc);
                assert_eq!(rc, 0, "rte_eal_remote_launch failed for lcore {lc}");
            }
            // Join ALL workers before args/func go out of scope.
            dpdk_sys::rte_eal_mp_wait_lcore();
        }
    }
}

/// Count of EAL worker lcores (all lcores except the main one). Use to size the queue request.
#[must_use]
pub fn worker_lcore_count() -> u16 {
    let mut n = 0u16;
    // SAFETY: read-only lcore enumeration after EAL init.
    unsafe {
        let mut lc = dpdk_sys::rte_get_next_lcore(u32::MAX, 1, 0);
        while lc < dpdk_sys::RTE_MAX_LCORE {
            n += 1;
            lc = dpdk_sys::rte_get_next_lcore(lc, 1, 0);
        }
    }
    n
}
