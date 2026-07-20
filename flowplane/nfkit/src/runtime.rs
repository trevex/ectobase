//! Per-lcore run-to-completion launcher. `for_each_worker` runs a closure on the first `n_workers`
//! WORKER lcores (all EAL lcores except the main one), passing a 0-based `queue_id`, and joins
//! before returning.
use std::os::raw::c_void;

/// The trampoline the C worker thread calls. `arg` points to a `WorkerArg`.
extern "C" fn trampoline(arg: *mut c_void) -> i32 {
    // SAFETY: `arg` is a `*mut WorkerArg` we passed to rte_eal_remote_launch; it lives on the
    // launching thread's stack for the whole scope (we join before returning), and exactly one
    // worker thread reads it. We must NOT unwind across the C boundary — catch any panic + abort.
    // This validity depends on the launcher not unwinding between launch and join; the launcher
    // aborts rather than panics for exactly this reason.
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
        debug_assert!(
            n_workers <= worker_lcore_count(),
            "n_workers={n_workers} exceeds worker lcores={}",
            worker_lcore_count()
        );
        // WorkerArgs live on THIS stack frame for the whole call; we join (mp_wait_lcore) before
        // returning, so the references stay valid for every worker.
        let dynf: &(dyn Fn(u16) + Sync) = &func;
        let mut args: Vec<WorkerArg> = Vec::new();
        let mut lcores: Vec<u32> = Vec::new();
        // SAFETY: (1) rte_get_next_lcore enumerates EAL worker lcores (skip_main=1). (2) We pass
        // raw pointers into `args` to worker threads; this is sound because `args` is fully built
        // before the launch loop (no realloc invalidates the pointers) AND every worker is joined
        // by rte_eal_mp_wait_lcore() before `args`/`func` go out of scope. Any early exit between
        // launch and join would be UB — hence the abort (not panic) on a launch failure below.
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
                let ptr = &args[i] as *const WorkerArg as *mut c_void; // cast to *mut required by the C `void*` ABI; the trampoline only reads via *const, no mutation.
                let rc = dpdk_sys::rte_eal_remote_launch(Some(trampoline), ptr, lc);
                if rc != 0 {
                    // A launch failure here is fatal misconfiguration. We MUST NOT unwind: workers
                    // already launched hold raw pointers into `args`; unwinding would drop `args`
                    // (UAF). Abort instead — consistent with the trampoline's panic-abort.
                    eprintln!("nfkit: rte_eal_remote_launch failed for lcore {lc}: {rc}; aborting");
                    std::process::abort();
                }
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
