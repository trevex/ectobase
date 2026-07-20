// LcoreRuntime runs a worker closure on the first N worker lcores and joins. With `-l 0-1`, main
// is lcore 0 and there is one worker (lcore 1) -> queue_id 0. --test-threads=1.
use nfkit::{Eal, LcoreRuntime};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[test]
fn runtime_runs_worker_on_each_lcore() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0-1",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_rt",
    ])
    .expect("EAL init");
    let ran = AtomicU32::new(0);
    LcoreRuntime::for_each_worker(1, |queue_id| {
        ran.fetch_add(1u32 << queue_id, Ordering::SeqCst);
    });
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "exactly one worker (queue 0) ran and joined"
    );

    // n_workers == 0 launches nothing and returns immediately (must not call the closure).
    let zero_ran = AtomicBool::new(false);
    LcoreRuntime::for_each_worker(0, |_| zero_ran.store(true, Ordering::SeqCst));
    assert!(
        !zero_ran.load(Ordering::SeqCst),
        "n_workers=0 must not run any worker"
    );
}
