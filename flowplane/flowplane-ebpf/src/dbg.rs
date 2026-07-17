//! Compile-time-gated debug logging for the datapath.
//!
//! `dlog!(&ctx, "msg {}", val)` expands to an `aya-log` `info!` call ONLY when the crate is
//! built with `--features debug`; otherwise it compiles to nothing (no map, no instructions,
//! no verifier cost). This keeps production objects lean while giving us a one-flag way to
//! trace the datapath when diagnosing issues like "does native XDP even run on this RX path?".
//!
//! When enabled, messages surface in the userspace dpservice logs — the loader installs an
//! `EbpfLogger` when `FLOWPLANE_DEBUG=1` (see `flowplane`'s loader). So a debug image must ALSO be
//! run with `FLOWPLANE_DEBUG=1` for the lines to appear; the env var alone (non-debug image) is a
//! no-op because the `AYA_LOGS` map isn't present.

#[cfg(feature = "debug")]
macro_rules! dlog {
    ($ctx:expr, $($arg:tt)+) => {
        ::aya_log_ebpf::info!($ctx, $($arg)+)
    };
}

#[cfg(not(feature = "debug"))]
macro_rules! dlog {
    ($ctx:expr, $($arg:tt)+) => {{
        // Reference the context so callers compile identically in both configs, but emit nothing.
        let _ = &$ctx;
    }};
}

pub(crate) use dlog;
