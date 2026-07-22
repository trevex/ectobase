//! Raw DPDK FFI: bindgen over the public API + a C shim for the static-inline fast path.
//! All `unsafe`. Safe wrappers live in `nfkit`.
#![allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    unnecessary_transmutes,
    clippy::useless_transmute,
    clippy::unnecessary_cast,
    clippy::too_many_arguments,
    clippy::missing_safety_doc
)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
