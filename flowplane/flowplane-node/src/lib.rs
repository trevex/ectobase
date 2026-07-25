//! Shared DataplaneNode gRPC layer: the proto types (compiled once here) + parse helpers + the
//! per-RPC marshalling fns both the eBPF `flowplane` and DPDK `flowplane-dpdk` node services call.
//! Keeps the handler logic single-source. `flowplane-control` stays tonic-free; this crate is the
//! tonic layer on top of it.
//!
//! `result_large_err`: every handler returns `Result<_, tonic::Status>`; `Status` is large by design
//! (it carries the gRPC status + metadata). Allowed crate-wide, matching the two node services'
//! modules (`flowplane[-dpdk]/src/node.rs`).
#![allow(clippy::result_large_err)]

pub mod pb {
    tonic::include_proto!("dataplane.v1");
}

pub mod handlers;
pub mod parse;

pub use handlers::*;
pub use parse::*;

#[cfg(test)]
mod tests {
    #[test]
    fn proto_types_present() {
        let _ = super::pb::AddRouteRequest::default();
        let _ = super::pb::AddRouteResponse::default();
        let _ = super::pb::ConfigureQoSRequest::default();
    }
}
