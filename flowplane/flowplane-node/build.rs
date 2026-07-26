fn main() {
    tonic_build::configure()
        // Generate the client stub too: the DPDK full-serve af_xdp e2e harness
        // (`flowplane-dpdk/examples/attach_client.rs`) drives a running DataplaneNode over gRPC via
        // `pb::dataplane_node_client::DataplaneNodeClient`. Purely additive — no existing consumer
        // depends on the client, and the server codegen is unchanged.
        .build_client(true)
        .compile_protos(
            &["../../api/proto/dataplane/v1/dataplane.proto"],
            &["../../api/proto/dataplane/v1"],
        )
        .expect("tonic-build compile dataplane protos");
    println!("cargo:rerun-if-changed=../../api/proto/dataplane/v1");
}
