fn main() {
    tonic_build::configure()
        .build_client(false)
        .compile_protos(
            &["../../api/proto/dataplane/v1/dataplane.proto"],
            &["../../api/proto/dataplane/v1"],
        )
        .expect("tonic-build compile dataplane protos");
    println!("cargo:rerun-if-changed=../../api/proto/dataplane/v1");
}
