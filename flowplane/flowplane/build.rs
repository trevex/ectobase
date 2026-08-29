use anyhow::{anyhow, Context as _};
use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    // 1) Compile the eBPF object via aya-build.
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("cargo metadata")?;
    let ebpf = metadata
        .packages
        .into_iter()
        .find(|p| p.name.as_str() == "flowplane-ebpf")
        .ok_or_else(|| anyhow!("flowplane-ebpf package not found"))?;
    let root_dir = ebpf
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent dir for {}", ebpf.manifest_path))?
        .to_string();
    // Propagate our `debug` feature to the eBPF crate so `cargo build -p flowplane --features debug`
    // (or `make image FEATURES=debug`) compiles in the `dlog!` aya-log tracing. cargo sets
    // CARGO_FEATURE_DEBUG when this crate's `debug` feature is active.
    let ebpf_features: &[&str] = if std::env::var_os("CARGO_FEATURE_DEBUG").is_some() {
        &["debug"]
    } else {
        &[]
    };
    aya_build::build_ebpf(
        [Package {
            name: "flowplane-ebpf",
            root_dir: root_dir.as_str(),
            features: ebpf_features,
            ..Default::default()
        }],
        Toolchain::Custom("nightly-2026-01-15"),
    )?;
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEBUG");

    // Re-run aya-build when the eBPF crate sources change. cargo would otherwise NOT re-run this
    // build.rs on edits to flowplane-ebpf/src/*.rs (the build-dependency edge only covers that
    // crate's lib target, not its bin), leaving a stale embedded object.
    println!("cargo:rerun-if-changed=../flowplane-ebpf/src");
    println!("cargo:rerun-if-changed=../flowplane-ebpf/Cargo.toml");

    // 2) Compile the DataplaneNode gRPC proto (server + client stubs) into `pb` (src/main.rs).
    // Generate the client stub too: e2e test harnesses drive a running DataplaneNode over gRPC via
    // `pb::dataplane_node_client::DataplaneNodeClient`.
    tonic_build::configure()
        .build_client(true)
        .compile_protos(
            &["../../api/proto/dataplane/v1/dataplane.proto"],
            &["../../api/proto/dataplane/v1"],
        )
        .expect("tonic-build compile dataplane protos");
    println!("cargo:rerun-if-changed=../../api/proto/dataplane/v1");

    Ok(())
}
