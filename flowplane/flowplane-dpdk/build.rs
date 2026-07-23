//! flowplane-dpdk build script: re-emit DPDK link flags so this crate's bin + test binaries link.
//!
//! Identical in effect to `nfkit/build.rs`: dpdk-sys emits `cargo:prefix=<path>` (readable as
//! `DEP_DPDK_PREFIX` by direct dependents); we re-parse the same `.pc` files and re-emit the full
//! static link graph. A build-support crate would DRY this with nfkit/dpdk-sys in a later milestone.
use std::{env, fs, path::Path};

fn main() {
    let prefix = env::var("DEP_DPDK_PREFIX").expect(
        "DEP_DPDK_PREFIX not set — dpdk-sys must emit `cargo:prefix=<path>` from its build.rs",
    );
    let prefix = Path::new(&prefix);
    emit_dpdk_link_flags(prefix);

    println!("cargo:rerun-if-env-changed=DEP_DPDK_PREFIX");
}

fn emit_dpdk_link_flags(prefix: &Path) {
    let lib_dir = prefix.join("lib");
    let pc_dir = prefix.join("lib/pkgconfig");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    // Libs.private from libdpdk.pc — the whole-archive PMD block.
    let libdpdk_pc = fs::read_to_string(pc_dir.join("libdpdk.pc")).expect("libdpdk.pc missing");
    let libs_private = parse_pc_field(&libdpdk_pc, "Libs.private")
        .replace("${libdir}", lib_dir.to_str().unwrap())
        .replace("${prefix}", prefix.to_str().unwrap());
    for tok in libs_private.split_whitespace() {
        if let Some(p) = tok.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={p}");
        } else {
            println!("cargo:rustc-link-arg={tok}");
        }
    }

    // Libs from libdpdk-libs.pc — the -lrte_* shared-mode core libs.
    let libs_pc =
        fs::read_to_string(pc_dir.join("libdpdk-libs.pc")).expect("libdpdk-libs.pc missing");
    let libs_field = parse_pc_field(&libs_pc, "Libs")
        .replace("${libdir}", lib_dir.to_str().unwrap())
        .replace("${prefix}", prefix.to_str().unwrap());
    for tok in libs_field.split_whitespace() {
        if let Some(p) = tok.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={p}");
        } else {
            println!("cargo:rustc-link-arg={tok}");
        }
    }

    // System libs available as shared in the nix devShell (see nfkit/build.rs for rationale).
    for lib in &["pcap", "bpf", "xdp", "numa"] {
        println!("cargo:rustc-link-arg=-l{lib}");
    }
    for lib in &["m", "dl", "pthread"] {
        println!("cargo:rustc-link-lib={lib}");
    }
}

fn parse_pc_field(content: &str, field: &str) -> String {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{field}:")) {
            return rest.trim().to_string();
        }
    }
    String::new()
}
