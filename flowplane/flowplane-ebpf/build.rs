use which::which;

// aya-build links the object with `bpf-linker`. This rebuild hint (mirrored from the aya
// template) re-runs the build when the resolved bpf-linker binary changes.
fn main() {
    let bpf_linker = which("bpf-linker").expect("bpf-linker not found in PATH");
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
