use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const DPDK_VERSION: &str = "25.11.2";
// SHA-256 of the tarball — verified in Task 4 Step 2.
const DPDK_SHA256: &str = "418bfe3212640ee95a1cb10af6ed360cad2387686fe2721f8a3a9cd02d5ef4f2";
// Only the PMDs we need — keeps the DPDK build small/fast.
const DRIVERS: &str = "net/null,net/pcap,net/tap,net/af_xdp";

fn main() {
    // Escape hatch: a prebuilt DPDK prefix (nix/CI) skips the download+build entirely.
    let prefix = match env::var("DPDK_PREFIX") {
        Ok(p) => PathBuf::from(p),
        Err(_) => build_dpdk_cached(),
    };
    let pc_dir = prefix.join("lib/pkgconfig");

    // Emit static link flags for DPDK. We parse the installed .pc files directly rather than
    // using `pkg-config --static`, because the Nix-provided libpcap.pc has transitive deps
    // (libnl-genl-3.0) that aren't present in the devShell and cause `--static` to abort.
    // Strategy: emit the whole-archive PMD block from libdpdk.pc Libs.private, then the
    // shared core libs from libdpdk-libs.pc, then -lpcap/-lnuma/-lm/-ldl/-lpthread by name
    // (all available as shared libs in the nix devShell).
    emit_dpdk_link_flags(&prefix);

    // Expose the install prefix to downstream build scripts (e.g. nfkit) via DEP_DPDK_PREFIX.
    // Downstream crates with `links = "dpdk"` metadata deps can read this as the env var
    // DEP_DPDK_<KEY> where KEY is the uppercased key after "cargo:".
    println!("cargo:prefix={}", prefix.display());

    // Include paths + compile flags for the shim (cc) and bindgen.
    // We read cflags directly from the libdpdk-libs.pc file to get -march=corei7,
    // -include rte_config.h etc., without invoking pkg-config --static (which hits
    // the libnl-genl issue described above).
    let libs_pc_content =
        fs::read_to_string(pc_dir.join("libdpdk-libs.pc")).expect("libdpdk-libs.pc missing");
    let raw_cflags = parse_pc_field(&libs_pc_content, "Cflags");
    let include_dir = prefix.join("include");
    // Substitute pc file variables.
    let raw_cflags = raw_cflags
        .replace("${includedir}", include_dir.to_str().unwrap())
        .replace("${prefix}", prefix.to_str().unwrap());
    let cflags: Vec<String> = raw_cflags
        .split_whitespace()
        .map(|t| t.to_string())
        .collect();
    // Compile the C shim (exposes DPDK's static-inline fast path as real symbols).
    // Pass all DPDK cflags (includes, -march, -include rte_config.h) so inline functions compile.
    let mut build = cc::Build::new();
    build.file("shim.c");
    build.opt_level(2);
    for flag in &cflags {
        build.flag(flag);
    }
    build.compile("nfkit_shim");

    // Bindgen the public API + shim.
    // Notes on type handling:
    // - derive_debug/derive_default disabled globally: DPDK has packed structs containing
    //   #[repr(align)] types (E0588) and unions that can't implement Debug (E0277).
    // - opaque_type for rte_arp_* and rte_l2tpv2_combined_msg_hdr: these are `#[repr(packed)]`
    //   structs that transitively contain `#[repr(align)]` types, which Rust rejects (E0588).
    //   Making them opaque gives safe FFI blobs without layout issues.
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(&cflags)
        .allowlist_function("rte_.*")
        .allowlist_function("nfkit_.*")
        .allowlist_type("rte_.*")
        .allowlist_var("RTE_.*")
        .derive_debug(false)
        .derive_default(false)
        .opaque_type("rte_arp_ipv4")
        .opaque_type("rte_arp_hdr")
        .opaque_type("rte_l2tpv2_combined_msg_hdr")
        .generate()
        .expect("bindgen failed");
    bindings
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("write bindings");

    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=shim.h");
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-env-changed=DPDK_PREFIX");
    println!("cargo:rerun-if-env-changed=DPDK_CACHE_DIR");
    println!("cargo:rerun-if-env-changed=XDG_CACHE_HOME");
}

/// Download (once) + build (once) DPDK into a STABLE cache dir outside OUT_DIR, so `cargo clean`
/// does not force a re-download or rebuild. Returns the install prefix. Cache-keyed by version+config.
fn build_dpdk_cached() -> PathBuf {
    let root = cache_root();
    fs::create_dir_all(&root).unwrap();
    let tarball = root.join(format!("dpdk-{DPDK_VERSION}.tar.xz"));
    // The DPDK stable release tarball extracts to `dpdk-stable-{VERSION}/`.
    let srcdir = root.join(format!("dpdk-stable-{DPDK_VERSION}"));
    let key = short_hash(&format!("{DPDK_VERSION}|{DRIVERS}|static|generic"));
    let prefix = root.join(format!("install-{key}"));
    let stamp = prefix.join("lib/pkgconfig/libdpdk.pc");
    if stamp.exists() {
        return prefix; // CACHE HIT: no download, no build.
    }

    if !tarball.exists() {
        let url = format!("https://fast.dpdk.org/rel/dpdk-{DPDK_VERSION}.tar.xz");
        download(&url, &tarball);
    }
    verify_sha256(&tarball, DPDK_SHA256);
    if !srcdir.exists() {
        run(
            "tar",
            &[
                "-xf",
                tarball.to_str().unwrap(),
                "-C",
                root.to_str().unwrap(),
            ],
        );
    }

    // Install directly into the final prefix. DPDK embeds --prefix into the installed .pc files,
    // so an atomic tmp→rename approach would break pkg-config. Instead we use a sentinel
    // `.building` file: if it exists on entry, the previous build was interrupted — nuke and retry.
    // NOTE: the sentinel guards against interrupted builds but there is no cross-process file lock,
    // so two concurrent `cargo build -p dpdk-sys` could race the meson build (rare — dpdk-sys is
    // not in default-members so this only happens if invoked explicitly in parallel).
    let sentinel = root.join(format!("install-{key}.building"));
    if sentinel.exists() {
        // Interrupted build — clean up and retry.
        let _ = fs::remove_dir_all(&prefix);
    }
    fs::write(&sentinel, b"").unwrap();
    let build = srcdir.join(format!("build-{key}"));
    let _ = fs::remove_dir_all(&build);
    run(
        "meson",
        &[
            "setup",
            build.to_str().unwrap(),
            srcdir.to_str().unwrap(),
            &format!("--prefix={}", prefix.display()),
            "--default-library=static",
            "-Dplatform=generic", // portable, no -march=native
            "-Dtests=false",
            // Note: -Denable_kmods was removed in DPDK 25.x; kernel modules are always off
            // when building without kernel headers, which is the case in our nix devShell.
            "-Dexamples=",
            &format!("-Denable_drivers={DRIVERS}"),
        ],
    );
    run("ninja", &["-C", build.to_str().unwrap(), "install"]);
    // Build succeeded — remove the sentinel so we know the prefix is complete.
    let _ = fs::remove_file(&sentinel);
    prefix
}

fn cache_root() -> PathBuf {
    if let Ok(d) = env::var("DPDK_CACHE_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(d) = env::var("XDG_CACHE_HOME") {
        return PathBuf::from(d).join("dpdk-sys");
    }
    PathBuf::from(env::var("HOME").expect("HOME unset")).join(".cache/dpdk-sys")
}

fn download(url: &str, dest: &Path) {
    let tmp = dest.with_extension("part");
    let resp = ureq::get(url).call().expect("dpdk tarball download failed");
    let mut r = resp.into_reader();
    let mut f = fs::File::create(&tmp).unwrap();
    std::io::copy(&mut r, &mut f).unwrap();
    fs::rename(&tmp, dest).unwrap();
}

fn verify_sha256(path: &Path, expected: &str) {
    let bytes = fs::read(path).unwrap();
    let got = hex(&Sha256::digest(&bytes));
    assert_eq!(
        got,
        expected,
        "DPDK tarball checksum mismatch — expected {expected}, got {got}. Delete {} and retry.",
        path.display()
    );
}

/// Emit Cargo link directives for the DPDK static install at `prefix`.
///
/// We parse the installed `.pc` files directly rather than calling `pkg-config --static`, because
/// the Nix-provided `libpcap.pc` transitively requires `libnl-genl-3.0` for static mode — a lib
/// not present in the nix devShell. Instead we:
///   1. Emit the `-Wl,--whole-archive … -Wl,--no-whole-archive` PMD block from `libdpdk.pc`.
///   2. Emit the `-lrte_*` shared-mode core libs from `libdpdk-libs.pc`.
///   3. Emit `-lpcap -lnuma -lm -ldl -lpthread` (available as shared libs in the devShell).
fn emit_dpdk_link_flags(prefix: &Path) {
    let lib_dir = prefix.join("lib");
    let pc_dir = prefix.join("lib/pkgconfig");

    // Always add the DPDK lib dir to the search path.
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    // --- Parse libdpdk.pc to extract Libs.private (whole-archive block + system libs) ---
    let libdpdk_pc = fs::read_to_string(pc_dir.join("libdpdk.pc")).expect("libdpdk.pc missing");
    let libs_private = parse_pc_field(&libdpdk_pc, "Libs.private");
    // Substitute ${libdir} and ${prefix} variables.
    let libs_private = libs_private
        .replace("${libdir}", lib_dir.to_str().unwrap())
        .replace("${prefix}", prefix.to_str().unwrap());
    // Emit each token from Libs.private as a raw link arg (preserves -Wl,--whole-archive etc.)
    for tok in libs_private.split_whitespace() {
        if let Some(p) = tok.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={p}");
        } else {
            println!("cargo:rustc-link-arg={tok}");
        }
    }

    // --- Parse libdpdk-libs.pc Libs (the -lrte_* shared mode core libs) ---
    let libs_pc =
        fs::read_to_string(pc_dir.join("libdpdk-libs.pc")).expect("libdpdk-libs.pc missing");
    let libs_field = parse_pc_field(&libs_pc, "Libs");
    let libs_field = libs_field
        .replace("${libdir}", lib_dir.to_str().unwrap())
        .replace("${prefix}", prefix.to_str().unwrap());
    for tok in libs_field.split_whitespace() {
        if let Some(p) = tok.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={p}");
        } else {
            println!("cargo:rustc-link-arg={tok}");
        }
    }

    // --- System libs available as shared in the nix devShell ---
    // libpcap: shared lib; libnl-genl is only needed for static libpcap (not available in devShell).
    for lib in &["pcap", "numa", "m", "dl", "pthread"] {
        println!("cargo:rustc-link-lib={lib}");
    }

    // --- af_xdp PMD runtime deps: libbpf + libxdp ---
    // DPDK lists these in Requires.private (not Libs.private), so our custom pc parser misses them.
    // When net/af_xdp is enabled we emit their link dirs + libs directly via pkg-config.
    if DRIVERS.split(',').any(|d| d.trim() == "net/af_xdp") {
        emit_pkgconfig_link_flags("libbpf");
        emit_pkgconfig_link_flags("libxdp");
    }
}

/// Emit rustc-link-search + rustc-link-lib directives for a pkg-config package.
/// We parse `pkg-config --libs <pkg>` output (non-static: avoids the libelf/libnl issue)
/// and emit -L as link-search and -l as link-lib directives.
fn emit_pkgconfig_link_flags(pkg: &str) {
    let out = Command::new("pkg-config")
        .args(["--libs", pkg])
        .output()
        .unwrap_or_else(|e| panic!("pkg-config failed to start: {e}"));
    assert!(
        out.status.success(),
        "pkg-config --libs {pkg} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let flags = String::from_utf8_lossy(&out.stdout);
    for tok in flags.split_whitespace() {
        if let Some(p) = tok.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={p}");
        } else if let Some(l) = tok.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={l}");
        }
    }
}

/// Extract a single field value from a pkg-config `.pc` file (simple single-line fields only).
fn parse_pc_field(content: &str, field: &str) -> String {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{field}:")) {
            return rest.trim().to_string();
        }
    }
    String::new()
}

fn run(cmd: &str, args: &[&str]) {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("{cmd} failed to start: {e}"));
    assert!(status.success(), "{cmd} {:?} failed", args);
}

fn short_hash(s: &str) -> String {
    hex(&Sha256::digest(s.as_bytes()))[..16].to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
