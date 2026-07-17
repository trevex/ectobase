# syntax=docker/dockerfile:1
#
# Container image for the `flowplane` XDP datapath binary.
#
# The eBPF object is compiled by aya-build (via bpf-linker) and include_bytes!-baked into
# the flowplane binary at build time; the runtime image therefore needs ONLY that one binary.
#
# Toolchain pinning is version-sensitive (see rust-toolchain.toml):
#   * rustc nightly-2026-01-15 emits LLVM 21 bitcode.
#   * bpf-linker MUST be built against the SAME LLVM major (21), or aya-build fails with
#     "ERROR llvm: Invalid record". We install LLVM/clang 21 from apt.llvm.org and build
#     bpf-linker against it via LLVM_SYS_211_PREFIX.

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
FROM debian:bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Base build tooling. protobuf-compiler is required by tonic-build/prost-build (build.rs
# compiles proto/dpdk.proto and there is no vendored protoc in Cargo.lock).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg \
        build-essential pkg-config \
        protobuf-compiler \
        libssl-dev zlib1g-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

# LLVM 21 + clang 21 from apt.llvm.org (bookworm). bpf-linker links against the system
# LLVM, so the -dev libraries must be present and must be major version 21 to match the
# LLVM 21 bitcode rustc nightly-2026-01-15 emits.
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/llvm.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-21 main" \
        > /etc/apt/sources.list.d/llvm-21.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        llvm-21 llvm-21-dev libpolly-21-dev clang-21 libclang-21-dev \
    && rm -rf /var/lib/apt/lists/*

ENV LLVM_SYS_211_PREFIX=/usr/lib/llvm-21
ENV PATH=/usr/lib/llvm-21/bin:/root/.cargo/bin:${PATH}

# rustup + the pinned nightly with rust-src (rust-src is required for `-Z build-std=core`
# on the bpfel target, which has no prebuilt std).
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain none --profile minimal \
    && rustup toolchain install nightly-2026-01-15 \
        --profile minimal --component rust-src

# bpf-linker, linked against the LLVM 21 dev libs installed above (via LLVM_SYS_211_PREFIX).
# NOTE: do NOT pass --no-default-features here — bpf-linker's default features include the
# code it needs (dropping them gives ~67 unresolved-name compile errors); llvm-sys already
# uses the system LLVM via LLVM_SYS_211_PREFIX, so default features link system LLVM 21.
RUN cargo +nightly-2026-01-15 install bpf-linker --locked

WORKDIR /src
COPY . .

# Build only the flowplane host binary; aya-build (invoked from its build.rs) compiles and
# bakes in the eBPF object. The bin name differs from the package so the build never tries
# to compile the #![no_main] eBPF bin on the host target.
RUN cargo +nightly-2026-01-15 build --release -p flowplane \
    && cp target/release/flowplane /flowplane \
    && strip /flowplane

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
# debian:bookworm-slim (matches the builder's glibc) + iproute2. iproute2 is included so the SAME
# image can run the tap-pool init container (`ip tuntap add ...` to create the kernel taps DPDK's
# net_tap PMD used to make) AND the datapath (`flowplane serve`) — one image, no extra init image.
FROM debian:bookworm-slim

# iproute2 for veth/netns setup; ethtool to disable tx-checksum offload on guest veths (their
# CHECKSUM_PARTIAL packets would otherwise be encapped with a stale/partial inner L4 checksum).
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 ethtool \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /flowplane /usr/local/bin/flowplane

ENTRYPOINT ["/usr/local/bin/flowplane"]
