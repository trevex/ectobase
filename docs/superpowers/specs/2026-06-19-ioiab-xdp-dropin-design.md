# ioiab Drop-In: flowplane Replacing dpservice — Design

**Status:** proposed
**Date:** 2026-06-19
**Goal:** Run `flowplane` as a drop-in replacement for dpservice inside a forked ironcore-in-a-box, and prove it end-to-end: `make up`, then one guest VM boots, gets its address via our in-XDP DHCP, and pings the gateway / a second VM.

## Decisions (locked)

- **Milestone / definition of done:** one VM boots → DHCPs → pings (a live, end-to-end drop-in proof).
- **Tap model:** **option 2 — attach to externally-created taps.** Source investigation of dpservice v0.3.22 + metalnet v0.3.16 confirmed the whole stack is built around the dataplane *attaching to a fixed, externally-named tap pool*: metalnet hardcodes `dtapvf_0..3`, supplies the name via `CreateInterface(device_name=…)`, and libvirt binds the VM to that name via macvtap `direct`. dpservice does not create taps — DPDK's `net_tap` PMD does (the `--vdev` lines), for both the VF taps and the PF taps `dtap0`/`dtap1`. **`flowplane` already implements this exact attach-only contract** (`control.rs::create_interface` reads `/sys/class/net/<dev>/ifindex`, errors `NOT_FOUND` if absent). So we need **zero** flowplane tap-creation changes and **zero** metalnet changes; we only need *something* to create the kernel tap pool before flowplane serves (the job DPDK used to do).
- **Fork + image:** work on a **branch in the existing `/home/nik/Development/ironcore-in-a-box` checkout**; build the flowplane container with a **multi-stage Dockerfile** (not Nix dockerTools).

## The seam (what we keep vs replace)

Keep, unchanged: the gRPC contract on `:1337` (DPDKironcore v0.3.22, which flowplane targets), the `dtap0`/`dtap1` PF + `dtapvf_0..3` VF naming, the DHCP/underlay flag *shape* (flowplane's `serve` arg list was deliberately built to accept dpservice's flags), metalnet, metalnetlet, apinet, libvirt-provider, metalbond. Replace: the dpservice DaemonSet workload (image + command + DPDK prerequisites).

`flowplane serve` flags (from `flowplane/src/main.rs`): `--addr`, `--uplink`, `--local-underlay`, `--gateway-mac`, `--gateway` (overlay v4 GW for ARP), `--gateway6` (overlay v6 GW for ND), `--dhcp-mtu`, `--dhcp-dns` (repeatable), `--dhcpv6-dns` (repeatable), `--pin-dir`, `--conntrack-max`.

## Components

### 1. Container image (`Dockerfile`, in the flowplane repo)

Multi-stage:
- **builder:** pin the eBPF toolchain the repo uses — Rust `nightly-2026-01-15` + `rust-src`, `bpf-linker`, LLVM 21/clang (aya-build invokes bpf-linker; the eBPF object is compiled and `include_bytes!`-baked into the `flowplane` binary). `cargo build --release -p flowplane`.
- **runtime:** minimal (`debian:bookworm-slim` or distroless/cc); copy the single `flowplane` binary. No DPDK, no hugepages, no DPDK kernel modules.

Runtime needs at deploy time: `CAP_BPF` + `CAP_NET_ADMIN` (+ `CAP_SYS_ADMIN`/`CAP_PERFMON` if the kernel requires it for XDP/map ops), `hostNetwork: true` (attach XDP to the node's netdevs), and kernel BTF at `/sys/kernel/btf/vmlinux` (present on the host kernel; the kind node container shares it).

**Risk:** reproducing the pinned eBPF toolchain (LLVM 21 + bpf-linker + nightly) in a Dockerfile builder is the main build-effort item. Fallback if the in-Docker build is troublesome: build the binary on the host via the existing `nix develop` shell and `COPY` it into a runtime-only Dockerfile (still "a Dockerfile", just not self-building).

### 2. ioiab DaemonSet patch (`base/dpservice/…` on the fork)

Replace the upstream `github.com/ironcore-dev/dpservice/config/default?ref=v0.3.22` base + `dpservice-tap.yaml` patch with an flowplane DaemonSet that:
- uses our image,
- drops all DPDK EAL args (`-l`, `--no-huge`, `-m`, `--no-pci`, `--vdev=…`) and hugepage/temp mounts,
- runs (mapping dpservice's ioiab flags 1:1):
  ```
  flowplane serve \
    --addr [::]:1337 \
    --uplink dtap0 \
    --local-underlay 2001:db8:fefe::1 \
    --gateway 169.254.0.1 \
    --gateway6 fe80::1 \
    --gateway-mac <underlay-next-hop-mac> \
    --dhcp-mtu 1450 \
    --dhcp-dns 8.8.4.4 --dhcp-dns 8.8.8.8 \
    --dhcpv6-dns 2001:4860:4860::6464 --dhcpv6-dns 2002:4861:4861::6464
  ```
- sets `securityContext.capabilities` (BPF/NET_ADMIN/…), `hostNetwork: true`, `hostPID` if needed, and a readiness probe on `:1337` (gRPC) so libvirt-provider's "wait for dataplane ready" ordering still holds.
- keeps the namespace `dpservice-system` and DaemonSet name so metalnetlet's discovery (localhost:1337 / service) is unchanged.

### 3. Init container — create the kernel tap pool (the DPDK-replacement job)

An initContainer (privileged, `NET_ADMIN`, hostNetwork, in the node netns) that creates the taps DPDK used to materialize, with the **same names and MACs** so metalnet's hardcoded pool and libvirt's by-name binding keep working:
```
ip tuntap add dev dtap0     mode tap ; ip link set dtap0     address 22:22:22:22:22:00 ; ip link set dtap0 up
ip tuntap add dev dtap1     mode tap ; ip link set dtap1     address 22:22:22:22:22:01 ; ip link set dtap1 up
ip tuntap add dev dtapvf_0  mode tap ; ip link set dtapvf_0  address 66:66:66:66:66:00 ; ip link set dtapvf_0 up
… dtapvf_1..3 (66:66:66:66:66:01..03) …
```
Idempotent (skip if present). This runs before the flowplane container, which then attaches `uplink_rx` to `dtap0` and `guest_tx` to each `dtapvf_N` as metalnet calls `CreateInterface`.

### 4. setup-network + single-node underlay

ioiab's `hack/setup-network.sh` configures `dtap0` (e.g. `ip -6 route add 2001:db8:fefe::/48 via fe80::1 dev dtap0`) and waits for the dataplane to bring `dtap0` up. With the init container creating `dtap0` up-front, that wait is satisfied. In a **single-node** kind cluster there is no remote hypervisor, so guest-to-guest traffic uses flowplane's **local fast path** (the `LOCAL`/`UNDERLAY` maps deliver to the peer tap on the same host without real encap egress). The `--gateway-mac` is then a placeholder (no real encap leaves the node). This must be validated (see Risks).

## Milestone test (definition of done)

1. `make up` on the fork → all pods Ready, flowplane DaemonSet Ready on `:1337`, metalnetlet connected.
2. Create a `Network` + `Machine` + `NetworkInterface` (the ioiab example / BATS path).
3. The VM boots (libvirt-provider), its NIC binds to a `dtapvf_N` (macvtap direct), metalnet `CreateInterface` succeeds, flowplane attaches `guest_tx`.
4. **DHCP:** the guest gets its IPv4 (and IPv6) lease from our in-XDP DHCP responder.
5. **Connectivity:** the guest pings the overlay gateway (`169.254.0.1` / `fe80::1`, answered by our ARP/ND responder) and a second VM on the same network.

## Risks / discovery (validate early, before building the full deployment)

- **R1 (highest): macvtap-direct over an XDP-bound tap.** libvirt binds the VM via macvtap `direct` *on top of* `dtapvf_N`, while flowplane attaches `guest_tx` (XDP) to `dtapvf_N` itself. dpservice owned the tap fd directly (DPDK); here a macvtap is stacked on the lower tap. **Must verify XDP on the lower tap sees the VM's egress frames** (and that our `XDP_TX`/redirect replies reach the VM). This is the single biggest unknown — prototype it in isolation (one tap + a macvtap + a netns "VM" + flowplane) before wiring the whole cluster.
- **R2: kind node kernel / XDP.** kind nodes are containers on the host kernel (7.0.11, which we know supports the verifier/BTF). Confirm XDP attach + BPF maps work from inside the pod (CAP_BPF, `/sys/kernel/btf` visible). SKB vs native mode on taps (our DHCP grows frames; taps support native `adjust_tail`, proven by `tap-dhcp-probe`).
- **R3: single-node underlay semantics.** Confirm guest-to-guest works via the local fast path with no real encap egress, and that `--gateway-mac`/`--local-underlay` placeholders don't break the path. If ioiab expects a real underlay hop, decide what `dtap1`/the underlay route point at.
- **R4: readiness/ordering.** libvirt-provider waits on dataplane readiness; ensure the `:1337` gRPC readiness probe + init-container ordering reproduce dpservice's startup contract.
- **R5: Dockerfile eBPF toolchain** (see Component 1).

## Out of scope (this milestone)

Multi-node underlay/encap across real hosts, the full BATS suite, VPC/multi-VNI/NAT/LB parity in-cluster (our conformance suite already covers the datapath; in-ioiab parity beyond "one VM boots/DHCPs/pings" is a later milestone), and upstreaming to ironcore-dev.

## Suggested sequencing

Because R1 (macvtap-over-XDP-tap) can invalidate the whole approach, validate it **first** as a standalone prototype, then build the image, then the manifests, then `make up` and the VM test. The plan should front-load R1.

---

## Resolved (2026-06-19) — execution decisions

**R1 outcome — option 1 (plain tap) chosen.** macvtap is structurally incompatible with an XDP dataplane: macvtap turns guest *egress* into a TX on the lower device, and XDP is an RX-only hook, so `guest_tx` would never see guest traffic. A plain tap (qemu owns the fd → guest egress = RX on the tap) is the natural, already-proven model (our conformance + netns harness inject exactly this way). dpservice only needs macvtap because it's a userspace DPDK dataplane that reads the tap fd directly.

**libvirt-provider change is SELECTABLE, not a replacement.** Add a plain-tap NIC binding (`<interface type='ethernet'><target dev='dtapvf_N' managed='no'/>`) to libvirt-provider as an opt-in mode, **defaulting to the existing macvtap (`type='direct'`)** so the fork still works unmodified for the DPDK dpservice. Mechanism: a CLI flag (e.g. `--network-interface-direct-mode=macvtap|tap`, default `macvtap`) threaded to the `nic.Direct` branch of `providerNetworkInterfaceToLibvirt` (`internal/controllers/machine_controller_nics.go`), plus the matching inverse parser. No CRD/plugin-interface changes.

**Forks & registry (all under github.com/trevex):**
- `flowplane` datapath → repo `trevex/ectobase/flowplane`, local `/home/nik/Development/ironcore-net-xdp` (origin already `trevex/ectobase/flowplane`). Image: **`ghcr.io/trevex/ectobase/flowplane`** (new `Dockerfile`).
- libvirt-provider fork → repo `trevex/libvirt-provider-tap`, local `/home/nik/Development/libvirt-provider-tap` (has `Dockerfile` + `Makefile` `docker-build`/`docker-push`). Image: **`ghcr.io/trevex/libvirt-provider-tap`**.
- ioiab fork → repo `trevex/ironcore-in-a-box-xdp`, local `/home/nik/Development/ironcore-in-a-box-xdp` (`base/dpservice/`, `base/libvirt-provider/` kustomize dirs to modify).

**Deliverables:** publish both images to ghcr.io/trevex, then wire `ironcore-in-a-box-xdp` (`base/dpservice` → flowplane DaemonSet + init-container tap pool; `base/libvirt-provider` → our image + `--network-interface-direct-mode=tap`) and get `make up` → one VM boots/DHCPs/pings.

**R1 is validated empirically first**, the cheap way: `flowplane serve` on a plain tap + a raw qemu VM bound to that tap (no libvirt-provider, no cluster) → guest DHCPs from our responder and pings the gateway. This de-risks the one thing the existing tests don't cover (qemu's tap-fd I/O behaving like our injection) before building images / wiring the fork.
