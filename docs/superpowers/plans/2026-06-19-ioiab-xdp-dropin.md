# ioiab flowplane Drop-In (Phase 1: one VM boots / DHCPs / pings) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]` checkboxes. Spec: `docs/superpowers/specs/2026-06-19-ioiab-xdp-dropin-design.md`.

**Goal:** Run `flowplane` as a drop-in for dpservice in a forked ironcore-in-a-box and prove one guest VM boots, gets its address from our in-XDP DHCP, and pings the gateway / a second VM.

**Repos (all github.com/trevex):**
- `ectobase/flowplane` (the datapath) — local `/home/nik/Development/ironcore-net-xdp` → image `ghcr.io/trevex/ectobase/flowplane`
- `libvirt-provider-tap` — local `/home/nik/Development/libvirt-provider-tap` → image `ghcr.io/trevex/libvirt-provider-tap`
- `ironcore-in-a-box-xdp` — local `/home/nik/Development/ironcore-in-a-box-xdp`

**Architecture:** XDP can only process guest *egress* if it arrives as RX on the tap → the VM must bind via a **plain tap** (qemu owns the fd), not macvtap. So: (1) make libvirt-provider's plain-tap binding a selectable mode (macvtap stays default); (2) an init-container creates the kernel tap pool DPDK used to make; (3) flowplane attaches to those taps (already does). metalnet/metalnetlet/apinet/the gRPC contract are unchanged.

**A note on publishing:** `docker push` to ghcr.io/trevex is outward-facing — only run the push steps once the user confirms they're logged in to ghcr (`docker login ghcr.io`) or asks you to. Building images locally is always fine.

---

## Workstream A — R1 validation (GATING; do first)

### Task A1: prove XDP-on-plain-tap with a real DHCP client

**Goal:** a *real* (non-scapy) DHCP client behind a plain tap served by `flowplane` gets a lease and pings the gateway. This de-risks the one thing the conformance suite doesn't cover (a real client / qemu fd I/O vs our scapy injection) before we build anything.

- [ ] **Step 1: stand up a plain tap + flowplane.** In a fresh netns or the host: create a persistent tap (`ip tuntap add dev xtap0 mode tap`, set MAC, `up`), give the "underlay" side what `flowplane serve` needs, and run `flowplane serve --addr 127.0.0.1:1337 --uplink <uplink> --local-underlay <v6> --gateway 169.254.0.1 --gateway6 fe80::1 --gateway-mac <mac> --dhcp-mtu 1450 --dhcp-dns 8.8.8.8`. Register the guest interface over gRPC (dpservice-cli `addinterface`/the existing harness helper) so `guest_tx` attaches to `xtap0`.

- [ ] **Step 2: attach a real client.** Preferred: a minimal qemu VM bound to the tap (`qemu-system-x86_64 -enable-kvm -netdev tap,id=n0,ifname=xtap0,script=no,downscript=no -device virtio-net,netdev=n0 …`) running `udhcpc` + `ping`. Acceptable lighter fallback (same tun-fd mechanism): move the tap into a netns and run `udhcpc`/`dhclient` + `ping` there. The point is a real DHCP client driving the full DISCOVER/OFFER/REQUEST/ACK against our responder.

- [ ] **Step 3: assert.** The client obtains the expected IPv4 lease from our responder and can ping `169.254.0.1` (ARP answered by the datapath). Capture with `tcpdump -i xtap0`.

- [ ] **Step 4: GO/NO-GO.** If green → proceed. If the real client / qemu path behaves differently from scapy injection, STOP and report the exact failure (this would change the whole approach). Record the result in the spec.

---

## Workstream B — ectobase/flowplane container image

### Task B1: add a Dockerfile to the flowplane repo

**Files:** Create `/home/nik/Development/ironcore-net-xdp/Dockerfile` (+ `.dockerignore`).

- [ ] **Step 1: multi-stage Dockerfile.** Builder stage pins the eBPF toolchain the repo uses (Rust `nightly-2026-01-15` + `rust-src` via rustup, `bpf-linker`, LLVM/clang ≥ the version `bpf-linker` needs; aya-build invokes bpf-linker and bakes the eBPF object into the binary via `include_bytes!`). `cargo build --release -p flowplane`. Runtime stage: `debian:bookworm-slim` (or distroless/cc), copy the single `target/release/flowplane` binary, `ENTRYPOINT ["/usr/local/bin/flowplane"]`. No DPDK, hugepages, or DPDK kernel modules.
  - The pinned toolchain in apt/rustup is the main effort/risk. **Fallback if the in-Docker eBPF build is troublesome:** build the binary on the host (`nix develop -c cargo build --release -p flowplane`) and use a runtime-only Dockerfile that `COPY`s the prebuilt binary (document the host-build step). Prefer the self-building image; fall back only if blocked.

- [ ] **Step 2: build locally.** `docker build -t ghcr.io/trevex/ectobase/flowplane:dev .` succeeds; `docker run --rm ghcr.io/trevex/ectobase/flowplane:dev --help` prints the `flowplane` CLI.

- [ ] **Step 3: commit** (in the flowplane repo): `git commit -m "feat(image): Dockerfile for the ectobase/flowplane container"`.

### Task B2: publish the image

- [ ] **Step 1 (publish — confirm ghcr auth first):** tag a versioned image (e.g. `ghcr.io/trevex/ectobase/flowplane:v0.1.0` + `:latest`) and `docker push` both. Only run after the user confirms `docker login ghcr.io`. Note the digest.

---

## Workstream C — libvirt-provider-tap (selectable plain-tap binding)

### Task C1: add a selectable plain-tap NIC binding (macvtap stays default)

**Files (in `/home/nik/Development/libvirt-provider-tap`):**
- `internal/controllers/machine_controller_nics.go` — `providerNetworkInterfaceToLibvirt` (`nic.Direct` branch, ~464-480) + the inverse `libvirtInterfaceToProviderNetworkInterface` (`src.Direct` branch, ~424-429).
- The machine-controller construction + the flag wiring (find where the controller/manager is built and flags are registered, likely `cmd/` or `main.go` + `internal/controllers`).

- [ ] **Step 1: add the mode config + flag.** Introduce a `--network-interface-direct-mode` CLI flag with values `macvtap` (default) and `tap`, plumbed onto the machine controller (a field on the reconciler/struct, or threaded into `providerNetworkInterfaceToLibvirt` as a parameter). Default MUST preserve today's macvtap behavior so the fork still works for DPDK dpservice.

- [ ] **Step 2: emit plain tap when mode=tap.** In the `nic.Direct` branch, when mode==`tap`, build:
  ```go
  iface: &libvirtxml.DomainInterface{
      Alias: &libvirtxml.DomainAlias{Name: networkInterfaceAlias(name)},
      Model: &libvirtxml.DomainInterfaceModel{Type: "virtio"},
      Source: &libvirtxml.DomainInterfaceSource{
          Ethernet: &libvirtxml.DomainInterfaceSourceEthernet{},
      },
      Target: &libvirtxml.DomainInterfaceTarget{Dev: nic.Direct.Dev, Managed: "no"},
  }
  ```
  (verify the exact `libvirtxml` struct names/fields for `type='ethernet'` + `<target dev=.. managed='no'/>` against the vendored `libvirt.org/go/libvirtxml`; the marshaled XML must be `<interface type='ethernet'><target dev='dtapvf_N' managed='no'/><model type='virtio'/></interface>`). Keep the macvtap (`Source.Direct{Dev, Mode:"bridge"}`) branch for mode==`macvtap`.

- [ ] **Step 3: inverse parser.** Teach `libvirtInterfaceToProviderNetworkInterface` to recognize the `Target`-based ethernet form (map back to `Direct{Dev}`) in addition to `src.Direct`, so attach/detach reconciliation stays idempotent.

- [ ] **Step 4: build + unit test.** `make build` / `go build ./...` succeeds; run any NIC-XML unit tests (`go test ./internal/controllers/...`). Add/extend a table test asserting both modes marshal to the expected XML if the repo has such tests.

- [ ] **Step 5: commit** (in libvirt-provider-tap): `git commit -m "feat(nic): selectable plain-tap (type=ethernet) NIC binding; macvtap default"`. Push the branch.

### Task C2: publish the image

- [ ] **Step 1 (publish — confirm ghcr auth):** `make docker-build docker-push IMG=ghcr.io/trevex/libvirt-provider-tap:v0.1.0` (the repo's Makefile already has these targets). Only after the user confirms ghcr login. Note the digest.

---

## Workstream D — ironcore-in-a-box-xdp wiring

**Files (in `/home/nik/Development/ironcore-in-a-box-xdp`):** `base/dpservice/*` and `base/libvirt-provider/*` (kustomize).

### Task D1: replace the dpservice DaemonSet with flowplane + tap-pool init container

- [ ] **Step 1: rework `base/dpservice`.** Replace the upstream dpservice base + `dpservice-tap.yaml` patch with a DaemonSet (keep namespace `dpservice-system` + the DaemonSet name so metalnetlet discovery is unchanged) that:
  - uses `ghcr.io/trevex/ectobase/flowplane:<tag>`,
  - drops ALL DPDK EAL args + hugepage/temp mounts,
  - runs: `flowplane serve --addr [::]:1337 --uplink dtap0 --local-underlay 2001:db8:fefe::1 --gateway 169.254.0.1 --gateway6 fe80::1 --gateway-mac <underlay-nexthop> --dhcp-mtu 1450 --dhcp-dns 8.8.4.4 --dhcp-dns 8.8.8.8 --dhcpv6-dns 2001:4860:4860::6464 --dhcpv6-dns 2002:4861:4861::6464` (resolve `<underlay-nexthop>` during bring-up; in single-node it may be a placeholder — see spec R3),
  - `hostNetwork: true`, `securityContext.capabilities.add: [BPF, NET_ADMIN, PERFMON, SYS_ADMIN]` (trim to what the kernel actually requires), `privileged` only if needed,
  - mounts `/sys` (for BTF/`/sys/kernel/btf`) and `/sys/fs/bpf` if pinning is used,
  - a gRPC readiness probe on `:1337` so libvirt-provider's "wait for dataplane" ordering holds.

- [ ] **Step 2: init container — create the tap pool.** Add an initContainer (privileged/NET_ADMIN, hostNetwork) that idempotently creates the kernel taps DPDK used to make, with the SAME names + MACs metalnet/libvirt expect:
  ```
  for n in 0 1; do ip tuntap add dev dtap$n mode tap 2>/dev/null; ip link set dtap$n address 22:22:22:22:22:0$n; ip link set dtap$n up; done
  for n in 0 1 2 3; do ip tuntap add dev dtapvf_$n mode tap 2>/dev/null; ip link set dtapvf_$n address 66:66:66:66:66:0$n; ip link set dtapvf_$n up; done
  ```
  (a small image with `iproute2`; `ip` must be persistent taps so the netdevs survive for qemu + flowplane to share). Reconcile with `hack/setup-network.sh` (which configures `dtap0`'s underlay route) — the taps now pre-exist, satisfying its wait.

### Task D2: point libvirt-provider at our image + enable tap mode

- [ ] **Step 1:** in `base/libvirt-provider`, set the manager image to `ghcr.io/trevex/libvirt-provider-tap:<tag>` and add the arg `--network-interface-direct-mode=tap` (patch `patch-manager-daemonset.yaml`).

### Task D3: any setup-network / kustomization reconciliation

- [ ] **Step 1:** update `kustomization.yaml`s / image refs / `hack/setup-network.sh` as needed so `make up`'s ordering still holds (dpservice→metalnet→setup-network→…). Verify the underlay route + `--gateway-mac` make sense single-node (spec R3).

---

## Workstream E — bring-up + the milestone test

### Task E1: cluster comes up

- [ ] **Step 1:** `make up` on the fork. Iterate until all pods Ready: the flowplane DaemonSet Ready on `:1337` (check logs: programs attached to `dtap0` uplink; gRPC serving), metalnetlet connected, metalnet/metalbond/libvirt-provider Ready. Debug attach/permission/BTF issues here (spec R2). Capture the failure + fix for each iteration.

### Task E2: one VM boots, DHCPs, pings (definition of done)

- [ ] **Step 1:** create a `Network` + `Machine` + `NetworkInterface` (ioiab's example/BATS path).
- [ ] **Step 2:** the VM boots (libvirt-provider, plain-tap binding); metalnet `CreateInterface(dtapvf_N)` succeeds; flowplane attaches `guest_tx` to that tap (check logs).
- [ ] **Step 3:** the guest gets its IPv4 (and IPv6) lease from our in-XDP DHCP responder (guest console / dhcp logs).
- [ ] **Step 4:** the guest pings the overlay gateway (`169.254.0.1` / `fe80::1`, answered by our ARP/ND responder) and a second VM on the same network.
- [ ] **Step 5:** record the result; update the spec/README with the working drop-in.

---

## Notes / risks (from the spec)

- **R2 (kind kernel/XDP):** kind nodes are containers on the host kernel (7.0.11 — supports the verifier/BTF). Confirm XDP attach + maps work from inside the pod (CAP_BPF, `/sys/kernel/btf` visible); taps support native `adjust_tail` for our DHCP frame growth (proven by `tap-dhcp-probe`); SKB-mode env knob exists if needed.
- **R3 (single-node underlay):** no remote hypervisor → guest-to-guest uses flowplane's local fast path; `--gateway-mac`/`--local-underlay` may be placeholders. Validate during E1/E2.
- **Publishing** images is outward-facing — gate the `docker push` / `docker-push` steps on the user's ghcr login / explicit go-ahead.
- This plan is deliberately less micro for Workstreams D/E (cluster bring-up is iterative debugging, not pre-scriptable); execute them as a debug loop against the milestone, committing fixes as you go.
