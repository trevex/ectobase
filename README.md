# ectobase

**ectobase** is an umbrella, Kubernetes-native multi-cluster IaaS layer for running **containers and KubeVirt VMs** on a shared eBPF/XDP overlay network. It is built from two components:

- **flowplane** — the **eBPF/XDP dataplane** (Rust): a map-driven kernel overlay that gives every workload an address on a shared IPv6-underlay, IP-in-IPv6 overlay, and provides routing, stateful NAT, load balancing, a deny-by-default firewall, and DHCP/ARP/ND, all in the Linux kernel.
- **netplane** — the **Kubernetes control plane** (Go): CRDs describe intent; per-node agents, a central route reflector, and controllers compile and distribute that intent down to each node's `flowplane` datapath.

> **Lineage & scope.** `flowplane` began as an eBPF/XDP reimplementation of IronCore's DPDK [`dpservice`](https://github.com/ironcore-dev/dpservice). ectobase has since grown its **own** Kubernetes control plane (`netplane`), CRD API, route-distribution bus, and CNI, and now targets containers + KubeVirt VMs directly. The `DPDKironcore` compat gRPC and the vendored dpservice conformance suite have been removed; `flowplane serve` now exposes only `DataplaneNode`. **metalnet/ironcore compatibility is no longer a design constraint.**

## Architecture at a glance

ectobase is two planes — the `flowplane` datapath and the `netplane` control plane:

**1. Datapath (`flowplane`, Rust/eBPF).** A map-driven kernel dataplane — every forwarding decision is a per-flow-keyed table lookup (the shape a SmartNIC `rte_flow` would encode). Programs:

- **`uplink_rx`** — XDP on the fabric uplink: overlay → local guest (decap, deliver, LB local-deliver, NAT return). Edge nodes also attach **`wan_rx`** for the WAN↔overlay return path.
- **`tc_guest_tx`** — **tcx (tc) on the guest tap/veth ingress = guest egress**: firewall, SNAT/VIP, encap, redirect to the uplink.
- In-datapath responders (**ARP, IPv6 ND, DHCPv4/v6**), **conntrack**, **NAT-GW** (distributed return via neighbor-NAT), **VIP** (1:1 DNAT/SNAT), **load balancing** (Maglev, dpservice underlay-forwarding model), **NAT64**, **firewall** (stateful, deny-by-default), and **rate metering** (srTCM).
- **Overlay:** IPv6 underlay, IP-in-IPv6 encap (inner-proto 4 for IPv4, 41 for IPv6), multi-VNI tenancy, same-host fast path.
- **Graceful restart / HA:** state maps are pinned to bpffs and **adopted** on restart (bookkeeping rebuilt from an `IFACE_META` journal, IPAM reseeded so a live `/128` is never reissued), and the program **links are pinned** so a same-image restart is *zero forwarding gap* (atomic `bpf_link_update` re-point; new bytecode on a rolling upgrade). See `docs/superpowers/{specs,plans}/2026-07-16-*`.

**2. Control plane (`netplane`, Go + Kubernetes).** CRDs describe intent; the control plane compiles and distributes them to the per-node dataplanes:

- **agent** (per node) — reconciles the node's `NetworkInterface`s, programs the local dataplane over the **DataplaneNode gRPC** (`127.0.0.1:1337`), and announces/learns overlay routes, NAT blocks, and edge identities over the **route bus**.
- **reflector** (central) — a route broker: agents open a bidi `RouteBus` stream and it reflects per-VNI routes (and NAT/public records) between nodes. This is the overlay's routing distribution (custom, not BGP; BGP is used only for the WAN-edge announcement).
- **controller** (central) — controller-runtime reconcilers: the **NATGateway** port-block allocator and the **CompiledNIC** compiler that lowers `NetworkInterface` + `NetworkPolicy` into per-NIC firewall rules the agent programs.
- **CNI** (`cni/`) — on pod ADD, resolves the pod's overlay VNI/IPs from the CRDs and calls the node's DataplaneNode gRPC (`AttachInterface`) to create the veth + program the datapath.

**CRD API** (`net.ectobase.dev/v1alpha1`, in `api/`): `VPC`, `NetworkInterface`, `NetworkPolicy`, `NATGateway`, `VirtualIP`, `LoadBalancer`, `VPCPeering`, plus the controller-written `CompiledNIC`/`CompiledFirewall`/`CompiledNAT`/`CompiledLB`.

## Repository layout

| Path | What |
|---|---|
| `flowplane-common/` | `#[repr(C)]` POD types shared between eBPF and userspace (map keys/values), with layout tests. `no_std` by default; a `user` feature adds the aya integration. |
| `flowplane-core/` | `no_std`, generic (over `Pkt`/`Maps` traits) **pure datapath logic** — the same forwarding/conntrack/NAT/LB/firewall code runs in eBPF, in the native sim, and in unit tests. |
| `flowplane-ebpf/` | The eBPF programs (`uplink_rx`, `wan_rx`, `tc_guest_tx`, `tc_guest_dhcp`, `tc_guest_nat64`, `xdp_pass`, `xdp_inspect`) + the map declarations. Compiled to bytecode via `aya-build`. |
| `flowplane/` | The Rust userspace daemon: gRPC server (`DataplaneNode`), the map control plane (`control.rs`), the eBPF loader + link/adopt logic (`loader.rs`), veth/tap lifecycle + IPAM (`attach.rs`), and the CLI (`main.rs`). |
| `flowplane-sim/` | An **in-process datapath simulator**: heap-backed `Pkt`/`Maps` impls + `SimNode`/`Fabric` run the real `flowplane-core` logic with **no kernel, no clab, no root** — the fast dev/regression loop. |
| `netplane/` | The Go control plane: `cmd/agent`, `cmd/reflector`, `cmd/controller`, and the `routebus` client/server + reconcile/desired-state logic. |
| `cni/` | The CNI plugin (`cni/plugin/main.go`) that attaches pods via the DataplaneNode gRPC. |
| `api/` | Kubernetes CRD types (`api/v1alpha1/`, group `net.ectobase.dev`) and the gRPC contracts (`api/proto/dataplane/v1/{dataplane,dpdk}.proto`, `api/proto/routebus/v1/routebus.proto`). |
| `config/` | Kubernetes manifests: CRD bases, the `flowplane` DaemonSet, netplane agent/reflector/controller deployments, RBAC, and the `ectobase-system` namespace. |
| `hack/` | Lab bring-up: the **containerlab + kind fabric** (`clab-up.sh`/`clab-down.sh`, `clab/`), the fabric kind-node image, and edge-agent helpers. |
| `test/` | Local harnesses: the `scenario-*.sh` feature scenarios, `netns-e2e.sh`, `ha-smoke.sh`, `scenario-restart.sh`, `tap-vm-smoke.sh`, and the WAN-edge netns tests. |
| `docs/superpowers/{specs,plans}/` | Per-milestone design specs and implementation plans. |

## `flowplane` CLI

| Subcommand | What |
|---|---|
| **`serve`** | The production daemon: attaches `uplink_rx`, serves `DataplaneNode` gRPC, attaches/detaches the guest edge per interface as gRPC drives it. Key flags: `--role node\|edge` (edge adds `wan_rx`), `--uplink`/`--extra-uplink`/`--wan-uplink`, `--gateway-mac`, `--pin-dir` (bpffs, default `/sys/fs/bpf/flowplane`), `--pin-links` (default on — zero-gap restart), `--dhcp-*`. |
| **`bringup`** | Static, flag-driven datapath for the netns lab (no gRPC). |
| **`tc-bringup`** | Minimal tc guest-edge bringup (one tap). |
| **`load` / `pass` / `inspect`** | Debug helpers: attach `uplink_rx` and idle / attach `xdp_pass` / attach `xdp_inspect`. |
| **`infer-underlay`** | Print the inferred host underlay `/64` and exit (no root, no datapath). |

## Getting started

Everything is provided by the Nix flake — Rust (pinned in `rust-toolchain.toml`), `bpf-linker`, `protobuf`, Go, `kind`/`containerlab`, `python3`+`scapy`+`pytest`, plus `qemu`, `iproute2`, `bpftool`, `tcpdump`, etc.

```sh
nix develop            # enter the dev shell (all targets assume you are inside it)
make                   # list all targets
```

Common workflows (from inside `nix develop`):

```sh
make build             # build flowplane (host crates + the eBPF object via aya-build)
make lint              # clippy across all targets
make test              # host unit + POD-layout tests           (no root)
make sim               # in-process datapath tests              (no root, no clab)
make sim-anchor        # BPF_PROG_TEST_RUN byte-parity anchor    (sudo)
make verifier          # load the programs through the verifier  (sudo)
make e2e               # 3-node netns overlay end-to-end         (sudo)
make ha                # HA pinned-maps kill+adopt smoke         (sudo)
make tap-vm-smoke      # boot a CirrOS VM on a real tap          (sudo + KVM)
make image             # build the ghcr.io/trevex/ectobase/flowplane image
```

The `e2e`, `ha`, and `tap-*` targets need **passwordless sudo** (XDP attach, network namespaces, raw sockets). The scripts elevate individual commands themselves.

### The clab + kind fabric (integration)

The primary integration environment is a **containerlab IPv6 fabric wrapping a kind cluster**, with the full netplane stack (agent + reflector + controller) and the `flowplane` DaemonSet deployed:

```sh
hack/clab-up.sh            # bring up the fabric + kind + netplane stack
# ... deploy workloads / run scenarios ...
sudo -E bash test/scenario-nat-egress.sh    # container egress via distributed SNAT + WAN edge
sudo -E bash test/scenario-lb-ingress.sh    # N-S load balancing
sudo -E bash test/scenario-restart.sh       # graceful datapath restart (crictl kill -> adopt, no /128 reissue)
hack/clab-down.sh
```

## Distributed firewall

The distributed firewall is **always-on deny-by-default**: `fw_eval_dir` accepts a packet only on an explicit matching allow rule. The control plane materializes k8s default-allow explicitly — `Compile()` emits a per-direction allow-all for any NIC no `NetworkPolicy` selects. A **compiler controller** (`CompiledNICReconciler`) writes one `CompiledNIC` per `NetworkInterface`; the **node agent** installs its rules on the dataplane via `AddFwRule` during each reconcile loop (`ReconcileFirewall`). See [`docs/superpowers/specs/2026-07-15-compilednic-firewall-pipeline-design.md`](docs/superpowers/specs/2026-07-15-compilednic-firewall-pipeline-design.md) for the full design.

## Synthetic datapath testing

The real datapath logic lives in `flowplane-core` — a `no_std` crate whose functions are generic over `Pkt`/`Maps` traits. The same code runs in two contexts:

- **eBPF** — `CtxPkt`/`GlobalMaps` in `flowplane-ebpf/src/coreimpl.rs` bind the trait impls to real kernel maps and the XDP packet context.
- **Native sim** — `VecPkt`/`MemMaps` in `flowplane-sim` provide in-process, heap-backed impls. `SimNode` runs the real core functions with no kernel, no clab, no root. `CompiledNIC` (the per-NIC control-plane CRD) is lowered into sim maps via `flowplane_sim::compilednic::apply`, so the control-plane→datapath path is tested end-to-end without touching a real interface.

**Multi-node fabric.** `flowplane_sim::Fabric` owns several `SimNode`s plus an underlay-`/128`→node table and follows encap/redirect hops across the fabric (`bpf_redirect` semantics), returning a `Trace` of every hop. This runs *whole flows* in-process: North-South (external → edge `wan_rx` → backend host), and East-West load-balancing including the relay **reforward** to a remote backend. The LB coverage (`flowplane-sim/src/lb_scenario_test.rs`) reproduces the "LB packets dropped" clab failure synthetically and pins the fix: the firewall is **explicit-only** (LB membership never generates rules) and the dataplane is **deny-by-default** — the control plane materializes k8s open-until-selected as explicit allow-all rules for unpolicied NICs (`Compile()`). Because LB is DSR (inner dst stays the VIP), a policy written for a backend's own overlay IP does *not* cover its LB traffic; an explicit `VIP:port` rule is required.

See `docs/superpowers/specs/2026-07-15-compiled-nic-synthetic-datapath-testing-design.md` (core sim) and `docs/superpowers/specs/2026-07-15-fabric-sim-lb-coverage-design.md` (fabric + LB) for the full designs.

### Commands

```sh
make sim             # fast in-process tests — the everyday dev loop (no root, no clab)
make sim-anchor      # privileged BPF_PROG_TEST_RUN check: native core output == real bytecode output
```

### How to add a datapath feature

1. **Port the fn into `flowplane-core`** generic over `Pkt`/`Maps`; add any new map-accessor methods to the `Maps` trait.
2. **Wire the eBPF side** — call the new fn from `flowplane-ebpf` via the existing `CtxPkt`/`GlobalMaps` impls in `coreimpl.rs`.
3. **Implement `MemMaps`** — add the corresponding in-memory map to `flowplane-sim` and implement the new `Maps` accessor.
4. **Add a sim test** — write a `SimNode`- or `Fabric`-based scenario in `flowplane-sim/src/*_test.rs` (single-node or multi-hop); run it with `make sim`.
5. **Add an anchor case** — add one `BPF_PROG_TEST_RUN` case in the relevant `flowplane/tests/anchor_*.rs` to assert native-core output matches real bytecode; verify with `make sim-anchor`.

## Conformance

Datapath fidelity is proven at three levels:

- **In-process sim (`make sim`)** — `flowplane-core` + `flowplane-sim` cover every protocol path (encap/decap, NAT, LB, DHCP, ARP/ND, firewall) via `MemMaps`/`VecPkt`; zero privileges, zero network stack.
- **Byte-parity anchors (`make sim-anchor`)** — `BPF_PROG_TEST_RUN` anchors assert the real eBPF bytecode produces identical output to the native-core sim for the same input.
- **Go e2e smoke (`make e2e`)** — real gRPC attach, real kernel netns topology; proves the control-plane wiring and live forwarding end-to-end.

## Design docs

Each milestone has a spec (`docs/superpowers/specs/`) and an implementation plan (`docs/superpowers/plans/`) — the parity gap analysis, the KubeVirt/multi-cluster designs, the netplane control-plane + route-distribution designs, the CompiledNIC firewall pipeline, the synthetic-testing (core sim + fabric) designs, and the resilience work (graceful restart, link-pinning). Each carries its outcome, including deferred items and their root-cause analyses (e.g. the clab-only guest-egress checksum artifact).
