# DPDK dataplane: Helm packaging + blue-green upgrades — design

**Date:** 2026-07-22
**Status:** Design (approved in brainstorm; awaiting written-spec review)
**Scope:** Deploying the DPDK dataplane (`flowplane-dpdk` on the `nfkit` substrate) to Kubernetes
alongside the existing eBPF `flowplane`, via a Helm chart, and adding an operator-driven blue-green
upgrade mechanism for the DPDK datapath.

---

## 1. Context and problem

Today the datapath ships as one eBPF binary, `flowplane`, deployed by a flat kustomize base
(`config/deploy/*`): a `DaemonSet` (hostNetwork, hostPID, privileged) that loads XDP, opens a gRPC
`DataplaneNode` listener on `127.0.0.1:1337`, and is dialed by the `netplane-agent` DaemonSet
(`--dataplane=127.0.0.1:1337`). There are no overlays; environment differences are baked into the
single manifest (e.g. `FLOWPLANE_SKB_MODE=1` for clab veths).

We now have a DPDK datapath — but only as a **library**. `nfkit` is the safe Rust DPDK *substrate*
(EAL/mbuf/mempool/port/rte_hash/rte_flow wrappers), analogous to what `aya` + `flowplane-ebpf` are
for the eBPF path. It has no `serve` binary, no gRPC server, no `main`, no container image, and
nothing in the workspace depends on it. The datapath logic itself is proven byte-identical to eBPF
via `flowplane-core`'s shared generic orchestrators (M1–M11), but there is no deployable process.

Three things are being asked for, and they are separable:

- **(a) Packaging** — add DPDK support to the deployment tooling, moving from kustomize to Helm.
- **(b) Deployability** — make the DPDK datapath a runnable pod at all.
- **(c) Blue-green** — hitless DPDK binary upgrades in Kubernetes.

DPDK needs (c) in a way eBPF does not: an eBPF upgrade swaps the XDP program on a live link
atomically and the maps persist, so there is no gap and no state loss. A DPDK binary owns the NIC
exclusively via EAL (vfio/PMD on HW, the AF_XDP PMD on clab); upgrading it means kill-old →
NIC-released → start-new → NIC-rebound, which is both a hard traffic gap **and** total flow-state
loss. Blue-green removes both by running the new instance beside the old, handing off flow state
(the existing `nfkit::snapshot` primitive), flipping traffic, then draining the old.

## 2. Decisions (locked in brainstorm)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Target environment | **Both, phased** — clab (AF_XDP, software fallback) now; real ConnectX HW (offload, hitless) later. Same chart, env-switched. |
| 2 | Packaging tooling | **Helm chart** (migrate from kustomize). |
| 3 | eBPF vs DPDK selection | **Whole-cluster toggle** — `values.dataplane: ebpf \| dpdk` renders exactly one datapath DaemonSet. No mixed clusters. |
| 4 | Blue-green orchestration | **Operator + CRD** (`DataplaneUpgrade`). |
| 5 | clab hitlessness | **Accept brief-gap on clab.** Zero-gap hitless is a HW-only acceptance criterion. |
| 6 | Naming | The deployable crate is **`flowplane-dpdk`** (on the `nfkit` substrate); *not* a bin inside `nfkit`. |
| 7 | Doc/plan structure | **One umbrella design doc** (this); implement **thread A (Helm) first**, then B, then C. |

**Key architectural invariant:** both datapaths speak the *same* `DataplaneNode` gRPC contract on
`127.0.0.1:1337`. The agent therefore stays **dataplane-agnostic** — it dials the port and whichever
datapath pod is scheduled on the node answers. Backend selection is purely a scheduling/render
concern, never an agent concern.

## 3. Architecture: three layers

```
A. Helm migration            B. flowplane-dpdk deployable       C. Blue-green operator
   config/deploy/* → chart      new workspace crate on nfkit;      DataplaneUpgrade CRD +
   values.dataplane toggle      serve bin + DataplaneNode gRPC     controller; green pod beside
   env-switched knobs           + DPDK image + DaemonSet           blue; Export→Import→Steer→Drain
   ── independent, ship 1st ──  ── prereq for any DPDK pod ──      ── depends on B ──
```

They are *layered*, not independent (the chart renders the operator+CRD; the operator drives
`flowplane-dpdk`'s upgrade RPCs). Hence one doc, three implementation plans, sequenced A → B → C.

---

## 4. Thread A — Helm chart migration (implement first)

**Goal:** replace `config/deploy/` (kustomize) with a Helm chart that reproduces today's eBPF
deployment byte-for-byte when `dataplane: ebpf`, and can render the DPDK datapath when
`dataplane: dpdk`. Ships independently of B/C — with `dataplane: dpdk` it renders a DaemonSet whose
image simply doesn't exist yet until B lands.

**Chart layout** (`deploy/charts/ectobase/` or similar):

```
Chart.yaml
values.yaml
templates/
  namespace.yaml
  rbac.yaml
  reflector.yaml
  agent.yaml            # unconditional
  controller.yaml       # unconditional
  cni.yaml              # unconditional
  kubevirt-binding.yaml # unconditional, still applied after Multus CRD
  dataplane-ebpf.yaml   # {{- if eq .Values.dataplane "ebpf" }}
  dataplane-dpdk.yaml   # {{- if eq .Values.dataplane "dpdk" }}
  crds/                 # net.ectobase.dev CRDs (see CRD note below)
```

**`values.yaml` (initial surface):**

```yaml
dataplane: ebpf            # ebpf | dpdk
env: clab                  # clab | hw   — drives datapath-specific knobs
images:
  flowplane: ghcr.io/trevex/ectobase/flowplane:dev
  flowplaneDpdk: ghcr.io/trevex/ectobase/flowplane-dpdk:dev
  netplane: ghcr.io/trevex/ectobase/netplane:dev
uplink: eth1               # overlay uplink iface
dpdk:
  lcores: "0"              # clab: single lcore (see §5); hw: wider
  hugepages: false         # clab: false (--no-huge if supported); hw: true
  hugepageSize: 1Gi
  vfioDevices: []          # hw: PCI/vfio device requests; clab: none
blueGreen:
  enabled: false           # thread C; off until operator lands
```

**Constraints / requirements:**

- The `ebpf` render MUST equal the current `config/deploy/flowplane.yaml` exactly (same wrapper
  script, probes, mounts, `FLOWPLANE_SKB_MODE`). This is a pure regression: existing users see no
  change. Verify by diffing rendered output against the current manifest.
- `agent`, `reflector`, `controller`, `cni`, RBAC render unconditionally and unchanged.
- **CRDs:** Helm's CRD handling is weaker than kustomize's (no upgrade of `crds/` dir). CRDs are
  already generated by `make generate` (controller-gen). Decision for the plan: put them in
  `templates/crds/` gated behind `installCRDs: true` (so `helm upgrade` manages them), rather than
  Helm's special `crds/` dir. Keep `make generate` as the source of truth; the chart only vendors
  the output.
- No `kustomize` removal until the chart is proven on the clab fabric (keep `config/deploy` until
  the chart passes a live smoke, then delete in the same PR that flips CI/scripts to `helm`).

**Testing:** `helm template` golden-file diff of the `ebpf` render vs the current manifest; `helm
lint`; a live `helm install` on the clab kind fabric reproducing the current eBPF regression sweep.

---

## 5. Thread B — `flowplane-dpdk` deployable (prereq for any DPDK pod)

**Goal:** a runnable DPDK datapath process + container image + DaemonSet, so the agent can dial it
exactly as it dials eBPF `flowplane`.

**New workspace crate `flowplane/flowplane-dpdk`** — stands to `nfkit` as `flowplane` stands to
`aya`/`flowplane-ebpf`:

- depends on `nfkit` (substrate) + `flowplane-core` (shared generic datapath) + `tonic`/`tokio`/
  `clap` (already workspace deps).
- `flowplane-dpdk serve` entrypoint mirroring `flowplane serve`: parse args (uplink, gateway,
  gateway-mac, backend/env knobs) → EAL init (`nfkit::eal`) → port/queue setup
  (`Backend::AfXdp` on clab, `Backend::Nic` on HW) → build the datapath over `nfkit` maps/pkt →
  health `Serving` → serve the `DataplaneNode` tonic service on `127.0.0.1:1337`.
- **gRPC service reuse:** the `DataplaneNode` service impl currently lives in the `flowplane` crate.
  Where the *handler logic* is backend-agnostic (route/fw/lb/nat map programming via the `Maps`
  trait) it should be extracted to a shared location both crates use; where it is backend-specific
  (AttachInterface: veth vs tap/vhost setup) each crate keeps its own glue. The plan for B decides
  the exact extraction seam; the invariant is *one proto, one wire contract*.

**Container image `Dockerfile.dpdk`:** builder stage compiles `-p flowplane-dpdk` (links DPDK —
needs the DPDK libs + `pkg-config` that `dpdk-sys/build.rs` already expects); runtime stage is a
slim image carrying the DPDK shared libraries + `iproute2`/`ethtool` (veth/netns/tap setup, same as
the eBPF image). Reuses the workspace's existing DPDK build tooling under `hack/dpdk`.

**DaemonSet `dataplane-dpdk.yaml`** — differs from the eBPF DaemonSet in the DPDK-specific runtime
surface, all `env`-driven from `values.dpdk`:

- **clab (`env: clab`):** `Backend::AfXdp{ iface: uplink, queues: 1 }`, **single lcore** (`-l 0` —
  override `backend.rs`'s hardcoded `-l 0-3`, which would pin 4 busy cores per node × N nodes on the
  shared host), AF_XDP `use_need_wakeup=1` / interrupt mode to avoid 100% busy-poll on the shared
  host, and **`--no-huge` if the AF_XDP PMD supports UMEM in normal memory** (OPEN — must verify;
  `backend.rs` currently does *not* pass `--no-huge` for `AfXdp`, and `afxdp-uplink.sh` reserves
  1024 host hugepages, which is a same-host footgun at N nodes). If `--no-huge` is unusable, reserve
  a small bounded pool and cap node count. XDP attaches in SKB/copy-mode on clab veths (native fails
  -95, same constraint as `FLOWPLANE_SKB_MODE`); first-frame warmup drop is expected.
- **hw (`env: hw`):** `Backend::Nic{ pci }`, hugepages (`resources.limits.hugepages-1Gi`), vfio-pci
  device access (device plugin or privileged), wider lcore set, `rte_flow` offload available.
- Same as eBPF: hostNetwork, hostPID, `DataplaneNode` on `127.0.0.1:1337`, `ss`-based readiness
  gating on the listener, bpffs/sys/netns mounts as needed.

**Testing:** unit/parity tests already cover the datapath (M1–M11). New for B: the `serve` binary
answers the `DataplaneNode` RPCs; a live clab smoke where the agent attaches an interface against
`flowplane-dpdk` and traffic flows over the AF_XDP uplink (extend the existing `afxdp-uplink.sh`
harness pattern).

---

## 6. Thread C — blue-green operator (depends on B)

**Goal:** upgrade the `flowplane-dpdk` binary on a node without losing established flows; hitless on
HW, brief-gap on clab.

**`DataplaneUpgrade` CRD** (cluster- or namespace-scoped): declares the target image/version and
rollout policy (e.g. node selector, max-in-flight, drain timeout). A controller reconciles it.

**Per-node upgrade sequence** (controller-driven, all over gRPC):

1. Schedule a **green** Pod beside the DaemonSet **blue** pod on the same node. Green binds a
   **second gRPC port** (e.g. `127.0.0.1:1338`) to dodge the `127.0.0.1:1337` bind conflict, and a
   second datapath instance on the steering seam (see below).
2. `blue.ExportState` → `green.ImportState` — carries conntrack/NAT/nat_ips via `nfkit::snapshot`
   (versioned blob; refuses magic/version mismatch, caller falls back to accepting flow loss).
   Config maps (routes/fw/lb/etc.) are re-derived on green from the control plane, not handed off.
3. `green.Steer(active)` → `blue.Steer(drain)` — flip ingress to green.
4. Await blue drain (existing flows quiesce or time out).
5. Retire blue; green assumes the DaemonSet identity (the controller lets the DaemonSet reconverge
   onto green, or promotes green in place — decided in C's plan).

**New `DataplaneNode` RPCs** (added to `api/proto/dataplane/v1/dataplane.proto`):
`ExportState`, `ImportState`, `Steer(active|drain)`. eBPF `flowplane` implements them as no-ops /
`UNIMPLEMENTED` (it never blue-greens — it hot-swaps XDP in place). This keeps one proto for both
backends.

**Steering-seam trait, two impls** (the phased split):

- **clab — release/rebind handoff (brief-gap):** a single-queue veth uplink has no RSS/steering
  fabric we control, and the kernel's `xsk_rcv` drops any packet whose RX queue index ≠ the
  socket's bound queue; two XSKs cannot bind the same `(netdev, queue)` (EBUSY). So blue and green
  cannot both receive live from one veth. `Steer(active)` on clab therefore = blue releases the
  queue, green binds it and imports state; flows survive with a sub-second gap. This validates
  state-continuity + the operator/CRD loop + the seam trait — **not** zero-gap.
- **hw — live `rte_flow`/eSwitch flip (hitless):** `Steer(active)` reprograms a flow/steering rule
  (or moves an RSS group / VF) so wire ingress lands on green's queue while blue drains. Zero-gap.
  This is the only place true hitlessness is asserted.

**Acceptance criteria:**

- clab CI: after an upgrade, established conntrack flows survive (state continuity), the operator
  reconciles a `DataplaneUpgrade` to completion, gap is sub-second.
- HW (later): the same, with **zero** dropped in-flight packets across the flip.

**Enablement:** gated by `values.blueGreen.enabled`; off until the operator + RPCs land. When off,
DPDK upgrades fall back to a plain DaemonSet rolling update (gap + flow loss — acceptable pre-C).

---

## 7. Sequencing and risks

**Order:** A (ship now, regression-free, unblocks the rest) → B (makes a DPDK pod real) → C
(blue-green on top of B). C is fully designed here but built only after B.

**Open items to resolve in the per-thread plans:**

- **[B]** Does the AF_XDP PMD run under `--no-huge` (UMEM in normal memory)? Gates the clab
  hugepage story. If not, bound the reserved pool and cap clab node count.
- **[B]** `backend.rs` hardcodes `-l 0-3`; must become lcore-count-configurable so clab uses `-l 0`.
- **[B]** Exact extraction seam for the shared `DataplaneNode` handler logic between `flowplane` and
  `flowplane-dpdk` (backend-agnostic map programming vs backend-specific attach glue).
- **[A]** CRD management under Helm (`templates/crds/` + `installCRDs` vs Helm's `crds/` dir), while
  keeping `make generate` authoritative.
- **[C]** How green assumes the DaemonSet identity after blue retires (DaemonSet reconverge vs
  in-place promotion).

**Non-goals:** mixed eBPF/DPDK clusters (whole-cluster toggle only); zero-gap hitlessness on clab;
removing kustomize before the Helm chart passes a live clab smoke; changing the agent (it stays
dataplane-agnostic).
