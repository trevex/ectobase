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

**Key architectural invariant:** both datapaths speak the *same* `DataplaneNode` gRPC contract. The
agent therefore stays **dataplane-agnostic** — whichever datapath pod is scheduled on the node
answers. Backend selection is purely a scheduling/render concern, never an agent concern. The one
blue-green refinement (thread C, §6.1): the agent dials **two** well-known node-local ports (blue
`127.0.0.1:1337`, green `127.0.0.1:1338`) and follows a streamed status phase to know which is
`Active`. It never needs to know eBPF-vs-DPDK; it only follows the phase.

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

### 4.1 Input validation (fail loudly on misconfig)

The chart must reject bad input with a clear error, not render a broken DaemonSet. Two layers:

- **`values.schema.json` (JSON Schema, draft-07)** shipped beside `Chart.yaml`. Helm validates
  `values` against it automatically on `install`/`upgrade`/`template`/`lint`. It enforces:
  - types + `required` on every key the templates dereference;
  - **enums**: `dataplane ∈ {ebpf, dpdk}`, `env ∈ {clab, hw}`;
  - `additionalProperties: false` at each object level, so a typo'd key (e.g. `dataplan:`) is a hard
    error instead of a silently-ignored default;
  - formats/bounds where they exist (image strings non-empty, `hugepageSize` pattern, `lcores`
    pattern).
- **Cross-field / conditional guards.** Some rules span keys. Where draft-07 `if/then/else` +
  `allOf` can express them, put them in the schema; where they'd be unreadable, use `{{- fail
  "..." }}` in a `templates/_validate.tpl` partial included first. Rules:
  - `dataplane: dpdk` **&&** `env: hw` ⇒ `dpdk.hugepages: true` **and** `dpdk.vfioDevices` non-empty
    (a DPDK HW node with no hugepages / no device is a guaranteed boot failure — fail at render).
  - `dataplane: dpdk` **&&** `env: clab` ⇒ `dpdk.lcores` must be a single lcore (`"0"`) — reject a
    wide lcore set that would pin N busy cores per node on the shared host (§5).
  - `blueGreen.enabled: true` ⇒ requires `dataplane: dpdk` (the operator/blue-green path is
    DPDK-only; eBPF hot-swaps in place) — fail otherwise.

Every failure message names the offending key, the allowed values, and *why* (one line). Validation
is covered by negative `helm template` tests (each bad-input case asserts a non-zero exit + expected
message) alongside the golden-file positive tests.

**Testing:** `helm template` golden-file diff of the `ebpf` render vs the current manifest; `helm
lint`; the negative validation cases above; a live `helm install` on the clab kind fabric
reproducing the current eBPF regression sweep.

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

**Per-node upgrade sequence** (controller-driven, gRPC; agent participates for config — see §6.1):

1. Schedule a **green** Pod beside the DaemonSet **blue** pod on the same node. Green binds the
   **green gRPC port** (`127.0.0.1:1338`) — blue keeps `:1337` for its whole life, so there is no
   socket handoff and no `SO_REUSEPORT` ambiguity. Green comes up `Init → Ready` with its datapath
   loaded but **no host-device ownership** (it has not bound the uplink or any tap yet).
2. **Config convergence (agent):** the agent, seeing green reach `Ready` on `:1338`, replays its
   full desired *config* onto green — the re-derivable map state only (routes/fw/lb/nat + each
   interface's overlay→underlay map entries). It does **not** re-run host-device side effects
   (§6.1). Both blue and green now hold identical config; green still owns no devices.
3. **Flow-state handoff (operator):** `blue.ExportState` → `green.ImportState` — conntrack/NAT/
   nat_ips via `nfkit::snapshot` (versioned blob; refuses magic/version mismatch, caller falls back
   to accepting flow loss).
4. **Flip (operator):** `green.Steer(active)` → `blue.Steer(drain)`. This is where **device
   ownership hands off**: blue releases the uplink (and taps), green binds them. HW does this
   hitlessly via `rte_flow`/eSwitch; clab does it as a release/rebind (brief gap). Green transitions
   `Ready → Active`, blue `Active → Draining`. The agent, watching the status stream, cuts its
   primary over to `:1338`.
5. Await blue drain (existing flows quiesce or time out) → `Retiring`; retire blue. Green assumes
   the DaemonSet identity (DaemonSet reconverge vs in-place promotion — decided in C's plan). The
   next upgrade runs green→blue, ports swapping roles.

**New `DataplaneNode` RPCs** (added to `api/proto/dataplane/v1/dataplane.proto`):

- `WatchStatus` (**server-streaming**): pushes
  `DataplaneStatus { phase, generation, role, successor }` where
  `phase ∈ {Init, Ready, Active, Draining, Retiring}` and `successor: Option<Endpoint>` is set on
  the `Active` instance while a migration is being prepared (points at the green port). It is the
  event that tells the agent to go configure the peer — see the FSM in §6.1. Purely event-driven;
  the agent never polls.
- `ExportState` / `ImportState`: flow-table snapshot handoff (`nfkit::snapshot`).
- `Steer(active|drain)`: the steering flip + device-ownership handoff.

eBPF `flowplane` implements `WatchStatus` as a trivial always-`Active` stream and
`ExportState`/`ImportState`/`Steer` as no-ops / `UNIMPLEMENTED` (it never blue-greens — it hot-swaps
XDP in place). One proto serves both backends.

### 6.1 Agent handoff (two-port + streamed status)

The agent must not lose config writes across the flip, and must never try to make two instances
co-own a host device. Design:

- **Event-driven, never polling.** Two well-known node-local ports (blue `:1337` / green `:1338`;
  exactly two, roles alternate each upgrade). The agent connects once and holds a `WatchStatus`
  subscription; the *stream* tells it when to act. It dials **both** ports only at **cold start** and
  during **self-heal** after an unexpected disconnect — bounded backoff-retry, never a steady-state
  timer.
- **Connection FSM** (guarantees "always connected"):
  - `Bootstrapping` → dial `{1337,1338}` concurrently, adopt the `Active` responder as `primary` →
    `Steady`.
  - `Steady(primary)` → exactly one live subscription, no timers. Apply config to `primary`.
  - On `primary.successor = :green` (operator spawned green) → `Preparing`: dial the peer, subscribe,
    replay config onto the `Ready` peer (map-state only, below). Both subscriptions live, briefly.
  - On `peer→Active && primary→Draining` → `Switching`: promote peer to primary, stop writing to the
    old, keep it briefly for in-flight.
  - On old `→Retiring`/stream close → `Steady(new primary)`, drop the old channel.
  - Any unexpected close with no known peer → back to `Bootstrapping` (self-heal).
  - `Draining`/`Retiring`/close is also the **reactive fallback** trigger to dial the peer if the
    agent ever missed the `successor` hint (e.g. it reconnected mid-migration).
- **Mutation parking.** During the brief `Switching` window the agent **parks new mutations (hold +
  backoff)** until an `Active`, configured instance is present, then applies. Config mutations are
  CRD-driven and rare, so a sub-second park is invisible.
- **Config replay is map-state only — the critical split.** `AttachInterface` has two kinds of
  effect: (i) **re-derivable datapath map programming** (overlay→underlay, fw/lb/nat/route entries),
  which is idempotent and safe to apply to green while blue is live; and (ii) **host-device
  ownership** (binding the AF_XDP/NIC uplink, creating/owning guest taps), which **cannot** be
  duplicated — two instances binding the same tap or the single clab veth uplink collide (EBUSY, and
  the queue-bind constraint from §5). So the agent replays only (i) onto `Ready` green; (ii) is
  handed off by the operator at `Steer` (step 4). This is the mechanism behind clab's brief-gap:
  green cannot hold the uplink until blue releases it.

**Responsibility split:** agent = config-map convergence (two-port, status-driven); operator =
flow-state snapshot + steering flip + device-ownership handoff; `WatchStatus` = the shared
coordination signal binding the two.

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
- **[C]** Config-ready handshake: how the operator knows the agent has finished replaying config
  onto green before it runs `ExportState`/`Steer` (green exposes an attach-count / config-generation
  the operator polls to match blue, vs an explicit agent signal). Avoid flipping onto a
  half-configured green.
- **[C]** Agent two-port channel lifecycle: `WatchStatus` reconnect/backoff, tolerating `:1338`
  being down in steady state, and the atomic "primary switch" barrier (drain outbound-to-blue, then
  switch) so late writes don't land on a draining instance.

**Non-goals:** mixed eBPF/DPDK clusters (whole-cluster toggle only); zero-gap hitlessness on clab;
removing kustomize before the Helm chart passes a live clab smoke; changing the agent (it stays
dataplane-agnostic).
