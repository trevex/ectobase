# Link-Pinning for Zero-Downtime Datapath Restart — Design

> **Context:** Follow-on to the graceful-restart work (hardening backlog item #1, branch
> `hardening/resilience-security`, commits `127e021`→`169dd7f`). That work made the datapath
> *state* survive an flowplane restart (pinned maps + adopt + `IFACE_META` journal). This adds
> *forwarding continuity* — the eBPF programs stay attached across the restart, closing the
> ~1–2 s packet gap the current design opens by re-attaching fresh.

## Problem

flowplane attaches its programs via `bpf_link`s owned by the process — `uplink_rx` on the fabric uplink,
`wan_rx` on the edge, and a guest program per veth. On kernel ≥ 6.6 (our nodes are 7.0.11), aya
attaches XDP via `bpf_link_create` and tc via **tcx** (`BPF_TCX_INGRESS`), so *all three are fd-owned
links*. When the process exits, the links are destroyed and the programs **detach**. On restart,
`Serve` re-attaches fresh — so between old-process-death and new-process-attach there is a window
with no program on the uplink, and overlay packets for this node aren't decapped/delivered. That
window is the last remaining interruption in an otherwise state-preserving restart.

## Goal

A process restart — crash, OOM, liveness-kill, `crictl stop`, **or a rolling image upgrade** — causes
**zero** forwarding gap. Behind a flag, default on.

## Key mechanism (how Cilium does it, and what aya gives us)

The datapath (programs + maps) lives in the kernel independently of the agent process. Two primitives
make a restart seamless:

1. **Pinned links.** An fd-owned `bpf_link` normally dies when the last fd closes. Pinning it to bpffs
   (`FdLink::pin`) makes it — and thus the attached program — outlive the process. The restarted
   process re-opens it with `PinnedLink::from_pin`.
2. **Atomic program replace.** `bpf_link_update` re-points an existing, still-attached link at a new
   program with no detach/re-attach and **no packet gap**. aya exposes this publicly as
   `Xdp::attach_to_link(link)` and `SchedClassifier::attach_to_link(link)` — both documented as
   *"atomically replaces the program referenced by the provided link."*

Together these mean: the program never leaves the hook across a restart, and the new process
atomically swaps in its own (possibly newer) bytecode. This is exactly Cilium's model (classic
`cls_bpf`/XDP persist for free; the tcx/bpf_link era pins links + uses `bpf_link_update`).

## Flag

New `Serve` flag `--pin-links` (bool, **default true**), with env fallback `FLOWPLANE_PIN_LINKS` for the
DaemonSet. Threaded into `Control::bring_up`, `attach_edge`, and the guest attach path.
`--pin-links=false` restores today's Task-5 behavior exactly (in-process links, fresh re-attach on
restart) — the safe rollback.

## What gets pinned

The `bpf_link`s, under `<pin_dir>/links/<name>`:

| Link path | Program | Hook |
|-----------|---------|------|
| `links/uplink-<iface>` | `uplink_rx` (+ extra uplinks) | XDP (`FdLink`) |
| `links/wan-<iface>` | `wan_rx` (edge role) | XDP (`FdLink`) |
| `links/guest-<interface_id>` | `tc_guest_tx` (tcx) or `guest_tx` (XDP) | tcx / XDP (`FdLink`) |

All are `FdLink`s on our kernels, so all pin uniformly. (On a kernel < 6.6, tc attach falls back to
netlink `cls_bpf`, which is *not* an `FdLink`: it already persists across the process on its own, but
can't be re-opened/updated as a link — in that case the guest edge keeps today's re-attach behavior.
Guarded by the Task-0 spike; the uplink/wan XDP path is unaffected.)

## Adopt logic (atomic replace — no version marker)

`Serve` starts, `adopt` (pins present), `--pin-links` on:

1. Load a fresh eBPF object (its programs are the new bytecode; also needed for map handles and future
   new-pod attaches) and rebuild in-memory bookkeeping from `IFACE_META` (unchanged).
2. For each expected link (uplinks, wan if edge, and each recovered guest):
   - **Pin exists:** `PinnedLink::from_pin(path)` → `<Prog>::attach_to_link(link)`. This is an atomic
     `bpf_link_update` that re-points the still-attached link at the freshly-loaded program. **Zero
     gap.** Whether the bytecode is identical (crash/OOM) or newer (upgrade), the swap is atomic and
     the result is always the current binary's program. Store the returned link handle so
     DetachInterface / clean shutdown can `unpin()` + drop it.
   - **Pin missing** (e.g. a link that wasn't pinned before, or first-ever start): attach fresh and
     pin — the normal fresh path.
3. `--pin-links=false`: today's fresh re-attach path (Task 5), unchanged.

No build-version marker, no `BUILD_INFO` map, no version compare, no detach/re-attach branch — the
atomic re-point is correct and gap-free for every case, so the gate is unnecessary.

### Why atomic re-point is always correct

`bpf_link_update` swaps the program a link points to in one kernel operation; the hook is never
empty. Every state map is pinned and shared, so both the old (pre-swap) and new (post-swap) program
instances read/write the same maps the control plane manages. Re-pointing to identical bytecode is a
harmless atomic no-op; re-pointing to new bytecode is the upgrade — both gap-free.

## Guest attach / detach

- `create_interface` (pin-links on): after attaching the guest program, pin its link to
  `links/guest-<interface_id>`.
- `reattach_guest` (adopt): `from_pin` + `attach_to_link` (atomic re-point) instead of a fresh attach.
- `detach_interface` (pin-links on): `unpin()` + remove `links/guest-<interface_id>` in addition to
  dropping the handle, so a deleted pod's program does not linger across a later restart.

## Interaction with existing graceful-restart code

Layers on the merged Task 1–7 work, same seams:
- `loader.rs`: generalize `attach_xdp_pinned`; add a tc-link pin helper, a `from_pin` re-open helper,
  and thin wrappers over `Xdp::attach_to_link` / `SchedClassifier::attach_to_link`. Keep the
  non-pinned helpers for `--pin-links=false`.
- `control.rs`: `bring_up` / `reattach_guest` / `create_interface` / `detach_interface` gain the
  pin-links branch (pin on attach; from_pin + attach_to_link on adopt; unpin on detach). Store the
  re-opened link handles in `Inner.links` (extend `GuestLink`) and new fields for the uplink/wan
  links (today the uplink link is dropped into the ebpf object; it must become a pinnable, held link).
- `main.rs`: `Serve` passes `--pin-links` through; the adopt branch drives from_pin + attach_to_link
  for the uplink(s)/wan, then per-guest.
- The `IFACE_META` journal, map pinning, SIGTERM handling, and IPAM reseed are unchanged.

## Testing

- **Unit:** pin-path construction and the adopt decision (pin-exists → re-point vs pin-missing →
  fresh), factored pure where possible.
- **Live (clab — verifiable for the uplink; the mechanism does not depend on the guest-tc no-op):**
  extend `test/scenario-restart.sh`:
  - Capture the uplink XDP **program id** via `bpftool net show` (not `tc filter show`, which does not
    list tcx) before and after a `crictl stop`. Same-image restart → **the link stays attached** and
    the program id reflects the new process's program via the atomic swap; critically, assert **no
    detach happened** (the uplink is never program-less — e.g. a flow kept open across the restart
    sees no loss / the pinned link path exists throughout).
  - Assert the pinned link files under `<pin_dir>/links/` survive the restart.
- **Guest-tc:** assert the re-open + `attach_to_link` path runs without error and query attachment via
  `bpftool net show dev <veth>` (tcx section). True guest zero-gap needs a native-tap fabric — on clab
  the tcx program does not land (confirmed: `bpftool net show` `tc:` empty), so guest packet-egress
  stays out of scope here.
- **Tooling fix:** replace the `tc filter show … ingress` guest check in `scenario-restart.sh` with
  `bpftool net show`, which shows tcx attachments.

## Risks / rollback

- **Kernel < 6.6 (no tcx):** guest tc attach is netlink `cls_bpf` — not an `FdLink`, so
  `from_pin`/`attach_to_link` don't apply; the guest edge keeps today's re-attach (it persists on its
  own anyway). Uplink/wan XDP zero-gap is unaffected. Confirmed/branched by the Task-0 spike.
- **Stale pinned link with no live program** (crash mid-operation): adopt treats a missing/invalid pin
  as "pin missing" and attaches fresh + re-pins.
- **`attach_to_link` semantics differ from expectation on this kernel/aya:** the Task-0 spike attaches,
  pins, re-opens, and `attach_to_link`s a program on a scratch interface and asserts no gap before we
  wire it into the datapath.
- **Rollback:** `--pin-links=false` reverts to the merged, tested Task-5 behavior. No data-format
  change — pinned maps and the `IFACE_META` journal are independent of link pinning.
