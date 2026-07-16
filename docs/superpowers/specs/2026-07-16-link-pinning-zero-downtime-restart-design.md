# Link-Pinning for Zero-Downtime Datapath Restart — Design

> **Context:** Follow-on to the graceful-restart work (hardening backlog item #1, branch
> `hardening/resilience-security`, commits `127e021`→`169dd7f`). That work made the datapath
> *state* survive an xdp-dp restart (pinned maps + adopt + `IFACE_META` journal). This adds
> *forwarding continuity* — the eBPF programs stay attached across the restart, closing the
> ~1–2 s packet gap while the old design re-attached fresh.

## Problem

Today, xdp-dp attaches its programs via `bpf_link`s owned by the process (`uplink_rx` on the fabric
uplink, `wan_rx` on the edge, and a guest program per veth). When the process exits, those links are
destroyed and the programs **detach**. On restart, `Serve` re-attaches them fresh. Result: the maps
survive (pinned), but there is a brief window between old-process-death and new-process-re-attach
where no program is on the uplink, so overlay packets for this node aren't decapped/delivered. That
window is the last remaining interruption in an otherwise state-preserving restart.

## Goal

Make a **same-image process restart** (crash, OOM, liveness-kill, `crictl stop`) cause **zero**
forwarding gap: the programs stay attached the whole time. Preserve correctness on an **image
upgrade** (new bytecode must actually take effect). Keep it behind a flag, default on.

## Non-goals

- Fixing the clab guest-tc-egress no-op (orthogonal attach-reliability issue; see
  `clab-container-datapath-gaps`). Link-pinning does not make clab NAT/LB egress reliable.
- Zero-gap across a genuine bytecode change — an upgrade intentionally accepts a brief gap to load
  the new program.
- Native vs generic XDP mode (unchanged; still `XDP_DP_SKB_MODE`-gated).

## Flag

New `Serve` flag `--pin-links` (bool, **default true**), mirrored by an env fallback
(`XDP_DP_PIN_LINKS`) for the DaemonSet. Threaded into `Control::bring_up`, `attach_edge`, and the
guest attach path. `--pin-links=false` restores today's Task-5 behavior exactly (in-process links,
re-attach on restart) — the safe rollback.

## What gets pinned

The `bpf_link`s, under `<pin_dir>/links/<name>`:

| Link | Program | Hook | Pinnable? |
|------|---------|------|-----------|
| `links/uplink-<iface>` | `uplink_rx` (+ extra uplinks) | XDP | **Yes** (XDP link is an `FdLink`; `attach_xdp_pinned` already proves this) |
| `links/wan-<iface>` | `wan_rx` (edge role) | XDP | **Yes** |
| `links/guest-<interface_id>` | `tc_guest_tx` or `guest_tx` | tc-clsact / XDP | **Best-effort** — see below |

**Guest-tc caveat.** aya's `SchedClassifierLink` wraps either an `FdLink` (tcx / `BPF_LINK_TYPE_TCX`,
kernel ≥ 6.6) or an `NlLink` (classic netlink clsact filter). Only the `FdLink` variant can be pinned.
On kernels/paths where the guest tc attach yields an `NlLink`, we **cannot** pin it — fall back to
re-attach for that link (log it once) and accept the guest-edge gap there. XDP guest mode
(`XDP_DP_GUEST_TC=0`) is always an `FdLink` and pins. A Task-0 spike confirms which variant this
fabric's kernel produces before we rely on guest-tc pinning; the uplink/wan zero-gap does not depend
on it.

## Version marker

The datapath's identity is its compiled bytecode. We track it with a **build version** stamped at
compile time:

- `build.rs` injects `XDP_DP_BUILD` (git sha + dirty flag, falling back to a build timestamp when git
  is absent) as a compile-time env, exposed as a `const`.
- At bring-up (fresh, or on a version-mismatch swap) we write it into a **dedicated tiny pinned
  `BUILD_INFO: Array<u64>`** (slot 0 = a stable hash of `XDP_DP_BUILD`). It is control-plane-only —
  never read by the datapath — mirroring the `IFACE_META` journal pattern, so it does not perturb the
  datapath's `Config` struct/layout. (A field on the existing pinned `CONFIG` array would avoid a new
  map but changes a struct the datapath reads; the isolated map is the lower-risk choice.)
- On adopt we read it back and compare to this binary's `XDP_DP_BUILD`.

> Rationale for the build marker over the kernel program `tag`: it is trivial to read/compare and is
> stable across our release process. `ProgramInfo::tag()` (a hash of the actual bytecode) is a truer
> "same program" signal and is available if we later want rebuild-identical to count as same; it is
> recorded here as the fallback, not the primary.

## Adopt logic (version-gated swap)

`Serve` starts, `adopt` (pins present), `--pin-links` on:

1. Load a fresh eBPF object (needed for map handles and for *future* new-pod attaches) and rebuild
   in-memory bookkeeping from `IFACE_META` (unchanged from the graceful-restart work).
2. Read the pinned build marker.
3. **Same version** (crash / OOM / same-image restart):
   - The pinned links kept the old programs attached the whole time — **do not re-attach**.
   - Re-open each pinned link with `PinnedLink::from_pin(path)` into a managed handle, so
     DetachInterface and clean shutdown can `unpin()` + drop it.
   - The datapath keeps executing the *old* (byte-identical) program instances against the *shared
     pinned maps*, which the new userspace also manages. **Zero gap.**
   - The freshly-loaded program instances stay loaded-but-unattached, ready for future new-pod attaches.
4. **Different version** (image upgrade):
   - `unpin()` + drop each pinned link (detaching the old programs), attach the fresh programs, pin
     the new links, and rewrite the marker. **Brief gap, new bytecode** — the correct upgrade.
5. `--pin-links=false`: today's fresh re-attach path (Task 5), unchanged.

### Why the "old program keeps running" is correct

Under a same-version adopt, program bytecode is identical and every state map is pinned and shared.
The old (attached) and new (loaded-but-idle) program instances reference the same pinned maps, so the
control plane's map writes are seen by the running datapath exactly as before. The new userspace owns
the maps and the re-opened link handles; the old *process* is gone but its *programs* live on via the
pinned links. This is the standard bpf-link-pinning lifecycle.

## Guest attach / detach

- `create_interface` (pin-links on): after attaching the guest program, pin its link to
  `links/guest-<interface_id>` (best-effort per the tc caveat).
- `reattach_guest` becomes version-aware: same-version adopt → `from_pin` re-open; different-version
  or unpinnable link → attach fresh and (re-)pin.
- `detach_interface` (pin-links on): `unpin()` + remove `links/guest-<interface_id>` in addition to
  dropping the in-memory handle, so a deleted pod's program does not linger across a later restart.

## Interaction with existing graceful-restart code

This layers on the merged Task 1–7 work and touches the same seams:
- `loader.rs`: generalize `attach_xdp_pinned` and add a tc-link pin helper + a `from_pin` re-open
  helper; keep the non-pinned helpers for `--pin-links=false`.
- `control.rs`: `bring_up`/`reattach_guest`/`create_interface`/`detach_interface` gain the pin-links
  branch and the version gate; store re-opened `PinnedLink` handles in `Inner.links` (a new enum
  arm, or wrap the existing `GuestLink`).
- `main.rs`: `Serve` computes the version gate and drives same-vs-different-version adopt.
- The `IFACE_META` journal, map pinning, and IPAM reseed are unchanged.

## Testing

- **Unit:** version-compare / gate decision (pure): same → keep, different → swap.
- **Live (clab, uplink — the mechanism is verifiable here even though guest-tc egress is not):**
  extend `test/scenario-restart.sh` to capture the uplink XDP **program id** (`bpftool link`/`ip link`)
  before and after a `crictl stop`:
  - same-image restart → **same uplink prog id** (proves no detach = zero gap) and no packet loss on
    a flow kept open across the restart;
  - simulate a version bump (write a different marker, or a rebuilt image) → prog id **changes**
    (swap path exercised).
- **Guest-tc:** on clab, assert the re-open path runs without error; true guest zero-gap needs a
  native-tap fabric and is out of scope for CI here.

## Risks / rollback

- **tc link not an `FdLink`** → guest-tc pinning impossible; fall back to re-attach for guest links
  (uplink/wan zero-gap still delivered). Gated by the Task-0 spike.
- **Image upgrade keeps old code** if the version gate is wrong → mitigated by the build-sha marker
  and a live swap test; worst case operators set `--pin-links=false` for a guaranteed fresh attach.
- **Stale pinned links after a crash mid-swap** → adopt reconciles: a link pin with no matching live
  program is re-created; on version mismatch all are replaced.
- **Rollback:** `--pin-links=false` reverts to the merged, tested Task-5 behavior with no data-format
  change (pinned maps/journal are independent of link pinning).
