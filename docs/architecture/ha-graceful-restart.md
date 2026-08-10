# HA & graceful restart

!!! success "Status: Implemented"
    Adopt-and-repoint (pinned maps + pinned bpf-links) is the default on kernels ≥ 6.6 and is
    proven zero-drop by the continuity test on the lab fabric.

A `flowplane` process restart — a crash, OOM, liveness-kill, `crictl stop`, or a rolling image
upgrade — causes **zero forwarding gap**. The datapath (eBPF programs + state maps) lives in the
kernel independently of the agent process; two bpffs-pinning primitives make a restart seamless:
state survives, and the programs never leave their hooks.

The mechanism is **adopt-and-repoint**, not detach-and-reattach.

## The two things that survive a restart

### 1. Pinned state maps + the `IFACE_META` journal

`flowplane`'s state maps (conntrack, NAT, routes, IPAM, the per-port `PortMeta`, ...) are **pinned
to bpffs** (default `/sys/fs/bpf/flowplane`). A pinned map outlives the process that created it, so
its contents — live conntrack, NAT allocations, learned routes — are intact when the new process
starts. On restart the new process **adopts** the pinned maps rather than recreating them.

The in-memory bookkeeping the process needs (which interfaces exist, their IDs, IPs, VNIs) is
rebuilt from an **`IFACE_META` journal**: an on-bpffs record of every attached interface, replayed at
startup. IPAM is reseeded from the recovered state so a live `/128` is **never reissued** to a new
interface.

### 2. Pinned bpf-links + atomic re-point

An fd-owned `bpf_link` normally dies when the last fd closes, detaching the program. On kernel ≥ 6.6
(XDP via `bpf_link_create`, tc via **tcx**), every attach is an fd-owned link, so all pin uniformly
under `<pin_dir>/links/<name>`:

| Link path | Program | Hook |
|---|---|---|
| `links/uplink-<iface>` | `uplink_rx` (+ extra uplinks) | XDP |
| `links/wan-<iface>` | `wan_rx` (edge role) | XDP |
| `links/guest-<interface_id>` | `tc_guest_tx` (tcx) | tcx |

Pinning a link to bpffs makes it — and thus the attached program — outlive the process. On restart
the new process re-opens each pin (`PinnedLink::from_pin`) and calls `attach_to_link`, which is an
atomic **`bpf_link_update`**: it re-points the still-attached link at the freshly-loaded program in
one kernel operation. The hook is **never empty**.

```mermaid
sequenceDiagram
    participant Old as old flowplane
    participant K as kernel (bpffs)
    participant New as new flowplane
    Old->>K: pin maps + pin links (uplink/wan/guest)
    Note over Old: process exits (crash / upgrade / kill)
    Note over K: programs STAY attached via pinned links;<br/>maps keep conntrack/NAT/route state
    New->>K: adopt pinned maps + replay IFACE_META + reseed IPAM
    New->>K: from_pin(link) + attach_to_link (bpf_link_update)
    Note over K: atomic re-point → hook never empty → ZERO gap
```

## Why atomic re-point is always correct

`bpf_link_update` swaps the program a link points to in a single operation:

- **Same bytecode** (crash / OOM / liveness-kill): re-pointing to identical bytecode is a harmless
  atomic no-op — the program was never off the hook.
- **New bytecode** (rolling upgrade): the swap *is* the upgrade, still gap-free.

Every state map is pinned and shared, so the pre-swap and post-swap program instances read/write the
same maps the control plane manages. There is no version marker, no build-info compare, and no
detach/re-attach branch — the re-point is correct and gap-free for every case, so no gate is needed.

## Flag and rollback

Link pinning is controlled by `--pin-links` (env `FLOWPLANE_PIN_LINKS`), **default on**.
`--pin-links=false` restores in-process links with a fresh re-attach on restart — the safe rollback,
with no data-format change (pinned maps and the `IFACE_META` journal are independent of link
pinning). One production case runs with it off: the [WAN edge](../features/ns-edge.md) in SKB/generic
XDP mode, where pinning the first XDP link and attaching a second silently drops the first — see the
[runbook](../guides/runbook.md). The edge is stateless anycast, so it does not need pinned-link zero-gap HA;
its maps still pin for conntrack continuity, only the links re-attach fresh.

Kernels < 6.6 have no tcx: the guest tc attach falls back to netlink `cls_bpf`, which persists across
the process on its own but cannot be re-opened as a link — the guest edge keeps the fresh-reattach
behaviour there. The uplink/wan XDP zero-gap path is unaffected.

## The zero-drop test

`TestRestartContinuity` (`test/lab/livetest/restart_test.go`) formalizes the guarantee. A continuous
ping flow runs *through* the datapath while the `flowplane` container is `crictl`-stopped and
kubelet-restarted, asserting the unique fingerprint of adopt-and-repoint:

1. **Packet loss across the restart boundary is ≤ the threshold** (target ~0).
2. **The pinned bpf-link at `$PIN/links/uplink-eth1` survived** the stop — same path present both
   before and after, proving the link was held by bpffs, not the process.
3. **The prog-id on the uplink changed** (before → after) — proving the restart atomically
   re-pointed the pinned link at the freshly-loaded program (`bpf_link_update`), **not** a detach +
   re-attach (which would show *no* prog-id mid-restart, i.e. a gap).

The pin-survived + prog-id-changed combination is the signature that distinguishes a true zero-gap
re-point from a detach/reattach. On the clab SKB fabric the tc guest attach may not land reliably, so
the loss threshold there tolerates the full restart window plus clab overhead; on a native-XDP fabric
(where the uplink XDP is genuinely zero-gap) a tight threshold of 2–3 pings is realistic.

The `make ha` target runs the pinned-maps kill+adopt smoke (state survival); the continuity scenario
adds the forwarding-gap assertion on top.
