# HA & graceful restart

!!! success "Status: Implemented"
    Adopt-and-repoint (pinned maps + pinned bpf-links) is the default on kernels ≥ 6.6 and is
    proven zero-drop by the continuity test on the lab fabric.

A `flowplane` process restart — a crash, OOM, liveness-kill, `crictl stop`, or a rolling image
upgrade — causes zero forwarding gap. The datapath (eBPF programs + state maps) lives in the
kernel independently of the agent process; two bpffs-pinning primitives make a restart seamless:
state survives, and the programs never leave their hooks.

The mechanism is adopt-and-repoint, not detach-and-reattach.

## The two things that survive a restart

### 1. Pinned state maps + the `IFACE_META` journal

`flowplane`'s state maps (conntrack, NAT, routes, the per-port `PortMeta`, ...) are pinned
to bpffs (default `/sys/fs/bpf/flowplane`). A pinned map outlives the process that created it, so
its contents — live conntrack, NAT allocations, learned routes — are intact when the new process
starts. On restart the new process adopts the pinned maps rather than recreating them.

The in-memory bookkeeping the process needs (which interfaces exist, their IDs, IPs, VNIs) is
rebuilt from an `IFACE_META` journal: an on-bpffs record of every attached interface, replayed at
startup. There is no underlay address pool to reseed: every interface on the node is programmed with
the one node VTEP, so a restart re-derives the same underlay rather than re-allocating one.

### 2. Pinned bpf-links + atomic re-point

An fd-owned `bpf_link` normally dies when the last fd closes, detaching the program. On kernel ≥ 6.6
every forwarding attach is an fd-owned link — tcx for veth/tap/geneve devices, a netkit link
(`bpf(BPF_LINK_CREATE)` with `BPF_NETKIT_PEER`) for a netkit primary — so all pin uniformly under
`<pin_dir>/links/<name>`:

| Link path | Program | Hook |
|---|---|---|
| `links/uplink-geneve` | `uplink_rx` | tcx ingress on the geneve `collect_md` device (`fp-geneve0`) |
| `links/uplink-dsr-note-geneve` | `uplink_dsr_note` | tcx ingress on the same geneve hook, ordered first |
| `links/wan-<iface>` | `wan_rx` (edge role) | tcx ingress on the WAN uplink |
| `links/uplink-<iface>` | `uplink_rx` on an `--extra-uplink` | tcx ingress on that NIC |
| `links/guest-<hex(interface_id)>` | `tc_guest_tx` | tcx ingress on a veth/tap, or netkit PEER on a netkit primary |

No program pins as an XDP link — the forwarding datapath is entirely tcx/netkit, and the one
remaining XDP program is the `flowplane inspect` debug dumper, which nothing pins (see
[Datapath programs](dataplane/programs.md)).

Pinning a link to bpffs makes it — and thus the attached program — outlive the process. On restart
the new process re-opens each pin and atomically re-points it at the freshly-loaded program in one
kernel operation: `PinnedLink::from_pin` + `attach_to_link` for a tcx link, `bpf(BPF_OBJ_GET)` +
`bpf(BPF_LINK_UPDATE)` for a netkit link (`readopt_tc_link` / `readopt_netkit_link` in
`flowplane/src/loader.rs`). The hook is never empty.

```mermaid
sequenceDiagram
    participant Old as old flowplane
    participant K as kernel (bpffs)
    participant New as new flowplane
    Old->>K: pin maps + pin links (uplink/wan/guest)
    Note over Old: process exits (crash / upgrade / kill)
    Note over K: programs STAY attached via pinned links;<br/>maps keep conntrack/NAT/route state
    New->>K: adopt pinned maps + replay IFACE_META
    New->>K: from_pin(link) + attach_to_link (bpf_link_update)
    Note over K: atomic re-point → hook never empty → ZERO gap
```

## Why atomic re-point is always correct

`bpf_link_update` swaps the program a link points to in a single operation:

- Same bytecode (crash / OOM / liveness-kill): re-pointing to identical bytecode is a harmless
  atomic no-op — the program was never off the hook.
- New bytecode (rolling upgrade): the swap is the upgrade, still gap-free.

Every state map is pinned and shared, so the pre-swap and post-swap program instances read/write the
same maps the control plane manages. There is no version marker, no build-info compare, and no
detach/re-attach branch — the re-point is correct and gap-free for every case, so no gate is needed.

## Flag and rollback

Link pinning is controlled by `--pin-links` (env `FLOWPLANE_PIN_LINKS`), default on.
`--pin-links=false` restores in-process links with a fresh re-attach on restart — the safe rollback,
with no data-format change (pinned maps and the `IFACE_META` journal are independent of link
pinning). Nothing in the fabric or the charts runs with it off today, the
[WAN edge](../features/ns-edge.md) included: co-located edge sidecars are isolated by a per-edge
bpffs `--pin-dir` (`/sys/fs/bpf/flowplane-edge1` / `-edge2`) instead, so they keep pinned-link
zero-gap restart — see the [runbook](../operations/runbook.md). One case the flag cannot cover: a
netkit guest attach exists only on the pinning path and is rejected outright with pinning off
(`netkit attach requires pin-links mode`).

Kernels < 6.6 have no tcx: aya's `SchedClassifier::attach` falls back to a netlink `cls_bpf` attach,
whose link cannot be pinned to or re-opened from bpffs — `attach_tc_pinned_at` fails loudly ("tc link
is not a tcx FdLink (kernel < 6.6); pinning unavailable") rather than silently degrading. Link
pinning therefore needs ≥ 6.6 for every hook alike (geneve, WAN, guest); on an older kernel run with
`--pin-links=false` and accept a fresh re-attach on restart.

## The zero-drop test

`TestRestartContinuity` (`test/lab/livetest/restart_test.go`) formalizes the guarantee. A continuous
cross-cluster overlay ping (60 probes at 0.2 s — a ~12 s window) runs through one compute node's
datapath while that node's `flowplane` DaemonSet pod is deleted and rescheduled (Talos nodes are
shell-less, so the test deletes the pod and lets the DaemonSet reschedule it rather than driving
`crictl`), asserting the unique fingerprint of adopt-and-repoint:

1. Packet loss across the restart boundary is ≤ the threshold (15 of the 60 probes).
2. The pinned bpf-link at `/sys/fs/bpf/flowplane/links/guest-<hex(interface_id)>` survived the pod
   delete — the source endpoint is a netkit L3 guest, and the pin is present both before and after,
   proving the link was held by the node's hostPath bpffs, not the process.
3. The prog-id bound to that pinned link changed (before → after) — proving the restart atomically
   re-pointed the link at the freshly-loaded `tc_guest_tx` (`readopt_netkit_link` →
   `bpf(BPF_LINK_UPDATE)`), not a detach + re-attach (which would open a gap).

Both prog-ids are read with the host `bpftool -j link show pinned <pin>`, reaching the node's bpffs
through `/proc/<node-pid>/root` — the link pin itself, not `bpftool net show` and not `tc filter
show`. The pin-survived + prog-id-changed combination is the signature that distinguishes a true
zero-gap re-point from a detach/reattach. The loss threshold is sized for the pod stop + reschedule +
adopt window on the clab fabric, not for a datapath detach: the link stays attached throughout.

The `make ha` target runs the pinned-maps kill+adopt smoke (state survival); the continuity scenario
adds the forwarding-gap assertion on top.
