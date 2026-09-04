# Runbook & known gotchas

!!! success "Status: Implemented"
    Each gotcha below has a root cause and a concrete workaround wired into the tooling
    (the `test/lab` CLI or `make bpf-clean`).

Operational findings that cost real debugging. Each has a root cause and a concrete workaround wired
into the scripts — do not "simplify" them away.

## NixOS: the real-`sudo` path

On NixOS the real setuid `sudo` is **`/run/wrappers/bin/sudo`**, not whatever a bare `sudo` on
`PATH` resolves to. PATH-shadowing (common inside nested `nix develop` / clab / Cilium scripts)
breaks a bare `sudo`. The scripts that need root select the wrapper explicitly:

```sh
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
elif [ -x /run/wrappers/bin/sudo ]; then
  SUDO=/run/wrappers/bin/sudo
else
  SUDO=sudo
fi
```

Symptom if you get this wrong: `sudo` in a clab/cilium sub-script fails to elevate or prompts
unexpectedly. Use the same guard in any new privileged script.

## NAT conntrack-map OOM — `hack/bpf-cleanup.sh`

`flowplane` pins its state maps to bpffs. The **`CONNTRACK` map alone is an LruHashMap with
1,048,576 pre-allocated entries (~100–150 MB of *kernel* RAM per instance)**. A pinned map outlives
the process that created it, and two pin locations leak across restarts and host-run scenarios:

- `/sys/fs/bpf/flowplane` — the persistent `serve` dir (maps + `links/`).
- `/sys/fs/bpf/flowplane-eph-<pid>` — per-PID dirs for `bringup` / `tc-bringup` / debug.

Every host-run scenario and every crash-restart leaves a full conntrack map behind. Over a debugging
session this can reach tens of GB and OOM the box. `clab destroy` removes the containers but never
touches host-side pins.

**`hack/bpf-cleanup.sh`** (also `make bpf-clean`) sweeps this idempotently: it kills stray host
`flowplane` processes (so their held map FDs close), `rm -rf`s the host pin dirs (dropping the last
map refcount frees the kernel memory), and tries the same sweep inside every running clab node
container. Talos compute nodes are shell-less, though, so the `docker exec sh` sweep degrades
gracefully there (a per-container skip message) — cleaning up *inside* a Talos node's own bpffs
currently needs a host `nsenter` into its net+mount namespace, which isn't wired into the script
yet. Run `make bpf-clean` whenever a debugging session (host-run netns scenarios, crash restarts,
or repeated `make lab-up`/`lab-down` cycles) accumulates memory — a `clab destroy` removes the
containers but never touches the host-side pins.

## Edge dual-XDP-attach in SKB mode — deferred (P4)

This used to document an aya generic-XDP `bpf_link` quirk (pinning a first XDP link and then
attaching a second silently drops the first) worked around via `--pin-links false` on the
WAN-edge flowplane sidecar's dual attach (`uplink_rx` + `wan_rx`). That sidecar has been pruned
from this fabric; the N/S-LB edge datapath is a later (P4) concern. Non-edge nodes keep
`--pin-links` on (see [HA & restart](../architecture/ha-graceful-restart.md)).

## Native XDP is blocked under vhost (ironcore-in-a-box)

In an ironcore-in-a-box style VM host, **native XDP on the VM tap is blocked** while SKB/generic mode
works end-to-end. The cause is the vhost chain: guest traffic goes `vhost-net → KVM`, and native XDP
on the `tun`/tap under vhost hits an `XDP_TX`-on-vhost-tun limitation. The guest edge is on **tcx**,
which works cleanly under vhost-net regardless (guest→host via `netif_receive_skb` → tcx ingress,
host→guest via the tap qdisc → tcx egress), so the unified guest edge is unaffected. When you need
native-XDP behaviour, use a native-XDP fabric, not the vhost VM path.

## Talos nodes have no in-container `bpftool` — always use the devShell `bpftool` via `nsenter`

Talos nodes are shell-less: there is no `docker exec`/`kubectl exec`-able shell and no `bpftool`
binary inside the node container at all (unlike the old kind nodes, which shipped a full distro —
including a `bpftool` v7.1.0 too old to render tcx attachments anyway). Every datapath debug
command has to reach the node from the **host** instead, via `nsenter` into its network namespace.

Use the **devShell `bpftool` (v7.6.0)** from the host and `nsenter` into the node's netns.
`bpftool net show dev <veth>` renders the tcx section correctly; `bpftool net show` renders the
uplink XDP prog-id (this is what the restart-continuity test uses, not `tc filter show`, which does
not list tcx).

## Quick reference

| Symptom | Cause | Fix |
|---|---|---|
| `sudo` fails to elevate in a sub-script | PATH-shadowed `sudo` on NixOS | use `/run/wrappers/bin/sudo` |
| Host RAM climbs across clab cycles / OOM | leaked pinned conntrack maps | `make bpf-clean` (auto-wired into clab up/down) |
| Edge N/S-LB datapath | pruned from the fabric | deferred (P4) |
| Native XDP won't attach on a VM tap | vhost-net → KVM `XDP_TX`-on-tun limit | use tcx (default) / a native-XDP fabric |
| Need to inspect BPF/tcx state on a node | Talos nodes are shell-less (no in-container bpftool) | devShell bpftool v7.6.0 via `nsenter` from the host |

See the [clab + Talos fabric](./local-fabric.md) doc for the fabric-level host/kernel interactions
(bridge-nf ND drop, FRR bring-up) that the bring-up scripts also handle.
