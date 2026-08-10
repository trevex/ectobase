# Runbook & known gotchas

!!! success "Status: Implemented"
    Each gotcha below has a root cause and a concrete workaround wired into the tooling
    (the `test/lab` CLI, the edge sidecar wrapper, or `make bpf-clean`).

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
map refcount frees the kernel memory), and repeats the sweep inside every running kind/clab node
container. Run `make bpf-clean` whenever a debugging session (host-run netns scenarios, crash
restarts, or repeated `make lab-up`/`lab-down` cycles) accumulates memory — a `clab destroy`
removes the containers but never touches the host-side pins.

## Edge dual-XDP-attach in SKB mode — `FLOWPLANE_PIN_LINKS=false`

A [WAN edge](../features/ns-edge.md) attaches **two** XDP programs: `uplink_rx` on the fabric uplink
(egress decap) and `wan_rx` on the WAN uplink (NAT-return re-encap). In **SKB/generic XDP** mode
(clab veths have no native XDP), **pinning the first link and then attaching the second XDP program
silently drops the first attachment** — an aya generic-XDP `bpf_link` quirk. Only one of
`uplink_rx`/`wan_rx` ever lands, and egress decap breaks.

The edge sidecar therefore attaches with **`--pin-links false`**
(`test/lab/templates/flowplane/edge-wrapper.sh`). This is safe because the edge is
stateless/drain-safe anycast — either edge handles any return, so it
does not need pinned-link zero-gap HA. Its **maps still pin** for conntrack continuity; only the
links re-attach fresh on restart, which also avoids adopting a stale link across a fabric recreate
(a dead ifindex). Non-edge nodes keep `--pin-links` on (see [HA & restart](../architecture/ha-graceful-restart.md)).

## Native XDP is blocked under vhost (ironcore-in-a-box)

In an ironcore-in-a-box style VM host, **native XDP on the VM tap is blocked** while SKB/generic mode
works end-to-end. The cause is the vhost chain: guest traffic goes `vhost-net → KVM`, and native XDP
on the `tun`/tap under vhost hits an `XDP_TX`-on-vhost-tun limitation. The guest edge is on **tcx**,
which works cleanly under vhost-net regardless (guest→host via `netif_receive_skb` → tcx ingress,
host→guest via the tap qdisc → tcx egress), so the unified guest edge is unaffected. When you need
native-XDP behaviour, use a native-XDP fabric, not the vhost VM path.

## In-container `bpftool` doesn't render tcx — use the devShell `bpftool` via `nsenter`

The `bpftool` shipped inside the kind/clab node containers (v7.1.0) **does not render tcx
attachments** (and renders XDP prog-ids unreliably). Checking a guest tcx attach — or a restart
prog-id — from inside the container shows an empty `tc:`/no prog-id and misleads you into thinking
the program didn't land.

Use the **devShell `bpftool` (v7.6.0)** from the host and `nsenter` into the node's netns instead.
`bpftool net show dev <veth>` renders the tcx section correctly; `bpftool net show` renders the
uplink XDP prog-id (this is what the restart-continuity test uses, not `tc filter show`, which does
not list tcx). This is a **tooling artifact, not a datapath failure**: the guest tcx program
attaches, forwards (SNAT + encap + redirect), and works — the container's old `bpftool` just can't
display it.

## Quick reference

| Symptom | Cause | Fix |
|---|---|---|
| `sudo` fails to elevate in a sub-script | PATH-shadowed `sudo` on NixOS | use `/run/wrappers/bin/sudo` |
| Host RAM climbs across clab cycles / OOM | leaked pinned conntrack maps | `make bpf-clean` (auto-wired into clab up/down) |
| Edge egress decap broken in clab | 2nd XDP attach drops the 1st in SKB mode | `FLOWPLANE_PIN_LINKS=false` on the edge |
| Native XDP won't attach on a VM tap | vhost-net → KVM `XDP_TX`-on-tun limit | use tcx (default) / a native-XDP fabric |
| `bpftool` shows no tcx / no prog-id | in-container bpftool v7.1.0 | devShell bpftool v7.6.0 via `nsenter` |

See the [clab + kind fabric](./local-fabric.md) doc for the fabric-level host/kernel interactions
(bridge-nf ND drop, the deploy pty, VyOS/Cilium bring-up) that the bring-up scripts also handle.
