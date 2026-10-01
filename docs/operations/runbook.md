# Runbook

This page collects the operational problems that have cost real debugging time, each with its
symptom, its cause and the fix. The first entries concern a running fleet: fences, storage and
upgrades. The later ones concern the lab and a development host.

Several fixes are wired into the tooling (`test/lab`, `hack/bpf-cleanup.sh`). Don't simplify
those away: each one is there because the problem came back without it.

## Quick reference

| Symptom | Cause | Fix |
|---|---|---|
| A recovered pool keeps `status.fencedPrefixes` | fence release is held | [A pool that will not let go](#a-pool-that-will-not-let-go) |
| RBD I/O on a recovered node is refused; `ceph osd blocklist ls` lists its /64 | a stranded blocklist entry | [A stranded Ceph blocklist entry](#a-stranded-ceph-blocklist-entry) |
| `helm upgrade` fails with `spec.strategy.rollingUpdate: Forbidden` | a Deployment created before it moved to `Recreate` | [Deploy with Helm: switching to Recreate](deploy-helm.md#switching-deployments-to-recreate) |
| kine logs `relation "kine" does not exist`; old objects reappear | postgres restarted on an empty data directory | [Deploy with Helm: emptyDir to persistent storage](deploy-helm.md#moving-postgres-from-emptydir-to-persistent-storage) |
| A redeploy keeps running the old code | a cached mutable tag, or an image never pushed | [A redeploy runs the old image](#a-redeploy-runs-the-old-image) |
| Host RAM climbs across lab cycles | leaked pinned BPF maps | [Leaked BPF pins](#leaked-bpf-pins) |
| A fresh lab edge looks programmed but does not forward | it adopted pins from an earlier fabric | [A surviving pin directory is adopted](#a-surviving-pin-directory-is-adopted) |
| `tc filter show` on a node prints nothing | tcx attachments are invisible to `tc` | [Inspecting a Talos node's datapath](#inspecting-a-talos-nodes-datapath) |
| `sudo` fails to elevate inside a nested script | a PATH-shadowed `sudo` on NixOS | [NixOS and the real sudo](#nixos-and-the-real-sudo) |

## A pool that will not let go

A fence (a reflector route fence plus a Ceph `NetworkFence` on the pool's declared
`spec.underlayPrefix`) is how failover isolates a lost pool. A pool without that prefix is never
fenced: its VMs stay put with `FailoverBlocked`. When the pool comes back, the `dispatch-controller` lifts each fence only
once it can show that doing so is safe, and it fails closed. A pool whose `status.fencedPrefixes`
stays non-empty after recovery is a pool where one of those proofs has not arrived. This entry is
the quick check of which one; the diagnosis and the remedies for each case are in
[Failover and rescheduling](../architecture/failover.md#a-pool-that-will-not-let-go).

Start with the pool's status on the dispatch:

```sh
kubectl get clusterpools.platform.ectobase.dev <pool> -o yaml
```

The release code (`releaseDrained` in `dispatch/pkg/failover/failover.go`) lifts a fenced prefix
only when every row of this table holds. Walk it top to bottom.

| Check | Where to look | When it fails |
|---|---|---|
| The pool is reachable | `status.phase` is `Ready` and `status.lease.renewTime` is under 30 seconds old | Nothing is released at all. The broker (`dispatch-broker`) is not renewing its lease. |
| The broker reports the prefix drained | `status.nodeDrain[]` has `drained: true` for that prefix | The broker still sees a VM running on a node whose /64 lies inside it, or cannot list where VMs run and leaves its previous report in place. While the pool was lost the controller marked every entry not drained, so only a report made after recovery counts. |
| No route from inside the prefix is still announced for an address placed on another pool | condition `FenceReleaseBlocked` is `True` with reason `RoutesStillAnnounced` | A node inside the prefix still announces a moved workload's address. The message names each route: VNI, prefix, announcing node, nexthop and the owning NIC. |
| The route check itself works | condition `FenceReleaseBlocked` is `True` with reason `RouteCheckFailed` | The check could not run. The message says why: `reflectorAdmin` is empty (message: no route reflector configured); the reflector is unreachable; it runs an image without `AnnouncedFrom` and answers `Unimplemented`, which happens when the reflector lags the controller during an upgrade ([Upgrade order](deploy-helm.md#upgrade-order)); or the `CompiledNIC` twins could not be listed. |
| Both fences confirm the release | the prefix's `NetworkFence`: `spec.fenceState`, `status.result`, `status.message` | The storage release returns only after csi-addons reports `unfencing operation successful`; until then the prefix stays fenced and the pass retries. The controller does not log a pending or failed release, so read the `NetworkFence` itself. |

A release held on routes is rechecked every 5 seconds; otherwise the controller looks at the pool
again at least every two minutes. When nothing is held any more, `FenceReleaseBlocked` turns
`False` with reason `RoutesWithdrawn`.

For what to do about each failing row, follow
[A pool that will not let go](../architecture/failover.md#a-pool-that-will-not-let-go).

!!! warning "Don't force a release"
    Don't hand-edit the pool's status, and never patch a `NetworkFence` to `Unfenced` while any
    `ClusterPool` lists its prefix in `status.fencedPrefixes`: that lifts the Ceph blocklist past
    the drain and route gates, and nothing re-fences a pool that is not lost. Fix the cause the
    checks name instead.

## A stranded Ceph blocklist entry

The storage fence is a csi-addons `NetworkFence`, a cluster-scoped object on the dispatch named
`ectobase-<prefix>` with `:` and `.` replaced by `-` and `/` by `--` (so `fd00:cafe:1234::/64`
becomes `ectobase-fd00-cafe-1234----64`). csi-addons adds the Ceph blocklist entry while the
object is `Fenced`. Ceph removes the entry when csi-addons reconciles the object with
`spec.fenceState: Unfenced`, which in practice means flipping it from `Fenced` to `Unfenced`.

A stranded entry is a blocklist entry that nothing tracks any more: no `ClusterPool` lists its
prefix in `status.fencedPrefixes`, yet nodes in that /64 are still refused by Ceph. Two ways to
get one:

- An older controller or a hand edit dropped the prefix from `status.fencedPrefixes`.
- A fence that was never confirmed. Failover records a prefix in `status.fencedPrefixes` only
  once csi-addons has confirmed its fence (`failover.go`, the fence loop). The first pass creates
  the `NetworkFence` and returns while the fence is still pending; if the pool's lease comes back
  before the next pass, about two minutes later, the pool is no longer lost and nothing returns
  to that object. It stays `Fenced`, is most likely blocklisted, and no pool lists it.

This section is the only place a hand unfence is allowed, and only when both hold:

- no `ClusterPool` lists the prefix in `status.fencedPrefixes`; and
- the nodes in that /64 are powered off, or provably run none of the VMs that were moved off
  them. A blocklist entry is what stops a stale node from writing to a disk that now belongs to
  a VM on another pool.

Confirm the entry from Ceph (in the lab, `docker exec clab-ectobase-ceph ceph osd blocklist ls`)
and find the object:

```sh
kubectl get networkfences.csiaddons.openshift.io
```

Clear it by patching the object to `Unfenced` and letting csi-addons run the removal:

```sh
kubectl patch networkfences.csiaddons.openshift.io ectobase-fd00-cafe-1234----64 \
  --type=merge -p '{"spec":{"fenceState":"Unfenced"}}'
kubectl get networkfences.csiaddons.openshift.io ectobase-fd00-cafe-1234----64 \
  -o jsonpath='{.status.result} {.status.message}{"\n"}'
```

The removal is done when the status reads `Succeeded unfencing operation successful`. Right after
the patch the status can still show the earlier fence operation's `Succeeded`, so check the
message, not just the result. The object is then spent: you can delete it, and if the prefix is
ever fenced again the controller replaces a spent object with a fresh one.

!!! warning "Never delete a `Fenced` NetworkFence to clear a blocklist entry"
    Deleting the object only drops csi-addons' finalizer; it never unfences. The blocklist
    entry stays in Ceph, with an expiry years out, and now nothing records that it exists. The
    `dispatch-controller` follows the same rule (`Release` in `dispatch/pkg/fence/storage.go`):
    flip to `Unfenced`, wait for the unfence to be reported, then delete.

## A redeploy runs the old image

Two separate things make a rebuilt image fail to reach the nodes.

The charts default to `imagePullPolicy: IfNotPresent`, and the `:dev` tags are mutable. A node
that has the tag cached keeps running it, and the rollout still reports success. The lab passes
`imagePullPolicy=Always` to both charts for this reason; a hand-run install against `:dev` tags
should do the same. See [imagePullPolicy and mutable tags](deploy-helm.md#imagepullpolicy-and-mutable-tags).

In the lab, `make lab-deploy` re-runs only the chart installs. It does not push images: only
`lab up` pushes the locally built `:dev` images into the in-fabric registry. After `make image`
(or `make image-mesh`, and so on), push the image yourself, then restart the workload:

```sh
docker tag ghcr.io/trevex/ectobase/flowplane:dev 127.0.0.1:5000/trevex/ectobase/flowplane:dev
docker push 127.0.0.1:5000/trevex/ectobase/flowplane:dev
```

The nodes pull it as `[fd00:29::5]:5000/trevex/ectobase/flowplane:dev`. A `helm upgrade` whose
rendered pod template did not change starts no rollout, so restart the DaemonSet or Deployment
afterwards.

The WAN edge sidecars run on the host's Docker, not from the in-fabric registry, so they need
their own refresh.

## Leaked BPF pins

`flowplane` pins its maps to bpffs. `CONNTRACK` and `CONNTRACK6` are LRU hash maps of 1,048,576
pre-allocated entries each, so every pinned instance holds a large block of kernel memory. A
pinned map outlives the process that created it. Every host-run scenario script and every crash
leaves a full set behind, and over a debugging session that has grown to tens of gigabytes and
taken the host down. `clab destroy` removes containers but never touches host pins.

The pin directories are:

| Directory | Left by |
|---|---|
| `/sys/fs/bpf/flowplane` | `flowplane serve` (maps and `links/`) |
| `/sys/fs/bpf/flowplane-eph-<pid>` | `flowplane bringup`, `tc-bringup` and debug runs |
| `/sys/fs/bpf/flowplane-edge<n>` | the lab's WAN-edge sidecars, one per edge |

`lab down` sweeps the `flowplane-edge*` directories itself. It deliberately leaves
`/sys/fs/bpf/flowplane` alone, because on a development host that may belong to a `flowplane
serve` the lab did not start.

For everything else, run `make bpf-clean` (`hack/bpf-cleanup.sh`). It kills stray `flowplane
serve`, `bringup` and `tc-bringup` processes so their map file descriptors close, removes the
host pin directories, which frees the maps, and then tries the same sweep inside each running
`clab-ectobase-*` container. Talos nodes have no shell, so that last step skips them with a
message.

!!! warning "Run `make bpf-clean` with the lab down"
    The process kill matches every `flowplane serve` the host can see, including the dataplane
    pods inside running lab nodes and the edge sidecars, and the sweep removes the edge pin
    directories. On a running lab it takes the datapath down with it.

## A surviving pin directory is adopted

A pin directory left behind is not only leaked memory. The next `flowplane serve` with the same
`--pin-dir` adopts it on purpose: that is what makes a graceful restart lose no traffic. Across a
`lab down` and `lab up`, adoption is a trap. The new fabric inherits the old one's maps, and an
edge has run on state from several fabrics earlier: a datapath that looked correctly programmed
and forwarded nothing. This is why `lab down` sweeps `flowplane-edge*`.

The two edge sidecars share the host's bpffs, so each gets its own `--pin-dir`
(`/sys/fs/bpf/flowplane-edge1`, `/sys/fs/bpf/flowplane-edge2`). Without the split they would
collide on the same pinned links and maps, and one edge would silently adopt the other's state.
The in-cluster DaemonSet needs no split: each node has its own bpffs and runs one `flowplane`
pod. See [HA and restarts](../architecture/ha-and-restarts.md) for what adoption restores.

## Inspecting a Talos node's datapath

Talos nodes have no shell and no `bpftool`, so `kubectl exec` and `docker exec` get you nothing.
Inspect a node from the host instead, with the devShell's `bpftool` inside the node's network
namespace:

```sh
pid=$(docker inspect -f '{{.State.Pid}}' clab-ectobase-k02-1)   # the node container
sudo nsenter -t "$pid" -n bpftool net show dev eth1
```

Use `bpftool net show`, not `tc filter show`: the forwarding programs attach through tcx, which
`tc` does not display, so an empty `tc filter show` proves nothing. Pinned objects can be read
through the node's root: BPF links are kernel-global, so
`bpftool -j link show pinned /proc/<pid>/root/sys/fs/bpf/flowplane/links/guest-<hex(id)>` works
from the host. `TestRestartContinuity` (`test/lab/livetest/restart_test.go`) checks a guest
link's `prog_id` across a restart exactly this way.

`flowplane inspect` attaches the one XDP program left, the `xdp_inspect` debug dumper. It tries a
native attach first and, if that fails, retries in generic (SKB) mode and prints why.

## NixOS and the real sudo

On NixOS the setuid `sudo` is `/run/wrappers/bin/sudo`. Nested `nix develop`, containerlab and
helper scripts can shadow `PATH` so that a bare `sudo` resolves to something that cannot
elevate. Scripts that need root pick the wrapper explicitly; use the same guard in any new one:

```sh
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
elif [ -x /run/wrappers/bin/sudo ]; then
  SUDO=/run/wrappers/bin/sudo
else
  SUDO=sudo
fi
```

## Where to go next

- [Failover and rescheduling](../architecture/failover.md): how fencing and release work.
- [Deploy with Helm](deploy-helm.md): install, upgrade order and one-time migrations.
- [Fail over a cluster](../guides/failover.md): drive a fence and a release in the lab.
- [Development](../contributing/development.md): the devShell, the lab loop and cleanup after
  `sudo` builds.
