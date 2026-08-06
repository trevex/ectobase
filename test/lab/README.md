# Talos lab harness (`test/lab`)

A Go/[cobra](https://github.com/spf13/cobra) `lab` CLI that stands up a **multi-cluster Talos IPv6-BGP fabric on [containerlab](https://containerlab.dev/)** (containers only, no VMs) and then deploys the **ectobase substrate** (central + brokers) onto it.

The fabric is:

- **VyOS edges** (`edge1`/`edge2`, AS 65000) — `default-originate` (`::/0`) + advertise `64:ff9b::/96`, with **DNS64** forwarding on a loopback and an `eth`→WAN / `eth`→Tayga wiring.
- **VyOS switches** (`sw1`/`sw2`, AS 65010) — transit eBGP to both edges and every Talos node, with **RA** (`service router-advert`) on each host-facing port advertising that port's `/64` + the edge DNS64 name-server.
- **Tayga NAT64** (`nat64-1`/`nat64-2`) — `64:ff9b::/96` → IPv4 pool → MASQUERADE to the WAN, one per edge.
- A **WAN sim** (`wan`) that masquerades all fabric prefixes onto the host uplink and is the host's single route into the fabric.
- A persistent **local registry mirror** (`registry:2`) on the WAN segment.
- **Talos nodes** (`<cluster>-<n>`, AS 65100) as native GoBGP speakers, dual-homed to both switches, advertising a `/128` identity + an anycast API VIP.

Egress is **fabric-only** — no docker side-channel (see below). Each cluster is a distinct Talos cluster (own etcd + anycast API VIP + kubeconfig) on the shared fabric.

This harness is **additive**. It coexists with the existing kind + containerlab bash fabric under `hack/clab` (`hack/clab-up.sh` / `hack/clab-down.sh`, `test/*.sh`); nothing there is changed or removed. The Talos harness exists because the kind fabric has no fabric egress and cannot load kernel modules, which the Tier-2 storage/VM work needs.

## Prerequisites

- **Run inside the nix devShell:** `nix develop`. It provides `go`, `talosctl`, `containerlab`, `kubectl`, `helm`, `skopeo`, and the squashfs/rootfs extraction tooling the images need. (A host `gopls` may warn `go.work requires go >= 1.26.4`; ignore it — always build and test from inside the devShell.)
- **Real root for the live commands.** `up`/`down`/`test` drive containerlab and host networking, so run them under real root:
  ```sh
  sudo -E env "PATH=$PATH" <cmd>
  ```
  On NixOS the real setuid `sudo` is `/run/wrappers/bin/sudo` (a PATH-shadowing `sudo` will break nested elevation).
- **Docker with IPv6 enabled** on the clab management network (the harness routes the host into the fabric over the mgmt net's IPv6 gateway).
- **Disk headroom.** The fabric runs ~12 containers + 3 Talos clusters and pulls images into each node. Talos taints a node `node.kubernetes.io/disk-pressure` once the host disk crosses ~85%, which strands pods as `Pending`. Keep comfortable free space (the lab needs tens of GB). If a deploy stalls on disk-pressure, reclaim and re-run the deploy:
  ```sh
  docker builder prune -f && docker image prune -a -f && docker volume prune -f
  sudo -E env "PATH=$PATH" /tmp/lab deploy
  ```
  The taint clears after kubelet's ~5-minute transition period. Co-resident stale fabrics compound the pressure — tear them down first.

## Quickstart

```sh
nix develop
make lab-images                                   # build talos/vyos/tayga/wan images (first run; needs internet)

# build the binary once, then run the live commands under real root:
go build -o /tmp/lab ./test/lab
sudo -E env "PATH=$PATH" /tmp/lab up              # render → clab → bootstrap clusters + Cilium → deploy ectobase
sudo -E env "PATH=$PATH" /tmp/lab test            # live connectivity + egress + registry + ectobase suite
sudo -E env "PATH=$PATH" /tmp/lab down            # tear down; keeps the registry cache (--purge removes it)
```

`up` can also be run directly with `go run`:

```sh
sudo -E env "PATH=$PATH" go run ./test/lab up
```

> **Note on building:** `go build ./...` from the repo root fails walking the root-owned `test/lab/build/` tree. Build specific packages instead (`./cmd/... ./topology/... ./internal/...`) or the module directory (`cd test/lab && go build -o /tmp/lab .`).

## Commands

| Command | What |
|---|---|
| `lab up` | Render the build tree → deploy the clab fabric → push local `:dev` images into the in-fabric mirror → per cluster bootstrap Talos + install Cilium + wait Ready → deploy the ectobase substrate. |
| `lab down [--purge]` | Destroy the clab topology and remove `build/<name>/`, **preserving the registry cache** for a warm re-up. `--purge` removes the whole build tree including the cache. |
| `lab render` | Expand every template into `build/<name>/` and run `talosctl gen` per cluster. Idempotent; no fabric touched. |
| `lab deploy` | Re-run **only** the ectobase substrate deploy against an already-up fabric (all cluster kubeconfigs must already exist). This is the **fast iteration loop** — no full re-`up`. |
| `lab test` | Run the live connectivity suite: `go test -tags live ./livetest/...`. The tests skip when the fabric is not up. |

**Config selection** is global: `--config <path>` (or `$LAB_CONFIG`) picks the `lab.yaml`. It defaults to `test/lab/lab.yaml`. Root anchors all relative paths (build tree, clab binds) to the config's directory, so the same tree is written regardless of the caller's working directory.

## Config model

One typed `lab.yaml`:

```yaml
name: ectobase
images:
  talos:    ghcr.io/trevex/ectobase/talos:container
  vyos:     ghcr.io/trevex/ectobase/vyos:clab
  tayga:    ghcr.io/trevex/ectobase/tayga:latest
  wan:      ghcr.io/trevex/ectobase/wan:latest
  registry: registry:2
fabric:
  as: { edge: 65000, switch: 65010, host: 65100 }
  nat64Prefix: 64:ff9b::/96
  registry:
    upstreams: [docker.io, ghcr.io, quay.io, registry.k8s.io, gcr.io]
    push: [flowplane, netplane, cni, central-apiserver, central-controller, central-broker]  # :dev
  clusters:
    - { name: central, nodes: 1 }   # hosts the central apiserver + controller + reflector
    - { name: k02, nodes: 1 }       # compute cluster (broker)
    - { name: k03, nodes: 1 }       # compute cluster (broker)
```

`nodes` per cluster is **templatable** (default 1). Validation rejects unknown fields, requires ASNs > 0, node counts 1–15, valid CIDR/addr syntax, and unique cluster names.

### Per-cluster prefix derivation

So parallel clusters on one fabric never collide, every per-cluster/per-node IPv6 prefix is **derived** (never hand-assigned) from an FNV-1a hash of the cluster name:

- Each cluster gets a stable **`/48`** `fd00:cafe:<h>::/48` (where `<h>` is the 16-bit FNV group of its name), and from it a node **`/64`**, an anycast **API VIP** `fd00:cafe:<h>:1::1/128`, and per-cluster Cilium pod/service CIDRs.
- Each node gets a **`/128`** identity `fd00:cafe:<h>::<index>` (the GoBGP-advertised `dummy0`).
- Each node's switch host-ports get an RA **`/64`** `fd00:db8:0:<portSeq>::/64` (`portSeq` is 1-based across *all* clusters, so RA `/64`s are per-switch-port and never overlap).

The whole fabric lives under `fd00:cafe::/32`, which is the single aggregate the host routes into the fabric (via the WAN container).

## Kubeconfigs / access

Per-cluster kubeconfigs land at:

```
test/lab/build/<name>/<cluster>.kubeconfig
```

They are root-owned (written under `sudo`), so read them with a non-interactive sudo:

```sh
sudo -n kubectl --kubeconfig test/lab/build/ectobase/central.kubeconfig get nodes
sudo -n kubectl --kubeconfig test/lab/build/ectobase/k02.kubeconfig     get clusterpools.platform.ectobase.dev
```

## Fabric-only egress (the "no side channel" rule)

The Talos mgmt interface (`eth0`, docker mgmt net) carries **no *preferred* default route**. The node's preferred default (`::/0`) comes only from the edges, learned via GoBGP + the switch RA at `proto ra` / **metric 1024**. So all internet-bound traffic goes:

```
node → switch → edge → (Tayga NAT64 for IPv4) → WAN → internet
```

and DNS is the edge DNS64 loopback. Native dual-stack works: native-v6 destinations egress directly, IPv4 destinations go through NAT64 (`64:ff9b::/96`).

The mgmt net stays a **metric-4096 fallback only**. This "no side channel" posture depends on several mechanics that `up` configures automatically:

- **Per-switch RA `/64`** so native-v6 return routing is symmetric (each node's switch ports advertise a distinct `/64`).
- **Host NAT66 + FORWARD**, auto-configured by `up` with the uplink auto-detected: the WAN masquerades fabric egress onto the clab mgmt subnet, which docker does **not** NAT66 to the host's real uplink — so the host must (`ip6tables` MASQUERADE/FORWARD + `forwarding=1`). This is best-effort: a host with no native-v6 uplink still gets v4/NAT64 egress.
- **The api-vip static pod** demotes the node's docker-mgmt default to a metric-4096 fallback.
- **A clab exec** drops the VyOS mgmt kernel default so it can't compete.

## Registry mirror

A persistent **pull-through + push-local** `registry:2` runs on the WAN segment at `fd00:29::5:5000`, backed by a cache directory `build/<name>/registry-cache` that **survives `down`** (removed only by `down --purge`).

- `up` **pushes the local `:dev` images** (flowplane / netplane / cni / central-\*) into it via the registry's host-published `127.0.0.1:5000`. That loopback is in docker's default insecure-registries, so **no daemon reconfig is needed**.
- **Nodes pull over the fabric** via the Talos `machine.registries.mirrors`, which point each upstream at the registry's fabric address (`fd00:29::5:5000`) — the *same* registry process and storage. Only cold pulls reach the internet, over the WAN.
- Images are stored under the full `trevex/ectobase/<name>` path to match what the Talos mirror forwards.

Because the cache survives `down`, a second `up` is materially faster (no cold pulls).

## Ectobase deploy (last step of `up`)

`up` finishes by deploying the ectobase substrate (this is also what `lab deploy` re-runs on its own):

- **Central cluster** gets `central/config` (the aggregated apiserver + controller, via kustomize) plus the shared **reflector**, the broker's central identity (SA + RBAC), and one pre-created **ClusterPool** per compute cluster.
- **Each compute cluster** gets the `deploy/charts/ectobase` Helm chart with `broker.enabled=true`, wired to central via a minted broker→central token kubeconfig and to central's reflector on the fabric.
- Both compute **ClusterPools converge to `Ready` with `nodePrefixes`**.

**Talos-specific requirement:** the `ectobase-system` namespace is labeled PodSecurity **`privileged`**. Talos enforces the `baseline` PSA level cluster-wide (unlike kind, which doesn't enforce PSA), and the dataplane pods are privileged + hostPID + hostPath / hostNetwork.

## Live test suite (`lab test`)

`go test -tags live ./livetest/...` asserts, against the up fabric:

- **API-VIP anycast** — one path per node to each cluster's anycast VIP.
- **Both ClusterPools `Ready`** with non-empty `nodePrefixes`.
- **Brokers/agents connected** to the central reflector (cross-cluster routebus).
- **Cross-cluster fabric reachability** between nodes of different clusters.
- **NAT64 egress** — a node pings a `64:ff9b::/96`-mapped IPv4 (e.g. `8.8.8.8`).
- **Fabric-only egress** — no default-route line is both `dev eth0` and `metric 1024` (mgmt is not the preferred default); a `proto ra` metric-1024 fabric default *is* installed.
- **≥2-path ECMP** — each node is reachable from both switches.
- **`::/0` origination** by the edges.
- **Switch → node reachability.**
- **Registry mirror serves** — the `v2` root and a pushed local `:dev` manifest.

## Known follow-ups / limitations

- **Cross-cluster overlay ping is not yet automated.** `TestCrossClusterOverlayPing` is **skipped**: the cross-cluster substrate + routebus + fabric datapath are proven, but the full **overlay endpoint-attach** ping (the dataplane `AttachInterface` on `127.0.0.1:1337`, driven by the `NetworkInterface` → `CompiledNIC` → broker → agent pipeline) still needs the netplane compiler running on central plus Talos-specific netns plumbing.
- **Ceph / CSI and the Tier-2 VM-reschedule gate are out of scope** for this harness (a follow-on spec).

### Debugging tips

- Trace fabric hops from inside a container's netns:
  ```sh
  sudo nsenter -t <clab-container-pid> -n ping6 <dst>
  sudo nsenter -t <clab-container-pid> -n tcpdump -ni eth1
  ```
- Inspect route origination on an edge:
  ```sh
  docker exec clab-ectobase-edge1 vtysh -c "show ipv6 route ::/0"
  ```
