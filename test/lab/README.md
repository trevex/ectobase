# Lab harness (`test/lab`)

A Go/[cobra](https://github.com/spf13/cobra) `lab` CLI that stands up a **multi-cluster IPv6-BGP fabric on [containerlab](https://containerlab.dev/)** with **[kind](https://kind.sigs.k8s.io/) clusters as the node substrate**, then deploys the **ectobase substrate** (central + brokers) onto it, plus optional **Ceph + the Tier-2 VM-reschedule gate**.

The fabric is:

- **VyOS edges** (`edge1`/`edge2`, AS 65000) — `default-originate` (`::/0`) + advertise `64:ff9b::/96`, with **DNS64** on a loopback and `eth`→WAN / `eth`→Tayga wiring.
- **VyOS switches** (`sw1`/`sw2`, AS 65010) — transit eBGP to both edges and every node, with per-port **RA** (`service router-advert`) advertising that port's `/64` + the edge DNS64 name-server, and per-node **ToR `/64` origination** (a recursive static via the node's `/128`).
- **Tayga NAT64** (`nat64-1`/`nat64-2`) — `64:ff9b::/96` → IPv4 pool → MASQUERADE to the WAN, one per edge.
- A **WAN sim** (`wan`) that masquerades all fabric prefixes onto the host uplink and is the host's single route into the fabric.
- A persistent **local registry mirror** (`registry:2`) on the WAN segment (`fd00:29::5:5000`).
- **kind clusters** — one per lab cluster. Each kind node runs the `kind-node-fabric` image, which before kubelet establishes a `dummy0` `/128` identity, sets `kubelet --node-ip` to it, and speaks **FRR eBGP** to both switches (`= /128` advertisement). The pod CNI is **kindnet** (+ kube-proxy).
- Optional **Ceph/demo** storage node (`fabric.ceph.enabled: true`) on its own `/64`, for RBD + the Tier-2 storage fence.

Each cluster is a distinct kind cluster (own control plane + kubeconfig) on the shared fabric. Egress is **fabric-only** (no docker side-channel). The clab fabric wiring and the `fabric.View` derivation are substrate-agnostic; the node substrate is kind.

> Why kind (not Talos-in-a-container): the clab `kind:linux` Talos containers had no init and zombied/wedged, which blocked the Tier-2 failover gate. kind nodes have a real init, so `docker`-level node ops are reliable — and the gate itself (fence + reschedule) is the whole point.

## Prerequisites

- **Run inside the nix devShell:** `nix develop`. It provides `go`, `kind`, `containerlab`, `kubectl`, `helm`, `docker`, and the image tooling. (A host `gopls` may warn `go.work requires go >= 1.26.4`; ignore it — always build/test inside the devShell.)
- **Real root for the live commands.** `up`/`down`/`ceph`/`tier2`/`test` drive containerlab + host networking, so run them under real root:
  ```sh
  sudo -E env "PATH=$PATH" <cmd>
  ```
  On NixOS the real setuid `sudo` is `/run/wrappers/bin/sudo` (a PATH-shadowing `sudo` breaks nested elevation).
- **Docker with IPv6 enabled** on the clab management network (the host routes into the fabric over the mgmt net's IPv6 gateway), and the `rbd` kernel module loadable on the host (`modprobe rbd`) for Ceph.
- **Images built** (`make lab-images` + `make image-kindnode`; ceph/frr pull from upstream when `ceph.enabled`). The central `:dev` images (`central-apiserver`/`-controller`/`-broker`) must be built too — `up` pushes local `:dev` images into the fabric mirror, it does not build them.
- **Disk headroom.** The fabric runs ~10 containers + 3 kind clusters and pulls images; keep tens of GB free. Prune co-resident stale fabrics first (`docker builder/image/volume prune`).

## Quickstart

```sh
nix develop
make lab-images && make image-kindnode            # build fabric + kind-node images (first run)

cd test/lab && go build -o /tmp/lab . && cd -      # build the CLI
export LAB_CONFIG=$PWD/test/lab/lab.yaml
sudo -E env "PATH=$PATH" /tmp/lab up               # render → clab → kind clusters (kindnet) → deploy ectobase
sudo -E env "PATH=$PATH" /tmp/lab ceph             # (if ceph.enabled) deploy ceph-csi + csi-addons
sudo -E env "PATH=$PATH" /tmp/lab tier2 up         # (if ceph.enabled) KubeVirt + CDI + vm-materializer
sudo -E env "PATH=$PATH" /tmp/lab test             # the live suite (incl. RBD + Tier-2 failover)
sudo -E env "PATH=$PATH" /tmp/lab down             # tear down; keeps the registry cache (--purge removes it)
```

> **Building:** `go build ./...` from the repo root fails walking the root-owned `test/lab/build/` tree. Build the module (`cd test/lab && go build -o /tmp/lab .`). The CLI **embeds** its templates (`go:embed`) — rebuild it after any `.tmpl` change before `render`/`up`.

## Commands

| Command | What |
|---|---|
| `lab up` | Render → deploy the clab fabric (the `k8s-kind` nodes create the kind clusters with kindnet) → push local `:dev` images into the in-fabric mirror → per cluster collect the kubeconfig + wait Ready → deploy the ectobase substrate. |
| `lab down [--purge]` | Destroy the clab topology (force-removing any wedged VyOS containers) and remove `build/<name>/`, **preserving the registry cache**. `--purge` removes the cache too. |
| `lab render` | Expand every template into `build/<name>/`. Idempotent; no fabric touched. |
| `lab deploy` | Re-run **only** the ectobase substrate deploy against an already-up fabric — the fast iteration loop. |
| `lab ceph [--purge]` | Deploy Ceph (pool + external ceph-csi-rbd + csi-addons on central). Requires `fabric.ceph.enabled`. |
| `lab tier2 up` | Deploy the Tier-2 prerequisites: KubeVirt + CDI + the vm-materializer on each compute cluster, and wire the ceph fsid into central's fence actuator. |
| `lab test` | Run the live suite: `go test -tags live ./livetest/...`. Tests skip when the fabric is not up. |

**Config selection** is global: `--config <path>` (or `$LAB_CONFIG`, default `test/lab/lab.yaml`). Root anchors all relative paths to the config's directory.

## Config model

```yaml
name: ectobase
images:
  kindNode: ghcr.io/trevex/ectobase/kind-node-fabric:dev
  vyos:     ghcr.io/trevex/ectobase/vyos:clab
  tayga:    ghcr.io/trevex/ectobase/tayga:latest
  wan:      ghcr.io/trevex/ectobase/wan:latest
  registry: registry:2
  frr:      frrouting/frr:latest        # only when ceph.enabled
  ceph:     quay.io/ceph/demo:latest     # only when ceph.enabled
fabric:
  as: { edge: 65000, switch: 65010, host: 65100 }
  nat64Prefix: 64:ff9b::/96
  registry:
    upstreams: [docker.io, ghcr.io, quay.io, registry.k8s.io, gcr.io]
    push: [flowplane, netplane, cni, central-apiserver, central-controller, central-broker]  # :dev
  ceph: { enabled: true }               # optional storage node + Tier-2 gate
  clusters:
    - { name: central, nodes: 1 }       # hosts the central apiserver + controller + reflector
    - { name: k02, nodes: 1 }           # compute cluster (broker)
    - { name: k03, nodes: 1 }           # compute cluster (broker)
```

`nodes` per cluster defaults to 1. **kindnet requires 1 node/cluster** on this per-`/64` fabric (its cross-node pod routes would break); multi-node would need flannel.

### Per-cluster prefix derivation

Every per-cluster/per-node prefix is **derived** (never hand-assigned) from an FNV-1a hash `<h>` of the cluster name, so parallel clusters never collide:

- Each cluster: a stable **`/48`** `fd00:cafe:<h>::/48` and from it a node **`/64`** `fd00:cafe:<h>::/64`.
- Each node: a **`/128`** identity `fd00:cafe:<h>::<index>` on `dummy0` (= kubelet InternalIP, FRR-advertised). The ToR originates the node `/64` with a recursive next-hop = this `/128`, so guest-endpoint underlays in the `/64` upper half are fabric-routable.
- Each node's switch host-ports get an RA **`/64`** `fd00:db8:<sw>:<portSeq>::/64` (per-switch, per-port).
- Ceph (when enabled): its own `/64` `fd00:cafe:635::/64`, mon at `::1`.

The whole fabric lives under `fd00:cafe::/32` (the single aggregate the host routes into the fabric via the WAN container).

## Kubeconfigs / access

Per-cluster kubeconfigs (root-owned) land at `test/lab/build/<name>/<cluster>.kubeconfig`:

```sh
sudo -n kubectl --kubeconfig test/lab/build/ectobase/central.kubeconfig get nodes
sudo -n kubectl --kubeconfig test/lab/build/ectobase/k02.kubeconfig     get clusterpools.platform.ectobase.dev
```

## Node substrate + CNI (kind + kindnet)

`clab` creates each kind cluster from `build/<name>/kind/<cluster>-kind.yaml` (ipv6, the `kind-node-fabric` image, `containerdConfigPatches` pointing containerd's registry `config_path` at a mounted `certs.d`). The per-node `fabric-preboot` oneshot (before kubelet):

- creates `dummy0` with the node's `/128` identity, sets `kubelet --node-ip` to it, and runs FRR eBGP on the uplinks advertising that `/128`;
- mounts **bpffs** at `/sys/fs/bpf` (kindnet, unlike Cilium, doesn't — flowplane needs it);
- sets `accept_ra=2` on the uplinks (so the switch RA default installs) and keeps SLAAC on (the RA-SLAAC uplink addr is the WAN-routable egress source).

The **pod CNI is kindnet** (+ kube-proxy), not Cilium: the CNI here only serves ordinary pods (the VM/overlay datapath is flowplane's, independent of the pod CNI). kindnet plain-`MASQUERADE`s pod egress to the per-packet route source (the egress uplink's SLAAC), so pods (e.g. the ceph-csi provisioner) reach the in-fabric mon symmetrically — Cilium couldn't masquerade at all on the unnumbered fabric uplinks.

## Fabric-only egress

The node's preferred default (`::/0`) comes only from the edges via the switch RA (`proto ra`, metric 1024); the docker mgmt default is demoted to metric 4096. Traffic goes `node → switch → edge → (Tayga NAT64 for IPv4) → WAN → internet`. `up` auto-configures the host NAT66 + FORWARD (uplink auto-detected) so the WAN's masqueraded fabric egress reaches the host uplink.

## Registry mirror

A persistent pull-through + push-local `registry:2` runs on the WAN segment at `fd00:29::5:5000`, cache-backed at `build/<name>/registry-cache` (survives `down`). `up` pushes local `:dev` images via the host-published `127.0.0.1:5000` (docker-default-insecure); nodes pull over the fabric via the containerd `certs.d` hosts.toml mirror (the same registry process). The cache makes a second `up` materially faster.

## Ectobase deploy (last step of `up`)

- **Central cluster** gets `central/config` (aggregated apiserver + controller, via kustomize) — with `-reflector-admin` patched to central's fabric identity — plus the shared **reflector**, the broker's central identity, and one pre-created **ClusterPool** per compute cluster.
- **Each compute cluster** gets the `deploy/charts/ectobase` Helm chart (`broker.enabled`, wired to central's apiserver + reflector at central's node identity).
- Both compute **ClusterPools converge to `Ready` with `nodePrefixes`**.

The `ectobase-system` namespace is labeled PodSecurity **`privileged`** (the dataplane pods are privileged/hostPID/hostPath/hostNetwork).

## Ceph + Tier-2 (`lab ceph`, `lab tier2`)

With `fabric.ceph.enabled`:

- `lab ceph` deploys the Ceph pool + external ceph-csi-rbd (on every cluster) + csi-addons (central, the fence executor), and the krbd nodeplugin fixup. The `client.rbd` user is granted `mon 'profile rbd, allow command "osd blocklist"'` so csi-addons can both **fence** (blocklist add) and **un-fence** (blocklist rm).
- `lab tier2 up` deploys KubeVirt + CDI + the vm-materializer and wires the ceph fsid into central's fence actuator.
- **Tier-2 failover gate** (`TestTier2Failover`): a stateful RBD-backed VM materializes on k02; **draining** k02 (scaling its broker to 0 so the ClusterPool lease goes stale) makes central mark the pool Unknown → it **fences** the pool (csi-addons NetworkFence → ceph `osd blocklist`) and **reschedules** the VM to k03; restoring the broker releases the fence (NetworkFence `Fenced`→`Unfenced` → `osd blocklist rm`). The drain is non-destructive — the node + its fabric veths stay intact — and is a realistic "pool unreachable but node alive" storage-fence scenario.

## Live test suite (`lab test`)

`go test -tags live ./livetest/...` asserts, against the up fabric: cluster API + nodes Ready; both ClusterPools Ready with `nodePrefixes`; brokers/agents connected to the reflector; cross-cluster fabric reachability; NAT64 egress; fabric-only egress; ≥2-path ECMP; `::/0` origination; switch→node reachability; registry mirror serves; cross-cluster overlay ping; and (when ceph.enabled) `TestRBDPVCBinds` + `TestTier2Failover`.

`TestTier2Failover` is alphabetically last; on a fresh fabric it runs after the others, and its **drain** (not node-kill) keeps k02 usable throughout.

### Debugging tips

- Trace fabric hops from a container's netns: `sudo nsenter -t <pid> -n ping -6 <dst>` / `... tcpdump -eni eth1`. XDP decap runs before tcpdump on the uplink — capture at the VyOS switch or in the guest netns (drop `-p`, non-promiscuous silently misses veth RX).
- Route origination on an edge/switch: `docker exec clab-ectobase-sw1 vtysh -c "show ipv6 route <prefix>"`.
- Ceph blocklist (Tier-2 fence): `docker exec clab-ectobase-ceph ceph osd blocklist ls`.
