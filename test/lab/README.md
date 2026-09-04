# Lab harness (`test/lab`)

A Go/[cobra](https://github.com/spf13/cobra) `lab` CLI that stands up a **multi-cluster IPv6-BGP fabric on [containerlab](https://containerlab.dev/)** with **Talos-in-container as the node substrate**, then deploys the **ectobase substrate** (dispatch + brokers) onto it, plus optional **Ceph + the Tier-2 VM-reschedule gate**.

The fabric is:

- **FRR edges** (`edge1`/`edge2`, AS 65000) — eBGP `default-originate` (`::/0`) + advertise `64:ff9b::/96`, with a static route handing the NAT64 prefix to Tayga and `eth`→WAN / `eth`→Tayga wiring. (DNS64 is deferred to a later egress spec.)
- **FRR switches** (`sw1`/`sw2`, AS 65010) — a pure `/128` ECMP relay: unnumbered eBGP to both edges and every node (`as-override` re-propagates each node's `/128`), no interface addresses, no originated `/64`, no router-advert.
- **Tayga NAT64** (`nat64-1`/`nat64-2`) — `64:ff9b::/96` → IPv4 pool → MASQUERADE to the WAN, one per edge.
- A **WAN sim** (`wan`) that masquerades all fabric prefixes onto the host uplink and is the host's single route into the fabric.
- A persistent **local registry mirror** (`registry:2`) on the WAN segment (`fd00:29::5:5000`).
- **Talos-in-container compute nodes** — one container per lab-cluster node (`nodes: 1` by default, across 3 clusters: `dispatch`, `k02`, `k03`). Each is a stock siderolabs `talos:container` image run as a plain containerlab `kind: linux` node, booted with `PLATFORM=container` + a base64 `USERDATA=` machine config. Talos' own embedded GoBGP peers unnumbered eBGP to both switches and advertises the node's `dummy0` `/128` identity (= kubelet `--node-ip`). The pod CNI is **Cilium** (container-mode, `kubeProxyReplacement=true` via Talos' KubePrism), coexisting with a thin **Multus** DaemonSet that attaches the flowplane overlay as a secondary network.
- Optional **Ceph/demo** storage node (`fabric.ceph.enabled: true`) on its own `/64`, for RBD + the Tier-2 storage fence.

Each cluster is a distinct single-control-plane Talos cluster (own control plane + kubeconfig) on the shared fabric. Egress is **fabric-only** (no docker side-channel). The clab fabric wiring and the `fabric.View` derivation are substrate-agnostic; the node substrate is Talos-in-container.

## Prerequisites

- **Run inside the nix devShell:** `nix develop`. It provides `go`, `containerlab`, `kubectl`, `helm`, `docker`, `talosctl` (pinned to the Talos release the container image ships, `1.14.0-beta.0` — nixpkgs' `talosctl` only tracks stable and the native GoBGP `BGPPeerConfig` doc needs 1.14+), and the image tooling. (A host `gopls` may warn `go.work requires go >= 1.26.4`; ignore it — always build/test inside the devShell.)
- **Real root for the live commands.** `up`/`down`/`ceph`/`tier2`/`test` drive containerlab + host networking, so run them under real root:
  ```sh
  sudo -E env "PATH=$PATH" <cmd>
  ```
  On NixOS the real setuid `sudo` is `/run/wrappers/bin/sudo` (a PATH-shadowing `sudo` breaks nested elevation).
- **Docker with IPv6 enabled** on the clab management network (the host routes into the fabric over the mgmt net's IPv6 gateway), and the `rbd` kernel module loadable on the host (`modprobe rbd`) for Ceph.
- **Images built** (`make lab-images` + `make image-talos-mirror`; ceph/frr pull from upstream when `ceph.enabled`). `make lab-images` builds the tayga + wan images; `make image-talos-mirror` pulls the pinned upstream `siderolabs/talos` release (`test/images/talos/versions.env`) and tags it into the fabric namespace as `ghcr.io/trevex/ectobase/talos:container` — no local rootfs build needed (that's what `make image-talos` is for, if you need one). The dispatch `:dev` images (`dispatch-apiserver`/`-controller`/`-broker`, plus `flowplane`/`mesh`/`cni`) must be built too — `make lab-app-images` builds all six; `up` pushes them into the fabric mirror, it does not build them.
- **Disk headroom.** The fabric runs ~10 containers + one Talos node container per lab cluster (3 by default) and pulls images; keep tens of GB free. Prune co-resident stale fabrics first (`docker builder/image/volume prune`).

## Quickstart

```sh
nix develop
make lab-images && make image-talos-mirror         # build fabric images + mirror the Talos node image (first run)

cd test/lab && go build -o /tmp/lab . && cd -       # build the CLI
export LAB_CONFIG=$PWD/test/lab/lab.yaml
sudo -E env "PATH=$PATH" /tmp/lab up                # render → clab deploy → talosctl bootstrap → Cilium → deploy ectobase
sudo -E env "PATH=$PATH" /tmp/lab ceph              # (if ceph.enabled) deploy ceph-csi + csi-addons
sudo -E env "PATH=$PATH" /tmp/lab tier2 up          # (if ceph.enabled) KubeVirt + CDI + vm-materializer
sudo -E env "PATH=$PATH" /tmp/lab test              # the live suite (incl. RBD + Tier-2 failover)
sudo -E env "PATH=$PATH" /tmp/lab down              # tear down; keeps the registry cache (--purge removes it)
```

> **Building:** `go build ./...` from the repo root fails walking the root-owned `test/lab/build/` tree. Build the module (`cd test/lab && go build -o /tmp/lab .`). The CLI **embeds** its templates (`go:embed`) — rebuild it after any `.tmpl` change before `render`/`up`.

## Commands

| Command | What |
|---|---|
| `lab up` | Render → deploy the clab fabric (the Talos nodes boot from their per-node `USERDATA` machine config) → push local `:dev` images into the in-fabric registry mirror → per cluster: `talosctl bootstrap` (over clab-mgmt) → wait for the API → install Cilium (container-mode + KubePrism) → wait nodes Ready → deploy the ectobase substrate. |
| `lab down [--purge]` | Destroy the clab topology and remove `build/<name>/`, **preserving the registry cache**. `--purge` removes the cache too. |
| `lab render` | Expand every template into `build/<name>/`, including each cluster's Talos machine-config set (gen'd via `talosctl`) and its Cilium values. Idempotent; no fabric touched. |
| `lab deploy` | Re-run **only** the ectobase substrate deploy against an already-up fabric — the fast iteration loop. |
| `lab ceph [--purge]` | Deploy Ceph (pool + external ceph-csi-rbd + csi-addons on dispatch). Requires `fabric.ceph.enabled`. |
| `lab tier2 up` | Deploy the Tier-2 prerequisites: KubeVirt + CDI + the vm-materializer on each compute cluster, and wire the ceph fsid into dispatch's fence actuator. |
| `lab test` | Run the live suite: `go test -tags live ./livetest/...`. Tests skip when the fabric is not up. |

**Config selection** is global: `--config <path>` (or `$LAB_CONFIG`, default `test/lab/lab.yaml`). Root anchors all relative paths to the config's directory.

## Config model

```yaml
name: ectobase
images:
  talos:    ghcr.io/trevex/ectobase/talos:container
  tayga:    ghcr.io/trevex/ectobase/tayga:latest
  wan:      ghcr.io/trevex/ectobase/wan:latest
  registry: registry:2
  frr:      frrouting/frr:latest        # edges + switches, plus the ceph FRR sidecar
  ceph:     quay.io/ceph/demo:latest     # only when ceph.enabled
fabric:
  as: { edge: 65000, switch: 65010, host: 65100 }
  nat64Prefix: 64:ff9b::/96
  registry:
    upstreams: [docker.io, ghcr.io, quay.io, registry.k8s.io, gcr.io]
    push: [flowplane, mesh, cni, dispatch-apiserver, dispatch-controller, dispatch-broker]  # :dev
  ceph: { enabled: true }               # optional storage node + Tier-2 gate
  clusters:
    - { name: dispatch, nodes: 1 }      # hosts the dispatch aggregated apiserver + controller + reflector
    - { name: k02, nodes: 1 }           # compute cluster (broker)
    - { name: k03, nodes: 1 }           # compute cluster (broker)
```

`nodes` per cluster defaults to 1 — every lab cluster today is a single-node Talos control plane, and Cilium's `operator.replicas` is pinned to 1 to match (its default 2-replica anti-affinity would otherwise leave the second replica permanently unschedulable and wedge `helm --wait`). Nothing in the bootstrap or BGP model itself caps a cluster at 1 node the way kindnet's node-local pod routing used to: `talosctl bootstrap` already treats additional nodes as etcd learners (`max-learners: 3`), and each node speaks its own unnumbered eBGP session — scaling `nodes` is mostly a matter of bumping the Cilium operator replica count/anti-affinity to match, not a fabric limitation.

### Per-cluster prefix derivation

Every per-cluster/per-node prefix is **derived** (never hand-assigned) from an FNV-1a hash `<h>` of the cluster name, so parallel clusters never collide:

- Each cluster: a stable **`/48`** `fd00:cafe:<h>::/48` and from it a node **`/64`** `fd00:cafe:<h>::/64`.
- Each node: a **`/128`** identity `fd00:cafe:<h>::<index>` on `dummy0` (= kubelet `--node-ip`, advertised by Talos' own embedded GoBGP over unnumbered eBGP to both switches). The ToR originates the node `/64` with a recursive next-hop = this `/128`, so guest-endpoint underlays in the `/64` upper half are fabric-routable.
- Each cluster also gets a stable anycast API VIP `fd00:cafe:<h>:1::1`: a health-gated static pod holds it on a `vip0` dummy only while the local apiserver's `/healthz` reports `ok`, and GoBGP advertises `vip0` alongside `dummy0` — `talosctl`/kubectl reach the cluster at this VIP once it's converged.
- Each cluster's pods live in a separate Cilium-owned pool `fd00:244:<h>::/56` (service CIDR `fd00:96:<h>::/108`, hashed the same way, one `/64` per node from `ipam.mode: cluster-pool`) — routed over Cilium's vxlan tunnel between node identities, not part of the `fd00:cafe::/32` BGP-fabric aggregate below.
- Each node's switch host-ports get an RA **`/64`** `fd00:db8:<sw>:<portSeq>::/64` (per-switch, per-port).
- Ceph (when enabled): its own `/64` `fd00:cafe:635::/64`, mon at `::1`.

The whole fabric lives under `fd00:cafe::/32` (the single aggregate the host routes into the fabric via the WAN container).

## Kubeconfigs / access

Per-cluster kubeconfigs (root-owned) land at `test/lab/build/<name>/<cluster>.kubeconfig`:

```sh
sudo -n kubectl --kubeconfig test/lab/build/ectobase/dispatch.kubeconfig get nodes
sudo -n kubectl --kubeconfig test/lab/build/ectobase/k02.kubeconfig      get clusterpools.platform.ectobase.dev
```

## Node substrate + CNI (Talos-in-container + Cilium/Multus)

Each lab-cluster node is a stock siderolabs `talos:container` image (`images.talos`, mirrored by `make image-talos-mirror`) run as a plain containerlab `kind: linux` node — not a VM, not a purpose-built fabric image. containerlab starts it privileged with `env: {PLATFORM: container}` and an `env-files:` pointing at `build/<name>/talos/<cluster>/<node>.env`, a base64 `USERDATA=` machine config rendered by `talos.Gen` (`talosctl gen config` + a per-node patch + the BGP peer doc). Talos' `SetupSharedFilesystems` needs `/run`, `/var` and `/etc/cni` to be real `MS_SHARED` mount points, so those are bind-mounted per node from `build/<name>/mounts/<node>/`, and the host kernel-modules dir is bind-mounted read-only for the kubelet. Each node is dual-homed to the fabric (`eth1`→`sw1`, `eth2`→`sw2`) and **also keeps `clab-mgmt` on `eth0`** — `talosctl` reaches the Talos API over mgmt during bring-up (bootstrap, kubeconfig fetch), before the anycast API VIP + GoBGP have converged.

**Node identity + BGP is Talos-native, not a fabric-preboot script.** Talos' embedded GoBGP (a `BGPPeerConfig` doc, Talos ≥1.14) peers unnumbered eBGP over both uplinks to `sw1`/`sw2` and advertises two things off the node: its `dummy0` `/128` identity (= the `KubeNodeConfig`-pinned kubelet `--node-ip`) and the health-gated anycast API VIP (`vip0`). There is no on-node FRR and no `fabric-preboot` oneshot. There is also no RA/SLAAC default and no kind-bridge `eth0` default to delete: the node's only default route is the BGP-learned `::/0` (originated by the edges, relayed by the switches), and because the node sources fabric egress from its own `/128` VTEP natively, NAT64 egress needs **no** masquerade/route-map patch — the old kind `fabric-preboot.sh` NAT64 fixup is gone entirely. `talos.Gen` also strips the `KubeNodeConfig` control-plane `NoSchedule` taint from the rendered config (Talos otherwise reconciles the taint back on every apply, so a one-shot `kubectl taint -` would race the pods that need to schedule), so these single-node control planes stay fully schedulable.

**The pod CNI is Cilium**, not kindnet: Talos resolves the cluster CNI to `"none"` (the `KubeFlannelCNIConfig` doc is stripped from the base config in `talos.Gen`), so nothing else claims it. `lab up` installs Cilium per cluster from `templates/k8s/cilium-values.yaml.tmpl` — IPv6-only, `routingMode: tunnel` / `tunnelProtocol: vxlan`, `kubeProxyReplacement: true` against Talos' KubePrism (`k8sServiceHost: localhost:7445`), `ipam.mode: cluster-pool` carving a `/64` per node out of the cluster's pod pool, container-mode cgroup settings (`cgroup.autoMount.enabled=false`, `hostRoot: /sys/fs/cgroup`) and the explicit agent capability set Talos documents, and `operator.replicas: 1` to match the single-node clusters.

Cilium coexists with a thin **Multus** DaemonSet (pinned `v4.1.0`, installed after the pool chart on each compute cluster): Multus provides the flowplane overlay's SECONDARY-network attach (`net1`, via a `NetworkAttachmentDefinition` + the pod's `k8s.v1.cni.cncf.io/networks` annotation), while Cilium still owns the pod's primary interface. This only works because the Cilium values set `cni.exclusive: false` — Cilium's default `cni.exclusive: true` renames every other CNI conf (including Multus's `00-multus.conflist`) to `*.cilium_bak`, which would silently break the overlay attach. flowplane itself — the Geneve overlay datapath on `netkit mode l3` pod devices, a privileged DaemonSet — is unchanged and independent of whichever pod CNI is primary.

## Fabric-only egress

The node's preferred default (`::/0`) arrives via Talos' embedded GoBGP peering unnumbered eBGP to both switches, originated by the edges (`default-originate`) and relayed by the switches — no RA involved, no on-node FRR needed. There is no kind-bridge default to delete: GoBGP is the node's only route source for `::/0`. Traffic goes `node → switch → edge → (Tayga NAT64 for IPv4) → WAN → internet`. `up` auto-configures the host NAT66 + FORWARD (uplink auto-detected) so the WAN's masqueraded fabric egress reaches the host uplink.

## Registry mirror

A persistent pull-through + push-local `registry:2` runs on the WAN segment at `fd00:29::5:5000`, cache-backed at `build/<name>/registry-cache` (survives `down`). `lab up` pushes the locally-built `:dev` app images (`fabric.registry.push`) via the host-published `127.0.0.1:5000` (docker-default-insecure) — there is no `kind load` sideload and no purpose-built node image to bake them into. Each Talos node's containerd mirrors `ghcr.io` at this same registry via a declarative `machine.registries.mirrors` doc in its rendered machine config (not a mounted `certs.d`), falling through to real `ghcr.io` for anything the mirror 404s; every other upstream (`quay.io`/`docker.io`/`registry.k8s.io`/`gcr.io`) is pulled directly. The cache makes a second `up` materially faster.

## Ectobase deploy (last step of `up`)

- **Dispatch cluster** gets the `charts/ectobase-dispatch` Helm chart (aggregated apiserver + controller + kine, the mesh compiler, the shared **reflector**, and the dispatch-side broker identity) — with `-reflector-admin` set to the dispatch's fabric identity via a chart value. If route-bus mTLS is on (the default; `ECTOBASE_ROUTEBUS_MTLS=false` disables it), cert-manager is installed on the dispatch cluster first, since the chart's `Issuer`/`ClusterIssuer`/`Certificate` objects need its webhook. The lab then mints the broker→dispatch token/kubeconfig and pre-creates one **ClusterPool** per compute cluster (test fixtures around the install).
- **Each compute cluster** gets the `charts/ectobase-pool` Helm chart (dataplane + agent + broker + cni + pod-materializer; vm-materializer under `lab tier2`) — cert-manager first if mTLS is on — wired to the dispatch's reflector at the dispatch's node identity and to its own local apiserver, then the thin **Multus** DaemonSet (installed after the chart, so `flowplane-cni` + the dataplane kubeconfig already exist).
- Both compute **ClusterPools converge to `Ready` with `nodePrefixes`**.

The pool's `ectobase-system` namespace is created PodSecurity **`privileged`** (the dataplane pods are privileged/hostPID/hostPath/hostNetwork); the dispatch chart likewise marks its `ectobase-system` namespace privileged for the hostNetwork compiler + reflector.

## Ceph + Tier-2 (`lab ceph`, `lab tier2`)

With `fabric.ceph.enabled`:

- `lab ceph` deploys the Ceph pool + external ceph-csi-rbd (on every cluster) + csi-addons (dispatch, the fence executor), and the krbd nodeplugin fixup. The `client.rbd` user is granted `mon 'profile rbd, allow command "osd blocklist"'` so csi-addons can both **fence** (blocklist add) and **un-fence** (blocklist rm).
- `lab tier2 up` deploys KubeVirt + CDI + the vm-materializer and wires the ceph fsid into dispatch's fence actuator.
- **Tier-2 failover gate** (`TestTier2Failover`): a stateful RBD-backed VM materializes on k02; **draining** k02 (scaling its broker to 0 so the ClusterPool lease goes stale) makes dispatch mark the pool Unknown → it **fences** the pool (csi-addons NetworkFence → ceph `osd blocklist`) and **reschedules** the VM to k03; restoring the broker releases the fence (NetworkFence `Fenced`→`Unfenced` → `osd blocklist rm`). The drain is non-destructive — the node + its fabric veths stay intact — and is a realistic "pool unreachable but node alive" storage-fence scenario.

## Live test suite (`lab test`)

`go test -tags live ./livetest/...` asserts, against the up fabric: cluster API + nodes Ready; both ClusterPools Ready with `nodePrefixes`; brokers/agents connected to the reflector; cross-cluster fabric reachability; a pod attached to the overlay via Multus → flowplane-cni pings across it (`TestPodOverlayPing`); a compute node's underlay is correctly inferred from the fabric, not the docker mgmt side-channel (`TestUnderlayInferenceOnFabric`); NAT64 egress with no masquerade patch needed (`TestNAT64Egress`); fabric-only egress; ≥2-path ECMP; `::/0` origination; switch→node reachability; registry mirror serves; cross-cluster overlay ping; and (when ceph.enabled) `TestRBDPVCBinds` + `TestTier2Failover`.

`TestTier2Failover` is alphabetically last; on a fresh fabric it runs after the others, and its **drain** (not node-kill) keeps k02 usable throughout.

### Debugging tips

- Trace fabric hops from a container's netns: `sudo nsenter -t <pid> -n ping -6 <dst>` / `... tcpdump -eni eth1`. XDP decap runs before tcpdump on the uplink — capture at the FRR switch or in the guest netns (drop `-p`, non-promiscuous silently misses veth RX).
- Route origination on an edge/switch: `docker exec clab-ectobase-sw1 vtysh -c "show ipv6 route <prefix>"`.
- Ceph blocklist (Tier-2 fence): `docker exec clab-ectobase-ceph ceph osd blocklist ls`.
