# Lean IPv6 BGP-unnumbered fabric (containerlab) for underlay-inference e2e

A minimal, kind-native containerlab lab that exercises **xdp-dp underlay inference**:
each "host" node announces a per-node `/64` that lives on its `dummy0`, the FRR ToR
routes each `/64` to the other, and `xdp-dp infer-underlay` must report the same `/64`
it read off `dummy0`.

It is adapted from a proven reference lab (`icn/sandbox`) but recreated **lean**: NO
VyOS edges, NO NAT64/DNS64, NO Garden-Linux VMs — just enough FRR fabric to route the
per-node `/64`s between kind nodes.

## What is here

| File | Role |
|------|------|
| `ipv6-fabric.clab.yml` | Topology: FRR ToR `sw1` + kind cluster `k01` (2 nodes as "hosts") |
| `kind-cluster.yaml` | The kind cluster config clab deploys (control-plane + worker, IPv6) |
| `frr/daemons` | FRR daemons (zebra/bgpd/bfdd/staticd only) |
| `frr/sw1.conf` | ToR: unnumbered eBGP transit (AS 65010) |
| `frr/host1.conf`, `frr/host2.conf` | Per-host FRR: announce `fd00:db8:0:1::/64` / `fd00:db8:0:2::/64` (AS 65100) |
| `../clab-up.sh`, `../clab-down.sh` | Idempotent deploy/destroy wrappers |

Topology:

```
        ┌──────┐
        │ sw1  │            FRR ToR (AS 65010), unnumbered eBGP transit
        └┬────┬┘
     eth1│    │eth2         unnumbered IPv6 links (link-local only)
   ┌─────┴┐  ┌┴─────┐
   │ host1│  │ host2│       kind nodes k01-control-plane / k01-worker (AS 65100)
   │dummy0│  │dummy0│       host1 announces fd00:db8:0:1::/64
   │ ::1  │  │ ::1  │       host2 announces fd00:db8:0:2::/64
   └──────┘  └──────┘       each runs xdp-dp -> infers its /64 from dummy0
```

## The kind ↔ containerlab integration (read this)

The reference lab used Garden-Linux VMs as hosts; using **kind** is new here. The
integration uses documented containerlab features:

- **`k8s-kind` node** (`k01`) — containerlab owns the kind cluster lifecycle
  (create on deploy, delete on destroy). `startup-config: kind-cluster.yaml`.
- **`ext-container` nodes** (`k01-control-plane`, `k01-worker`) — the kind node
  containers, referenced **by the exact name kind gives them**
  (`<cluster>-control-plane`, `<cluster>-worker`). These CAN be clab link endpoints,
  which is how the kind nodes attach to the fabric (`sw1:eth1` ↔ `k01-control-plane:eth1`).
  Their `exec:` blocks create `dummy0` + the announced `/64` **inside the kind node's
  own netns**, which is exactly where `xdp-dp` runs and infers from.
- **Per-host FRR sidecars** (`host1-frr`, `host2-frr`) — plain `linux` nodes with
  `network-mode: container:k01-control-plane` / `-worker`, so FRR runs in the **same
  netns** as the kind node. That lets FRR announce `dummy0`'s `/64` over the kind
  node's fabric uplink **without baking FRR into the kubelet/containerd node image**.

### Proven-from-reference vs new-and-unvalidated

**Proven** (copied/adapted directly from `icn/sandbox`, which runs green):
- The unnumbered-eBGP pattern (`neighbor ethN interface remote-as external`), the
  `fabric-fast` BFD profile, `maximum-paths` ECMP, `bestpath as-path multipath-relax`,
  the host-announces-`dummy0`-`/64` model, and the **mgmt-IPv6-disabled** note (that
  one genuinely bites — a clab-auto mgmt IPv6 default route outranks the fabric).

**New / UNVALIDATED here** (could not run — no containerlab/kind/root in the authoring
env). Flagged assumptions a capable host must confirm:
1. **`k8s-kind` + `ext-container` naming.** Assumes the containers are named
   `k01-control-plane` / `k01-worker`. Verify with `docker ps` after deploy; adjust
   node names + the e2e's `kindNode` constant if your clab/kind version differs.
2. **`exec` runs in the kind node netns and iproute2 is present** in `kindest/node`
   (it is, for `ip`/`dummy`), and dummy module is loadable. If `ip link add dummy0`
   fails, load `dummy` on the host or add `--sysctl`/`modprobe dummy` on the host.
3. **Shared-netns FRR sidecar** sees `dummy0` + `eth1`. `network-mode: container:` +
   `startup-delay` should order it after the kind node + its `exec`; if the LLA on
   `eth1` lost the race (session Idle), bounce it:
   `docker exec k01-control-plane sh -c 'ip link set eth1 down; ip link set eth1 up'`.
4. **Unnumbered eBGP needs an IPv6 link-local on every peering iface.** clab/kind
   veths default to `addr_gen_mode=eui64` so this should hold; if a session is Idle,
   confirm `ip -6 addr show dev eth1` shows an `fe80::` on both ends.
5. **xdp-dp image reachability.** The e2e runs `docker run --network container:<node>
   ghcr.io/trevex/dpservice-xdp:dev infer-underlay`. Build/pull that image first
   (`make image` at the repo root), or override the tag.

## Run it (on a capable host)

Prereqs: `containerlab`, `kind`, `docker` (or another clab runtime), root/sudo, the
`dummy` kernel module, and the `dpservice-xdp` image built (`make image`).

```bash
# from the repo root
hack/clab-up.sh                        # deploy (idempotent: --reconfigure)

# confirm the fabric addressing + sessions
docker exec k01-control-plane ip -6 -o addr show dev dummy0   # fd00:db8:0:1::1/64
docker exec clab-xdp-ipv6-fabric-sw1 vtysh -c 'show bgp ipv6 unicast summary'
docker exec clab-xdp-ipv6-fabric-sw1 vtysh -c 'show bfd peers brief'

# the actual assertion: xdp-dp infers the same /64 the fabric put on dummy0
docker run --rm --network container:k01-control-plane \
  ghcr.io/trevex/dpservice-xdp:dev infer-underlay
# expect: inferred underlay prefix: fd00:db8:0:1::/64
docker run --rm --network container:k01-worker \
  ghcr.io/trevex/dpservice-xdp:dev infer-underlay
# expect: inferred underlay prefix: fd00:db8:0:2::/64

# cross-node reachability (each /64 routed to the other via sw1)
docker exec k01-control-plane ping6 -c2 fd00:db8:0:2::1

hack/clab-down.sh                      # destroy (also deletes the kind cluster)
```

## The Go e2e

`test/e2e/fabric_test.go` → `TestUnderlayInferenceOnFabric` automates the above and
**skips cleanly** when `containerlab`/`kind`/`docker` are absent (as in CI without a
runtime). To run it on a capable host:

```bash
cd test/e2e && go test -run TestUnderlayInferenceOnFabric -v ./...
```

## CNI = Cilium (tunnel mode), and the harness gotchas behind it

The kind clusters run **Cilium** (not kindnet) — `disableDefaultCNI: true` + `kubeProxyMode:
none` in `kind-cluster*.yaml`, installed by `cilium-up.sh` (values in `cilium-values.yaml`,
IPv6-only, `routingMode: tunnel`/vxlan, `kubeProxyReplacement`). Rationale + the debugging that
led here:

- **Why not kindnet:** kindnet reconciles `ip -6 route add <peer-pod-CIDR> via <peer-InternalIP>`
  unconditionally and panics on `EHOSTUNREACH`. On our per-node `/64` BGP fabric the peer
  InternalIP is a BGP-recursive, non-on-link gateway, so that add can never succeed (no covering
  route or blackhole helps — kindnet adds it regardless). Cilium tunnel mode VXLAN-encaps pod
  traffic to the peer **node IP** instead, so the k8s pod overlay never enters the underlay FIB
  or the BGP fabric — which is also the production-correct separation.
- **Nodes come up NotReady until `cilium-up.sh` runs** (no default CNI). `clab-up.sh` therefore
  runs the deploy first, then installs Cilium per cluster. The k8s-kind `deploy.wait` is a
  boot-marker scan timeout (NOT a Ready gate) — keep it comfortably above the node's boot time.

`clab-up.sh` also handles three host/kernel + clab interactions that otherwise break a headless
bring-up (each cost real debugging — do not "simplify" them away):

1. **`bridge-nf-call-ip6tables=0`** — with it =1, even same-bridge IPv6 ND frames traverse the
   host ip6tables FORWARD chain, and clab sets that chain's policy to DROP with ACCEPT only for
   its own bridges (not the `kind` bridge). Result: a multi-node cluster's nodes can't ND each
   other over the kind bridge → worker can't reach the API → never Ready ("flaky boot-race").
2. **pty for the deploy** — clab's `vyosnetworks_vyos` kind talks to the VyOS CLI over a pty to
   wait for "Cli ready". Headless (backgrounded / CI / `>log`) that read fails
   (`read /dev/ptmx: input/output error`) and clab loops forever. `clab-up.sh` runs the deploy
   under `script(1)` when stdout is not a TTY.
3. **VyOS `admin` user + `enforce-startup-config: false`** — clab's vyos readiness probe runs
   `su - admin`, but `vyos:latest` ships only user `vyos`; `edge{1,2}.boot` therefore also define
   an `admin` login. Enforce is off because its `docker exec -it … su - admin` needs a TTY and
   re-applies config redundantly (config.boot is applied at boot regardless — BGP comes up).

**Cilium is pinned to >=1.20** (`cilium-up.sh`) for a reason: on an **nftables-only host kernel
without the legacy `ip6_tables` modules** (e.g. this NixOS box), Cilium <=1.19's IPv6 iptables
manager fatally `modprobe ip6_tables` on startup and the agent crash-loops (`could not load module
ip6_tables`) — even though the rules would go through `iptables-nft`/`nft_compat` fine and the
modules aren't actually needed (cilium/cilium#30638). kubeProxyReplacement forces
`install-iptables-rules=true`, so the "disable iptables rules" escape does not apply. **Cilium
1.20 handles the missing legacy module gracefully**, so agents come up `1/1` on the stock config
here. (If you must run an older Cilium, the alternative is a modprobe stub — `install ip6_tables
/bin/true` in the agent's modprobe.d — or providing the modules via the host kernel config.)
