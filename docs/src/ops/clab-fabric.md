# IPv6 fabric (containerlab + kind) for ectobase

The integration environment for **ectobase** — the `flowplane` dataplane + the `netplane` control
plane: a **containerlab IPv6 fabric** wrapping one
or more **kind** clusters, with **FRR ToRs**, **dual VyOS WAN edges** (each with a `flowplane` sidecar),
a **Cilium** CNI, and the full **netplane** control plane deployed. It exercises the real paths:
underlay inference, overlay routing over the fabric, distributed SNAT + WAN egress through the edges,
North-South load balancing, and graceful datapath restart.

> Historical note: this started as a *lean* single-ToR underlay-inference lab; it has since grown the
> VyOS WAN edges, multiple kind clusters, and the netplane stack. The Cilium section at the bottom and
> the host/kernel gotchas are the load-bearing operational knowledge — read them.

## What is here

| File | Role |
|------|------|
| `ipv6-fabric.clab.yml` | Topology: FRR ToRs `sw1`/`sw2` (+ `sw1-pass`/`sw2-pass` xdp_pass sidecars), VyOS edges `edge1`/`edge2` (+ `edge1-xdp`/`edge2-xdp` dataplane sidecars), the `clabwan` "internet" bridge, and kind clusters `k01`/`k02`/`k03`. |
| `kind-cluster.yaml`, `kind-cluster-k0{2,3}.yaml` | The kind cluster configs clab deploys (IPv6, `disableDefaultCNI: true`, `kubeProxyMode: none`). |
| `frr/` | FRR configs for the ToRs (`sw1.conf`/`sw2.conf`) + `daemons`. Unnumbered eBGP-via-LLA transit + BFD + ECMP. |
| `vyos/` | VyOS edge boot configs (`edge{1,2}.boot`): BGP to the fabric + WAN forwarding/masquerade toward `clabwan`. |
| `cilium-up.sh`, `cilium-values.yaml` | Install Cilium (IPv6, tunnel/VXLAN mode) per kind cluster — the pod CNI (see below). |
| `wan-up.sh`, `wan-down.sh` | Create/destroy the `clabwan` host bridge + the WAN masquerade (the edges' path to the "internet"). |
| `edge-agents-up.sh`, `edge-xdp-wrapper.sh`, `sw-pass-wrapper.sh` | Start the edge `flowplane` sidecars (`--role edge`, `wan_rx`) + their brokered agents; the ToR xdp_pass shims. |
| `prefixes/` | Per-node announced-prefix inputs. |
| `../clab-up.sh`, `../clab-down.sh` | Idempotent deploy/destroy wrappers (WAN bring-up → clab deploy → Cilium per cluster). |

## Topology (k01 shown)

```
                 clabwan  (host bridge = "the internet", NAT-masqueraded)
                    │
          ┌─────────┴─────────┐
      edge1 (VyOS)        edge2 (VyOS)     WAN edges: VyOS owns BGP + WAN forwarding;
      + edge1-xdp         + edge2-xdp      a flowplane `--role edge` sidecar (wan_rx) shares its netns
          │                   │
        sw1 (FRR ToR)     sw2 (FRR ToR)    unnumbered eBGP-via-LLA transit + BFD + ECMP
          │   ┌───────────────┤            (sw{1,2}-pass = xdp_pass shims on the edge-facing ports)
   ┌──────┴───┴──────┐
   │ k01-control-plane│  k01-worker        kind nodes (ext-container): each runs the flowplane DaemonSet
   │   (fd00:db8:0:1::/64)  (…:0:2::/64)    + a netplane agent; Cilium is the pod CNI
   └──────────────────┘
```

## Bring it up

Prereqs: `containerlab`, `kind`, `docker`, root/sudo, the `dummy` kernel module, and the images built
(`make image` + `make image-netplane` + `make image-kindnode` at the repo root).

```bash
hack/clab-up.sh        # wan-up → clab deploy (--reconfigure, idempotent) → Cilium per cluster
# deploy the netplane stack (agent + reflector + controller) + the flowplane DaemonSet on k01:
helm install ectobase-pool charts/ectobase-pool -n ectobase-system  # per compute cluster
hack/clab/edge-agents-up.sh               # start the WAN-edge flowplane sidecars + brokered agents

# sanity: fabric addressing + BGP/BFD
docker exec k01-control-plane ip -6 -o addr show dev dummy0   # fd00:db8:0:1::1/64
docker exec clab-xdp-ipv6-fabric-sw1 vtysh -c 'show bgp ipv6 unicast summary'

# scenarios (repo root; need sudo + the flake PATH):
sudo -E bash test/scenario-nat-egress.sh   # container egress via distributed SNAT + the VyOS WAN edge
sudo -E bash test/scenario-lb-ingress.sh   # N-S load balancing
sudo -E bash test/scenario-restart.sh      # graceful datapath restart (crictl kill -> adopt)

hack/clab-down.sh      # destroy the fabric + kind clusters
```

`kind` and `containerlab` are expected on `PATH` (commonly `~/go/bin`); the datapath tooling
(`bpftool`, `bpftrace`, `tcpdump`, `xdp-tools`, `kubectl`) comes from the Nix devShell — run the
scripts inside `nix develop` (or with the flake `PATH` exported). Passwordless `sudo` is assumed
(clab, kind, and the netns/bpf inspection all need root); on NixOS the real setuid binary is
`/run/wrappers/bin/sudo`.

## XDP attach modes, MTU, and the per-edge pin namespace

These three settings are load-bearing for the datapath on clab veths. They are **not** arbitrary —
each encodes a containerlab-veth constraint that does not exist on real hardware.

### Per-role XDP mode: nodes are generic, edges are native

The loader prefers native/driver XDP and falls back to SKB/generic (`attach_xdp_mode`); setting
`FLOWPLANE_SKB_MODE=1` forces generic. On clab the correct mode is **per role**:

- **Compute nodes → generic/SKB** (`FLOWPLANE_SKB_MODE=1` in `charts/ectobase-pool/templates/dataplane-ebpf.yaml`).
  `uplink_rx` delivers to guests by XDP-redirecting into the guest veth (the `GUEST_DEV` devmap). On a
  containerlab veth a **native** redirect into a veth fails with `-95`/`EOPNOTSUPP` (the veth
  `ndo_xdp_xmit` peer requirement) — only the generic/SKB path delivers. Nodes never `XDP_PASS` to the
  local stack, so native buys them nothing.
- **WAN edges → native** (`FLOWPLANE_SKB_MODE` *unset* in `edge-xdp-wrapper.sh`). `edge_local_deliver`
  decaps an egress packet then `XDP_PASS`es the inner IPv4 to VyOS. Under **generic** XDP the skb's
  `skb->protocol` was set (to outer IPv6) *before* the program ran and is **not** re-derived after the
  head-adjust, so the decapped IPv4 never reaches `ip_rcv_core`. **Native** rebuilds the skb on PASS →
  `eth_type_trans` re-runs → protocol correct. The edge does no guest-veth redirect, so it dodges the
  `EOPNOTSUPP` problem. (On real NICs native works for *both* roles — real drivers honor
  `ndo_xdp_xmit` and rebuild the skb on PASS. The split is a clab-veth artifact.)

Verify with `bpftool net show` in the node/edge netns: nodes show `generic`, edges show `driver`.
Note the graceful-restart **adopt** path re-points the existing pinned link *without* changing attach
mode — a plain DS rollout will **not** flip native↔generic. To force a fresh attach, clear the pins
(`kubectl delete ds flowplane` → `rm -rf /sys/fs/bpf/flowplane*` on the node → re-apply).

### Fabric MTU 3000 (so native can attach at all)

containerlab defaults every veth to **MTU 9500**. Native/driver XDP on a veth requires **MTU ≤ ~3500**
(a linear-buffer limit; larger needs `#[xdp(frags)]` multi-buffer support, an open follow-up). At 9500
the native attach silently falls back to SKB. So every fabric link in `ipv6-fabric.clab.yml` sets
`mtu: 3000` — comfortably above the encap need (outer IPv6 40 + a 1500-MTU guest's inner IP = 1540)
and below the native limit. The dataplane code itself is MTU-agnostic; this is purely a harness knob.

### Per-edge bpffs pin namespace (or the two edges collide)

Both edge sidecars (`edge1-xdp`, `edge2-xdp`) are co-located on one host and **bind-mount the same
host `/sys/fs/bpf`**. A shared pin dir would make them share one `LOCAL`/`INTERFACES`/`CONNTRACK` map
set. `LOCAL` holds a single `uplink_mac`; the two edges have different eth1 MACs, so whichever seeds
`LOCAL` last wins and the other edge's `edge_local_deliver` writes the **wrong** inner-eth dst MAC →
the kernel drops the decapped packet as `PACKET_OTHERHOST` in `ip_rcv_core` → 100% N-S loss for any
flow that ECMP-hashes to the losing edge. Fix: each edge pins to its **own** dir
(`--pin-dir /sys/fs/bpf/flowplane-$EDGE_ID`, `EDGE_ID` set per-edge in the topology). In production
the edges are separate hosts (separate bpffs) so this never arises. The in-cluster DaemonSet needs
**no** such split: each node (kind node container / real machine) has its own bpffs and runs exactly
one flowplane pod — verified (`k01-control-plane` and `k01-worker` have distinct bpffs superblocks).

## End-to-end testing: deploy flow, multi-cluster kubeconfig, scenario isolation

```bash
# 1. fabric (destroys + recreates the whole lab; ports/MACs change every run)
sudo -E env "PATH=$HOME/go/bin:$PATH" bash hack/clab-up.sh

# 2. stack + cross-cluster overlay proof (deploys k01 central + k02 compute, brokered over the fabric)
nix develop -c bash -c 'export PATH="$HOME/go/bin:$PATH"; bash hack/multicluster-e2e.sh'

# 3. N-S scenarios (each is self-contained but NOT isolated from the others — see below)
nix develop -c bash -c 'sudo -E env "PATH=$HOME/go/bin:$PATH" bash test/scenario-nat-egress.sh'
nix develop -c bash -c 'sudo -E env "PATH=$HOME/go/bin:$PATH" bash test/scenario-lb-ingress.sh'
```

**Multi-cluster kubeconfig — be explicit, never reuse a fixed path.** Every `clab-up`/kind recreate
assigns **new** api-server ports. `sudo kind get kubeconfig --name kNN > file` runs the `>` redirect
as the *invoking user*: if `file` is a fixed path left **root-owned** by an earlier full-sudo run, the
overwrite silently fails and the file keeps a **stale port** → every later `kubectl` fails with
`connection refused`. Always write to a fresh `mktemp` file (user-owned) and, ideally, fail-fast with
a `kubectl get --raw=/healthz` check right after capture. The N-S scenarios already use `mktemp`;
`hack/multicluster-e2e.sh` was fixed to do the same. Confirm the port matches reality with
`docker port k01-control-plane 6443`.

**Scenarios contaminate each other.** They all reuse **VNI 100** and the **10.0.0.0/24** overlay and
leave guests attached + routes on the reflector. Running them back-to-back collides on the `(vni, ip)`
`INTERFACES` key and serves stale routes. **Between scenarios, clean both/all clusters:**

```bash
kubectl --kubeconfig <kc> delete vpc,networkinterface,loadbalancer,natgateway,firewallpolicy,vpcpeering,compilednic --all -n default
# detach every guest on every node (grpc DetachInterface) + `ip netns del <id>`
```

**Conntrack-map OOM.** Each flowplane instance pre-allocates a ~1M-entry `CONNTRACK` LRU (~100+MB of
*kernel* RAM). Pins outlive the process, and host-run netns tests + crash-restarts leak them (this has
reached tens of GB and OOM-killed the box). `hack/bpf-cleanup.sh` (a.k.a. `make bpf-clean`) sweeps the
host + node pins, including the per-edge `flowplane-edge*` dirs; `clab-up.sh` runs it pre-deploy.

## Debugging the datapath (XDP layer *and* kernel stack)

`flowplane`'s datapath is XDP: `XDP_REDIRECT`/`TX`/`DROP` consume the packet **before** the AF_PACKET
tap, so plain `tcpdump` shows nothing and a silently-failed redirect looks identical to "no packet".
`hack/clab/bpf-trace.sh` gives kernel-global visibility across every clab netns at once (bpf prog IDs
and tracepoints are global — one kernel backs all containers). Run it inside `nix develop`:

| Command | Sees |
|---------|------|
| `bpf-trace.sh` | live `xdp:xdp_redirect{,_err}` / `devmap_xmit` / `xdp_exception` — a `REDIRECT ERR` or `err=-95` is the silently-dropped case tcpdump hides (this is how the node `EOPNOTSUPP` was found). |
| `bpf-trace.sh dropmon` | **kernel-stack** drops after `XDP_PASS`: `skb:kfree_skb` aggregated by `(reason, skb->protocol, freeing-fn)`. This is the cilium-drop-monitor analog that found the edge `OTHERHOST` bug. |
| `bpf-trace.sh legend` | prog-id → name map (annotate the streams). |
| `bpf-trace.sh pcap <ctr> <if>` | `xdpdump` one interface — shows packets XDP *consumes* + the action. |
| `bpf-trace.sh map <node> <MAP>` | dump + decode a flowplane state map (`UNDERLAY`/`CONNTRACK`/`NEIGHBOR_NAT`/…). |

Worked example — the long-open N-S drop, cracked assumption-free:

1. `bpf-trace.sh dropmon` during a failing `natpod` ping → `SKB_DROP_REASON_OTHERHOST, proto=2048
   (IPv4), ip_rcv_core` at exactly the ping rate. This *overturned* a "stale skb->protocol" theory
   (the protocol was correctly IPv4) and pointed straight at a wrong **destination MAC**.
2. `bpftool map dump pinned /sys/fs/bpf/flowplane-edge1/LOCAL` → the stored `uplink_mac` did not match
   the live `eth1` MAC → the shared-bpffs collision above.
3. After the per-edge pin fix, `dropmon` moved to `NETFILTER_DROP` and the XDP tracer showed
   `xdp_redirect_err err=-95` on the *node* → the per-role native/generic split above.

Lesson: chained hypotheses (rp_filter, forwarding, protocol) all self-disproved; the `kfree_skb`
drop-reason tracepoint + a `LOCAL` map dump gave ground truth in one shot. Reach for `dropmon` before
theorizing about where a post-`XDP_PASS` packet died.

## The kind ↔ containerlab integration

- **`k8s-kind` nodes** (`k01`/`k02`/`k03`) — containerlab owns the kind cluster lifecycle
  (create on deploy, delete on destroy).
- **`ext-container` nodes** (`k01-control-plane`, `k01-worker`, …) — the kind node containers,
  referenced by the exact name kind gives them; these are the clab link endpoints, so the kind nodes
  attach to the FRR fabric (`sw1:eth1 ↔ k01-control-plane:eth1`). Their `exec:` blocks create
  `dummy0` + the announced `/64` **inside the kind node's netns** — where `flowplane` infers from.
- **FRR runs in the kind node's netns** (shared-netns sidecar) so it can announce `dummy0`'s `/64`
  over the fabric uplink without baking FRR into the kubelet/containerd node image.
- **`vyosnetworks_vyos` edges** (`edge1`/`edge2`) run real VyOS (BGP + WAN forwarding, what hardware
  runs); a `flowplane --role edge` sidecar shares each edge's netns and owns the overlay `wan_rx` path.

The **mgmt-IPv6-disabled** note genuinely bites: a clab-auto mgmt IPv6 default route can outrank the
fabric — keep it disabled on the fabric nodes.

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
