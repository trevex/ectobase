# IPv6 fabric (containerlab + Talos) for ectobase

!!! success "Status: Implemented"
    The integration environment is driven by the **Go lab CLI** (`test/lab`, exposed as the
    `make lab-*` targets). It stands up a **containerlab IPv6-BGP fabric** wrapping several
    **Talos-in-container** clusters — a **dispatch** cluster plus one or more compute **pool**
    clusters — and deploys the two Helm charts onto them exactly as an operator would.

The fabric exercises the real paths: underlay inference over a per-node `/64` BGP fabric,
overlay routing across it, distributed SNAT + WAN egress through the FRR edges, NAT64,
North-South load balancing, and the multi-cluster broker/reflector control plane.

## What the fabric is

The lab CLI (`test/lab`, a cobra CLI; config in `test/lab/lab.yaml`) renders and deploys:

| Component | Role |
|---|---|
| **FRR edges** `edge1`/`edge2` (AS 65000) | eBGP `default-originate` (`::/0`) + advertise the NAT64 prefix `64:ff9b::/96`, a static route handing that prefix to Tayga, WAN + Tayga wiring. (DNS64 is deferred to a later egress spec.) The N/S-LB edge datapath is a later (P4) concern. |
| **FRR switches** `sw1`/`sw2` (AS 65010) | A pure `/128` ECMP relay: unnumbered eBGP to both edges and every node (`as-override`), no interface addresses, no originated `/64`, no router-advert. |
| **Tayga NAT64** `nat64-1`/`nat64-2` | `64:ff9b::/96` → IPv4 pool → MASQUERADE to the WAN, one per edge. |
| **WAN sim** `wan` | Masquerades all fabric prefixes onto the host uplink; the host's single route into the fabric. |
| **Registry mirror** (`registry:2`) | Persistent pull-through + push-local mirror on the WAN segment (`fd00:29::5:5000`), cache-backed across `down`. |
| **Talos-in-container nodes** | One per lab-cluster node (`dispatch`, `k02`, `k03`, …). Each is a stock siderolabs `talos:container` image, booted with `PLATFORM=container` + a base64 `USERDATA=` machine config. Talos' own embedded GoBGP establishes the `dummy0` `/128` identity (= kubelet `--node-ip`) and speaks unnumbered eBGP to both switches — no fabric-preboot script, no on-node FRR. |
| **Ceph/demo** (optional) | On its own `/64` when `fabric.ceph.enabled`, for RBD + the Tier-2 storage fence. |

Every per-cluster/per-node prefix is **derived** (FNV-1a of the cluster name) so parallel
clusters never collide; the whole fabric lives under `fd00:cafe::/32` (the single aggregate
the host routes into via the WAN container).

The pod CNI is **Cilium** (container-mode, `kubeProxyReplacement=true` via Talos' KubePrism,
IPv6-only, vxlan tunnel), not kindnet — Talos resolves the cluster CNI to `"none"` so Cilium
owns it. It coexists with a thin **Multus** DaemonSet (`cni.exclusive: false` in the Cilium
values) that attaches the flowplane overlay as a Multus secondary network; the VM/overlay
datapath is flowplane's either way, independent of the pod CNI. (This still requires **1 node
per cluster**: every lab cluster is a single-node Talos control plane today, and the Cilium
operator's replica count is pinned to match — not a fabric-routing limitation the way
kindnet's node-local pod routing used to be.)

## Bring it up

Prereqs (run everything inside `nix develop`):

- Build the fabric images and mirror the Talos node image: `make lab-images` and
  `make image-talos-mirror` (pulls the pinned upstream `siderolabs/talos` release and tags it
  into the fabric namespace — no local rootfs build needed).
- Build the component `:dev` images the fabric mirror serves: `make image`,
  `make image-mesh`, `make image-cni`, and the dispatch images (`dispatch-apiserver`,
  `dispatch-controller`, `dispatch-broker`). `lab up` **pushes** local `:dev` images into the mirror;
  it does not build them.
- Docker with IPv6 enabled on the clab management network; tens of GB of disk headroom.
- Passwordless real `sudo` (the live commands drive containerlab + host networking). On
  NixOS the real setuid binary is `/run/wrappers/bin/sudo` — see the
  [runbook](./runbook.md).

```sh
make lab-render     # expand templates into test/lab/build/<name>/ (no root)
make lab-up         # render → clab fabric (Talos nodes + Cilium/Multus) → push :dev images → deploy the two charts
make lab-test       # the live suite (go test -tags live ./livetest/...)
make lab-down       # tear down; keeps the registry cache (make lab-down-purge removes it)
```

Iteration loop: once the fabric is up, `make lab-deploy` re-runs **only** the ectobase
substrate deploy (the two `helm install`s) against the running fabric — no fabric rebuild.

Optional storage / VM tiers (require `fabric.ceph.enabled` in `lab.yaml`):

```sh
make lab-ceph       # Ceph pool + external ceph-csi-rbd + csi-addons
make lab-tier2-up   # KubeVirt + CDI + the vm-materializer, and wire the ceph fsid into the fence actuator
```

### What `lab up` deploys

The last step of `up` is the two-chart install (see [Deploying with Helm](./deploy-helm.md)
for the operator-facing version, and `test/lab/internal/deploy/ectobase.go` for the exact
sequence):

- The **dispatch** cluster gets `charts/ectobase-dispatch` (aggregated apiserver + kine, dispatch-controller,
  the mesh compiler, the reflector, and the dispatch-side broker identity), with
  `reflectorAdmin` set to the dispatch's fabric identity. The lab then mints the broker→dispatch
  token/kubeconfig and pre-creates one `ClusterPool` per compute cluster (test fixtures around
  the install).
- Each **compute** cluster gets `charts/ectobase-pool` (dataplane + agent + broker + cni +
  pod-materializer; vm-materializer under `lab tier2`), wired to the dispatch's reflector and to
  its own local apiserver. The lab pre-creates the privileged `ectobase-system` namespace + the
  `broker-dispatch-kubeconfig` Secret first.

Both compute **ClusterPools converge to `Ready` with `nodePrefixes`** — that convergence is
the up-signal the lab waits on.

## Kubeconfigs / access

Per-cluster kubeconfigs land at `test/lab/build/<name>/<cluster>.kubeconfig`. Even
though the lab brings the fabric up under `sudo`, `lab up` chowns each kubeconfig
back to the invoking user, so `kubectl --kubeconfig …` works **without sudo**:

```sh
kubectl --kubeconfig test/lab/build/ectobase/dispatch.kubeconfig get nodes
kubectl --kubeconfig test/lab/build/ectobase/k02.kubeconfig get clusterpools.platform.ectobase.dev
```

## Fabric-only egress

The node's preferred default (`::/0`) arrives via Talos' own embedded GoBGP peering unnumbered
eBGP to both switches, originated by the edges (`default-originate`) and relayed by the
switches — no RA involved, no on-node FRR. There is no kind-bridge default to delete: GoBGP is
the node's only route source for `::/0`, and because the node sources fabric egress from its
own `/128` VTEP natively, NAT64 egress needs no masquerade/route-map patch. Traffic goes
`node → switch → edge → (Tayga NAT64 for IPv4) → WAN → internet`. `up` auto-configures the host
NAT66 + FORWARD so the WAN's masqueraded fabric egress reaches the host uplink.

## Registry mirror

A persistent pull-through + push-local `registry:2` runs on the WAN segment
(`fd00:29::5:5000`), cache-backed at `build/<name>/registry-cache` (survives `down`). `up`
pushes local `:dev` images via the host-published `127.0.0.1:5000`; each Talos node's
containerd mirrors `ghcr.io` at this same registry via a declarative
`machine.registries.mirrors` doc in its rendered machine config (not a mounted `certs.d`). The
cache makes a second `up` materially faster.

## XDP attach modes, MTU, and the per-edge pin namespace

These three settings are load-bearing for the datapath on clab veths. They are **not**
arbitrary — each encodes a containerlab-veth constraint that does not exist on real hardware.

### Per-role XDP mode: nodes are generic/SKB; the edge role is deferred (P4)

The loader prefers native/driver XDP and falls back to SKB/generic (`attach_xdp_mode`); setting
`FLOWPLANE_SKB_MODE=1` forces generic. On clab the correct mode for compute nodes is:

- **Compute nodes → generic/SKB** (`FLOWPLANE_SKB_MODE=1` in the pool chart's
  `dataplane-ebpf` DaemonSet). `uplink_rx` delivers to guests by XDP-redirecting into the
  guest veth (the `GUEST_DEV` devmap). On a containerlab veth a **native** redirect into a veth
  fails with `-95`/`EOPNOTSUPP` (the veth `ndo_xdp_xmit` peer requirement) — only the
  generic/SKB path delivers. Nodes never `XDP_PASS` to the local stack, so native buys them
  nothing.

The WAN-edge flowplane sidecar (and its native-XDP handling) has been pruned from this fabric —
FRR is the whole edge node today. The N/S-LB edge datapath is a later (P4) concern.

Verify with `bpftool net show` in the node netns: nodes show `generic`. The graceful-restart
**adopt** path re-points the existing pinned link *without* changing attach mode — a plain DS
rollout will **not** flip native↔generic. To force a fresh attach, clear the pins.

### Fabric MTU (so native can attach at all)

containerlab defaults every veth to **MTU 9500**. Native/driver XDP on a veth requires
**MTU ≤ ~3500** (a linear-buffer limit; larger needs `#[xdp(frags)]` multi-buffer support, an
open follow-up). At 9500 the native attach silently falls back to SKB. So the fabric links set
a lower MTU — comfortably above the encap need (outer IPv6 40 + a 1500-MTU guest's inner IP)
and below the native limit. The dataplane code itself is MTU-agnostic; this is purely a harness
knob.

### Per-edge bpffs pin namespace — deferred (P4)

This used to document a bpffs-collision hazard between the two `flowplane --role edge`
sidecars co-located on one host. That sidecar has been pruned from the fabric, so the
hazard does not currently apply; revisit if/when the N/S-LB edge datapath (P4) reintroduces
a per-edge sidecar. The in-cluster DaemonSet needs no such split: each node has its own
bpffs and runs exactly one flowplane pod.

## Debugging the datapath (XDP layer *and* kernel stack)

`flowplane`'s datapath is XDP: `XDP_REDIRECT`/`TX`/`DROP` consume the packet **before** the
AF_PACKET tap, so plain `tcpdump` shows nothing and a silently-failed redirect looks identical
to "no packet". Trace fabric hops from a container's netns
(`sudo nsenter -t <pid> -n tcpdump -eni eth1`), and capture at the FRR switch or in the guest
netns since XDP decap runs before tcpdump on the uplink. For kernel-global visibility across
netns, the `xdp:xdp_redirect{,_err}` / `devmap_xmit` tracepoints and the `skb:kfree_skb`
drop-reason tracepoint give ground truth:

- An `xdp_redirect_err err=-95` is the silently-dropped `EOPNOTSUPP` case tcpdump hides (this
  is how the node native-redirect issue is spotted).
- `skb:kfree_skb` aggregated by `(reason, skb->protocol, freeing-fn)` catches **kernel-stack**
  drops after `XDP_PASS` — e.g. `SKB_DROP_REASON_OTHERHOST` on IPv4 at `ip_rcv_core` is the
  wrong-MAC / shared-bpffs collision above.

Reach for the drop-reason tracepoint before theorizing about where a post-`XDP_PASS` packet
died — a `kfree_skb` reason plus a `LOCAL` map dump (`bpftool map dump pinned …`) usually give
the answer in one shot.

## Host/kernel interactions the bring-up handles

The lab's `up` handles host/kernel + clab interactions that otherwise break a headless
bring-up (each cost real debugging — do not "simplify" them away):

- **`bridge-nf-call-ip6tables=0`** — with it =1, even same-bridge IPv6 ND frames traverse the
  host ip6tables FORWARD chain (clab sets that chain's policy to DROP), so a multi-node
  cluster's nodes can't ND each other → never Ready.

See the [runbook](./runbook.md) for the operational gotchas (real-`sudo` path, conntrack-map
OOM / `make bpf-clean`, the edge `FLOWPLANE_PIN_LINKS=false`, in-container `bpftool`).
