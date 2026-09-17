# IPv6 fabric (containerlab + Talos) for ectobase

!!! success "Status: Implemented"
    The integration environment is driven by the Go lab CLI (`test/lab`, exposed as the
    `make lab-*` targets). It stands up a containerlab IPv6-BGP fabric wrapping several
    Talos-in-container clusters — a dispatch cluster plus one or more compute pool
    clusters — and deploys the two Helm charts onto them exactly as an operator would.

The fabric exercises the real paths: underlay inference over a per-node `/64` BGP fabric,
overlay routing across it, distributed SNAT + WAN egress through the VyOS edges, NAT64,
North-South load balancing, and the multi-cluster broker/reflector control plane.

## What the fabric is

The lab CLI (`test/lab`, a cobra CLI; config in `test/lab/lab.yaml`) renders and deploys:

| Component | Role |
|---|---|
| VyOS edges `edge1`/`edge2` (AS 65000) | eBGP `default-originate` (`::/0`) + advertise the NAT64 prefix `64:ff9b::/96` and the edge-owned public v4/v6 prefixes, a static route handing the NAT64 prefix to Tayga, WAN + Tayga wiring, and a DNS64 forwarder on the edge's own loopback. Each also hosts a co-netns `flowplane --role edge` sidecar (the N/S-LB + NAT edge datapath). |
| VyOS switches `sw1`/`sw2` (AS 65010) | A pure `/128` ECMP relay: unnumbered eBGP to both edges and every node (`as-override`), no interface addresses, no originated `/64`. Router-advert *is* on (`default-lifetime 1800`) on the edge- and node-facing links, with RDNSS name-servers pointing at the two edge DNS64 resolvers. |
| Tayga NAT64 `nat64-1`/`nat64-2` | `64:ff9b::/96` → IPv4 pool → MASQUERADE to the WAN, one per edge. |
| WAN sim `wan` | Masquerades all fabric prefixes onto the host uplink; the host's single route into the fabric. |
| Registry mirror (`registry:2`) | Persistent pull-through + push-local mirror on the WAN segment (`[fd00:29::5]:5000`), cache-backed across `down`. |
| Talos-in-container nodes | One per lab-cluster node (`dispatch`, `k02`, `k03`, …). Each is a stock siderolabs `talos:container` image, booted with `PLATFORM=container` + a base64 `USERDATA=` machine config. Talos' own embedded GoBGP establishes the `dummy0` `/128` identity (= kubelet `--node-ip`) and speaks unnumbered eBGP to both switches — no fabric-preboot script, no on-node FRR. |
| Ceph/demo (optional) | On its own `/64` when `fabric.ceph.enabled`, for RBD + the Tier-2 storage fence. |

Every per-cluster/per-node prefix is derived (FNV-1a of the cluster name) so parallel
clusters never collide; the whole fabric lives under `fd00:cafe::/32` (the single aggregate
the host routes into via the WAN container).

The pod CNI is Cilium (container-mode, `kubeProxyReplacement=true` via Talos' KubePrism,
IPv6-only, vxlan tunnel), not kindnet — Talos resolves the cluster CNI to `"none"` so Cilium
owns it. It coexists with a thin Multus DaemonSet (`cni.exclusive: false` in the Cilium
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
- Build the component `:dev` images the fabric mirror serves: `make lab-app-images` (=
  `image` + `image-mesh` + `image-cni` + `image-dispatch`, the last building all three
  dispatch images: `dispatch-apiserver`, `dispatch-controller`, `dispatch-broker`).
  `make lab-up` depends on this target and so runs it for you; the `lab up` CLI itself only
  pushes the local `:dev` images into the mirror, it does not build them.
- Docker with IPv6 enabled on the clab management network; tens of GB of disk headroom.
- Passwordless real `sudo` (the live commands drive containerlab + host networking). On
  NixOS the real setuid binary is `/run/wrappers/bin/sudo` — see the
  [runbook](../operations/runbook.md).

```sh
make lab-render     # expand templates into test/lab/build/<name>/ (no root)
make lab-up         # render → clab fabric (Talos nodes + Cilium/Multus) → push :dev images → deploy the two charts
make lab-test       # the live suite (go test -tags live ./livetest/...)
make lab-down       # tear down; keeps the registry cache (make lab-down-purge removes it)
```

Iteration loop: once the fabric is up, `make lab-deploy` re-runs only the ectobase
substrate deploy (the two `helm install`s) against the running fabric — no fabric rebuild.

Optional storage / VM tiers (require `fabric.ceph.enabled` in `lab.yaml`):

```sh
make lab-ceph       # Ceph pool + external ceph-csi-rbd + csi-addons
make lab-tier2-up   # KubeVirt + CDI + the vm-materializer, and wire the ceph fsid into the fence actuator
```

### What `lab up` deploys

The last step of `up` is the two-chart install (see [Deploying with Helm](../operations/deploy-helm.md)
for the operator-facing version, and `test/lab/internal/deploy/ectobase.go` for the exact
sequence):

- cert-manager goes in first, on every cluster: the charts render `Issuer`/`ClusterIssuer`/
  `Certificate` objects its webhook has to validate. The dispatch's CA-type `ClusterIssuer`
  reads its CA secret from cert-manager's `--cluster-resource-namespace`, so there it is
  installed with that set to `system`; the pool uses a namespaced `Issuer` and needs no override.
- The dispatch cluster gets `charts/ectobase-dispatch` (aggregated apiserver + kine, dispatch-controller,
  the mesh compiler, the reflector, and the dispatch-side broker identity), with
  `reflectorAdmin` set to the dispatch's fabric identity. The aggregated apiserver runs
  `hostNetwork` and is exposed directly on the fabric at `https://[<dispatch>]:6444`, which
  baseline PSA forbids — so `system` is pre-created PSA-privileged ahead of the release.
- Per compute cluster, the lab then applies a fixture bundle on the dispatch (`clusterPoolsManifest`):
  a `pool-<cluster>` Namespace (where that pool's compiled twins live — admission rejects a twin
  written into a namespace that does not exist), the `ClusterPool` itself, a stub
  `RouteBusIdentity`, a namespaced `dispatch-broker` Role+RoleBinding in `pool-<cluster>`
  (read-only on the twins, plus `compiledvms/status`), a per-pool
  `dispatch-broker-bootstrap-<cluster>` ServiceAccount, and a resourceNames-scoped
  `dispatch-broker-pool-<cluster>` ClusterRole+ClusterRoleBinding.
- Each compute cluster gets `charts/ectobase-pool` (dataplane + agent + broker + cni +
  pod-materializer; vm-materializer under `lab tier2`), wired to the dispatch's reflector and to
  its own local apiserver. The lab pre-creates the privileged `ectobase-system` namespace and two
  enrollment Secrets in it first: `dispatch-root-ca` (key `ca.crt`, the dispatch's root cert, so
  the broker can verify the dispatch server) and `broker-dispatch-bootstrap` (key `kubeconfig`,
  a 1h first-boot-only bootstrap token scoped to route-bus identities). That token is only for
  the broker's first `RouteBusIdentity` CSR; steady-state broker→dispatch auth is cert-manager
  mTLS against `https://[<dispatch>]:6444`.

Both compute ClusterPools converge to `Ready` with `nodePrefixes` — that convergence is
the up-signal the lab waits on.

## Kubeconfigs / access

Per-cluster kubeconfigs land at `test/lab/build/<name>/<cluster>.kubeconfig`. Even
though the lab brings the fabric up under `sudo`, `lab up` chowns each kubeconfig
back to the invoking user, so `kubectl --kubeconfig …` works without sudo:

```sh
kubectl --kubeconfig test/lab/build/ectobase/dispatch.kubeconfig get nodes
kubectl --kubeconfig test/lab/build/ectobase/k02.kubeconfig get clusterpools.platform.ectobase.dev
```

## Fabric-only egress

The node's preferred default (`::/0`) arrives via Talos' own embedded GoBGP peering unnumbered
eBGP to both switches, originated by the edges (`default-originate`) and relayed by the
switches — no on-node FRR. The ToRs also send RAs on every node-facing link
(`default-lifetime 1800`, with RDNSS name-servers pointing at the two edge DNS64 resolvers), so
an RA default is there as a second, belt-and-suspenders source; BGP is the one the node
prefers. There is no kind-bridge default to delete — every `::/0` the node sees comes from the
fabric — and because the node sources fabric egress from its own `/128` VTEP natively, NAT64
egress needs no masquerade/route-map patch. Traffic goes
`node → switch → edge → (Tayga NAT64 for IPv4) → WAN → internet`. `up` auto-configures the host
NAT66 + FORWARD so the WAN's masqueraded fabric egress reaches the host uplink.

## Registry mirror

A persistent pull-through + push-local `registry:2` runs on the WAN segment
(`[fd00:29::5]:5000`), cache-backed at `build/<name>/registry-cache` (survives `down`). `up`
pushes local `:dev` images via the host-published `127.0.0.1:5000`; each Talos node's
containerd mirrors `ghcr.io` at this same registry via a declarative
`machine.registries.mirrors` doc in its rendered machine config (not a mounted `certs.d`). The
cache makes a second `up` materially faster.

## SKB mode, MTU, and the per-edge pin namespace

These three settings are load-bearing for the datapath on clab veths. Each encodes a
containerlab-veth constraint, or a harness choice made because of one, that does not apply on
real hardware.

### `FLOWPLANE_SKB_MODE`: a jumbo gate, not an XDP attach mode

No forwarding program is XDP any more, so there is no native-vs-generic attach mode to pick and no
`attach_xdp_mode` knob: the overlay runs as tcx classifiers on the kernel geneve `collect_md` device
and on the guest taps (see [Datapath programs](../architecture/dataplane/programs.md)). The only
real XDP program left is the debug-only `xdp_inspect`, attached by `flowplane inspect` (native,
falling back to `XdpFlags::SKB_MODE`) and never part of forwarding.

`FLOWPLANE_SKB_MODE` survived that change and is still set fleet-wide in the lab, but it now does
exactly one thing: it forces the jumbo-MTU gate open (`probe_jumbo_ok` / `jumbo_ok` in
`flowplane/flowplane/src/cli/serve.rs`). Without it, `serve` hands out a jumbo guest MTU only when
every uplink definitively advertises XDP scatter-gather (`rx-sg` in `ip -d link show`'s
`xdp-features`); a containerlab veth advertises no `xdp-features` line at all, so the probe returns
"unknown" and conservatively clamps the guest to the 1500-derived MTU. The env var is therefore
what keeps the jumbo compute underlay below working:

- Compute nodes: `FLOWPLANE_SKB_MODE=1` in the pool chart's `dataplane-ebpf` DaemonSet (clab env
  only).
- WAN edges: `FLOWPLANE_SKB_MODE: "1"` on the `flowplane-edge1` / `flowplane-edge2` sidecars in
  `fabric.clab.yml.tmpl`. Inert there (an edge hosts no guests, so it derives no guest MTU), kept
  for parity with the reference `serve --role edge` invocation.

The original reason for the pin — a *native* XDP redirect into a clab veth failing with
`-95`/`EOPNOTSUPP` on the veth `ndo_xdp_xmit` peer requirement — no longer applies to anything.
There is no `GUEST_DEV` devmap; guest delivery is a `bpf_redirect_peer` when the delivery device
has a pod-netns peer (veth/netkit) and a plain `bpf_redirect` otherwise, both skb helpers with no
driver requirement. (The inline comment on the chart's env var still tells the old XDP story — the
value is right, the stated reason is stale.)

Both VyOS edges do run a flowplane sidecar. Each shares its VyOS container's netns
(`network-mode: container:clab-<lab>-edge{1,2}`) and serves `--role edge --uplink eth1
--wan-uplink eth3`, so `wan_rx` lands on the tcx ingress of the dual-stack WAN segment while the
fabric ToR uplink supplies `LOCAL`. Both carry the sidecar so the edge-owned public prefixes can be
advertised *anycast* — the WAN ECMPs to either edge, and the live tests register each LB address on both
(`TestLbDistributeSmoke{,V4}` in `test/lab/livetest/lb_test.go`, `TestNatEgressReturn6` in
`nategress6_test.go`).

Verify the attachments with the devShell `bpftool` `nsenter`'d into the node netns:
`bpftool net show dev <dev>` renders the tcx section. Talos' own in-container `bpftool` is both
missing and, where one exists, too old to render tcx at all — see the
[runbook](../operations/runbook.md). The graceful-restart adopt path re-points the surviving pinned
link at the freshly-loaded program (`bpf_link_update`), so a plain DaemonSet rollout never detaches
the datapath; to force a fresh attach, clear the pins.

### Fabric MTU (jumbo on the compute underlay, 1500 at the edge)

containerlab defaults every veth to MTU 9500; `fabric.clab.yml.tmpl` overrides it per link, in
two bands:

- Compute-node underlay uplinks (`<node>:eth1 → sw1`, `<node>:eth2 → sw2`) are pinned to
  **9000**, deliberately jumbo, so the E/W overlay can carry jumbo guest frames. flowplane
  derives the guest MTU from the uplink (8920 = 9000 − `ENCAP_OVERHEAD_V6` 80: 56 bytes of
  Geneve encap plus the 24-byte DSR Geneve option, subtracted fleet-wide) and the CNI
  provisions the pod's overlay interface with it — `TestPodOverlayPing`
  (`test/lab/livetest/pod_test.go`) asserts the in-pod overlay MTU came out jumbo and then
  pushes an ~8 KB ping across it. This is fine because compute nodes run with
  `FLOWPLANE_SKB_MODE`, which unconditionally allows jumbo — the skb path carries non-linear
  frames; the native `#[xdp(frags)]` multi-buffer fast path is hardware-gated.
- Edge, WAN, Tayga, registry and host-jump links stay at **1500** — guests PMTU-clamp for
  internet egress.

The dataplane code itself is MTU-agnostic; the numbers are a harness knob.

### Per-edge bpffs pin namespace

The two `flowplane --role edge` sidecars are co-located on one host and bind-mount the same
`/sys/fs/bpf`, so without a split they would collide on identically-named pins — one edge
adopting the other's maps and links. Each is therefore given its own pin namespace via
`--pin-dir /sys/fs/bpf/flowplane-edge1` / `--pin-dir /sys/fs/bpf/flowplane-edge2`. That flag is
the live mechanism, not a historical note: drop it and the second sidecar silently adopts the
first's state. The in-cluster DaemonSet needs no such split — each node has its own bpffs and
runs exactly one flowplane pod.

## Debugging the datapath (tcx hooks and kernel stack)

`flowplane`'s datapath is a set of tcx classifiers over the kernel geneve `collect_md` device, so
the old "XDP consumes the packet before the AF_PACKET tap" framing no longer holds: on ingress the
packet taps run ahead of the tc hook, and the kernel — not eBPF — strips the outer header. That
makes `tcpdump` useful again, as long as you pick the right device:

- The fabric uplink (`sudo nsenter -t <pid> -n tcpdump -eni eth1`) shows the full
  `Eth·IPv6·UDP(6081)·Geneve·inner` frame. The NAT live tests depend on exactly this — they sniff
  eth1/eth2 with an outer-IPv6 + inner-header filter and assert on the inner packet
  (`TestNatEgressSmoke6`, `test/lab/livetest/nategress6_test.go`).
- The geneve device shows the already-decapped inner frame — the same view `uplink_dsr_note` and
  `uplink_rx` get.
- What no host-side capture shows is the *verdict*. A `bpf_redirect` hands the skb straight to
  another device's transmit path, and local guest delivery prefers `bpf_redirect_peer`, which
  injects the skb at the peer's ingress inside the pod netns. So on the sending device a delivered
  packet and a dropped one still look alike; capture in the guest netns
  (`nsenter --net=/proc/<pid>/root/run/netns/<id> …`, as `TestNatEgressReturn6` does) to see the
  far end.

For kernel-global visibility across netns the `skb:kfree_skb` drop-reason tracepoint remains the
primitive. Aggregated by `(reason, skb->protocol, freeing-fn)` it catches kernel-stack drops after
a `TC_ACT_OK` pass-to-stack — e.g. `SKB_DROP_REASON_OTHERHOST` on IPv4 at `ip_rcv_core` is the
wrong-MAC / shared-bpffs collision above. Reach for it before theorizing about where a passed
packet died: a `kfree_skb` reason plus a `LOCAL` map dump (`bpftool map dump pinned …`) usually
give the answer in one shot.

The `xdp:xdp_redirect{,_err}` / `xdp:xdp_devmap_xmit` tracepoints that used to be the first stop
here are XDP-only and now fire for nothing on this fabric: the sole remaining XDP program is the
debug `xdp_inspect`, which dumps into a map and never redirects. An `xdp_redirect_err err=-95` is
consequently a historical signature, not something this datapath can produce. There is no `tc:`
tracepoint group to swap in; the nearest skb-path equivalents are `net:netif_receive_skb` and
`net:net_dev_xmit`.

## Host/kernel interactions the bring-up handles

The lab's `up` handles host/kernel + clab interactions that otherwise break a headless
bring-up (each cost real debugging — do not "simplify" them away):

- `bridge-nf-call-ip6tables=0` — with it =1, even same-bridge IPv6 ND frames traverse the
  host ip6tables FORWARD chain (clab sets that chain's policy to DROP), so a multi-node
  cluster's nodes can't ND each other → never Ready.

See the [runbook](../operations/runbook.md) for the operational gotchas (real-`sudo` path, conntrack-map
OOM / `make bpf-clean`, the edge `FLOWPLANE_PIN_LINKS=false`, in-container `bpftool`).
