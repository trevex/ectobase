# Realistic BGP Fabric: Node Identity = Announced /64 (research + design)

**Date:** 2026-07-14
**Status:** Research/design agreed at the fork (B-hybrid + /64-per-node); next step is a hands-on spike, then a plan.
**Context:** The current clab IPv6 fabric (`hack/clab/ipv6-fabric.clab.yml`) integrates kind nodes with BGP, but **single-homed** and with a **split identity**: kubelet's Node InternalIP is the kind **docker mgmt IP** (`fc00:f853:…`), while the fabric `/64` is bolted onto `dummy0` *after* boot by a `clab exec`, with a per-node FRR **sidecar** doing BGP afterwards. That is not how a real bare-metal-on-BGP node bootstraps.

## Problem statement
Make the lab faithful: **the node's kubelet Node InternalIP must be the BGP-announced fabric address, and that address must exist before kubelet starts — the node itself is the BGP speaker.** This tests the dataplane as the owner of the node's real identity, not as a bolt-on. The user's refinement: the announced unit is a **per-node `/64`** (matching the dataplane's `/64`-per-node underlay), and the node-IP is an address within it (`fd00:db8:0:N::1`), **not** a `/128` loopback.

Two realism layers were separated:
1. **Fabric** — dual-homed / ECMP underlay (leaf-spine). Container-achievable (see §Fabric).
2. **Node identity + bootstrap ordering** — kubelet node-IP = fabric address, pre-kubelet. The focus here.

## Key research findings (cited)

### Fabric multi-homing / ECMP (research pass 1)
- Multi-homing kind nodes **works**: clab honors literal interface names, so a second uplink `eth2 → sw2` alongside `eth1 → sw1` on an `ext-container` kind node is valid (`eth0` stays kind mgmt). Only *shown* with one uplink in the k8s-kind docs → smoke-test the 2nd veth into a kind-owned netns.
- ECMP-to-host is the **Cumulus unnumbered model**: one FRR (in the shared netns / node) runs two unnumbered eBGP sessions, announces the same prefix on both, `maximum-paths` + `bestpath as-path multipath-relax` → ECMP in the kernel FIB flowplane reads.
- **VMs are the wrong axis** for fabric realism: kind is container-based; clab VM nodes replace kind, not host it. VMs only add real-driver / native-XDP realism — which our own notes say is blocked upstream by the vhost/KVM chain, not the fabric.
- Minimal realistic Clos: **2 FRR leaves + 1 FRR spine**, each node dual-homed. Sources: containerlab k8s-kind/ext-container/topo-def docs; FRR BGP unnumbered docs; containerlab `min-clos`.

### Node-IP = pre-kubelet BGP address on kind (research pass 2)
- kind templates `node-ip` from the docker IP, but **`kubeadmConfigPatches` overrides it** (user strategic-merge patches win). Patches are **cluster-wide**, so *distinct per-node* prefixes must be injected by a **custom node image / pre-kubelet unit**, not a shared patch.
- kindest/node runs **systemd 252**; kubelet is a systemd unit. A `Before=kubelet.service`, `Type=oneshot`, `RemainAfterExit=yes` unit is the clean injection point. Per-node `image:` and per-node `extraMounts` are both supported by kind.
- kindest/node's **entrypoint sed-rewrites the old→new docker IP** across kubelet/control-plane files on restart. A fabric address does not match the stored docker IP, so it survives — but the ordering (our unit must re-assert after the entrypoint, before kubelet) is the **#1 spike risk**.
- Apiserver-**on-fabric** (advertiseAddress/controlPlaneEndpoint = fabric) is where kind fights hardest (bootstrap + exported kubeconfig ride the docker host-port map; entrypoint re-pins the docker IP). → **Hybrid** is the sweet spot: bootstrap + host kubectl over docker; **Node InternalIP + dataplane on the fabric**.
- Prior art: loopback-over-unnumbered-BGP in container labs is common (fedepaol EVPN+FRR, MetalLB/FRR-K8s), but **loopback-as-kubelet-InternalIP** exists only on bare metal (linuxsimba Cumulus+Quagga) — the kind node-ip half is **greenfield**.
- Ordering has no hard deadlock: a locally-assigned address on `dummy0`/`lo` is next-hop-independent and instant; only *cross-node reachability* needs BGP convergence, gated per node. (FRR gotcha: `network <prefix>` only advertises if the prefix is actually present on an interface — the `ip addr add` is mandatory.)

## Decision (the fork)
- **Substrate: B-hybrid on kind.** We care about the **kubelet IP**, not the apiserver IP. Node InternalIP + dataplane on the fabric; kind bootstraps + exports kubeconfig over docker.
- **Announced unit: a per-node `/64`** (`fd00:db8:0:N::/64`), node-IP = `fd00:db8:0:N::1`, consistent with the dataplane's `/64`-per-node underlay (the same `/64` flowplane infers from dummy0 and allocates endpoint `/128`s from — reserve `::1` for the node so it doesn't collide with endpoint allocations).

## Target architecture (B-hybrid, /64 per node)
1. **Custom node image** `FROM kindest/node:<pinned>@sha256`: install FRR; `systemctl enable frr`; ship + enable `fabric-preboot.service` (`Before=kubelet.service`, oneshot, RemainAfterExit) that:
   - reads the per-node prefix from an `extraMounts`-injected file (e.g. `/etc/fabric/prefix` = `fd00:db8:0:1::/64`);
   - `ip addr add fd00:db8:0:1::1/64 dev dummy0` (create dummy0 if absent) — **before kubelet**;
   - rewrites `/var/lib/kubelet/kubeadm-flags.env` `--node-ip=fd00:db8:0:1::1` (belt-and-suspenders with the kubeadm patch);
   - starts FRR announcing `network fd00:db8:0:1::/64` over unnumbered eBGP (peers once clab wires `eth1`; convergence may trail kubelet — fine, identity is already local).
2. **kind config:** per-node `image:` = the custom image; per-node `extraMounts` for the prefix + FRR conf; `kubeadmConfigPatches` setting `nodeRegistration.kubeletExtraArgs.node-ip` (cluster-wide fallback) and `apiServer.certSANs` including the node/CP fabric addresses; keep `networking.apiServerAddress: 127.0.0.1` + a fixed port (bootstrap/kubeconfig stay on docker).
3. **clab topology:** keep the ToR(s) + `eth1` (and later `eth2`) links; **drop the host-frr sidecars** (FRR now runs in the node — the node is genuinely the speaker) and **drop the dummy0 `clab exec`** (the node's own unit owns dummy0 pre-kubelet). The per-node `/64` moves from clab `exec` to kind `extraMounts` so it is known at systemd boot, before any clab post-boot step.
4. **flowplane:** unchanged — it infers the `/64` from dummy0 (now set pre-kubelet) and the node-IP is finally consistent with the dataplane underlay.

Optional follow-on (separate): **dual-homing + ECMP** — add `eth2`+`sw2` (dual-home to two ToRs, no spine interlink — redundancy IS the dual-homing, per the icn/sandbox reference fabric), the node's FRR peers both, `bestpath as-path multipath-relax` + `maximum-paths` + `fabric-fast` BFD.

**How dpservice does the datapath side (source-verified — simpler than a full ECMP overhaul):**
- Binds **two independent PFs** (`--pf0` owner, `--pf1` peer), **not a DPDK bond**.
- The route carries a **single** underlay next-hop (the *remote* hypervisor's underlay IPv6 = the IPinIPv6 outer dst). Local uplink choice is **decoupled from the route** — our `routebus`/`AddRoute` model needs **no change**.
- Egress PF = **per-flow** `dp_multipath_get_pf(flow_hash)`: a 10-slot WCMP table. **Default `wcmp=100` = pf0-only + carrier failover to pf1** (active/standby); WCMP opt-in for active-active. (Caveat: upstream applies the selector only in `ipv4_lookup_node`, not `ipv6_lookup_node` — v6-inner is effectively pf0.)
- **Per-PF next-hop MAC from the host kernel IPv6 neighbor table** (`RTM_GETNEIGH` per `if_index`) — dpservice does no uplink ND; the kernel learns the ToR via RA. **This is exactly what our flowplane DS wrapper already does** (`ip -6 neigh … router`) for the single-uplink case.
- Failover = DPDK link-status (carrier); no internal BFD (host routing stack owns BFD).

**flowplane mapping:** grow `LOCAL` from one uplink to **two** `{ifindex, uplink_mac, gateway_mac, up}` + a 10-slot WCMP table; egress picks `idx = wcmp[hash % 10]` (or pf0-else-pf1), `bpf_redirect(uplink[idx])`, writes `gateway_mac[idx]`. Userspace: a netlink watcher keeping each port's ToR MAC + carrier live (the wrapper already does the one-shot version). Default active/standby is trivial; WCMP active-active is the opt-in refinement. Sources: ironcore-dev/dpservice `src/dp_multi_path.c`, `dp_conf_opts.c` (`--pf0/--pf1/--wcmp`), `nodes/ip{v4,v6}_lookup_node.c`, `nodes/ipip_encap_node.c`, `dp_netlink.c` (`dp_nl_get_pf_neigh_mac`), `dp_lpm.h` (single-nh route).

## Spike — DONE (proven; `hack/kind-fabric-node/`)
Ran on one custom kind node (no clab). **The node-ip mechanism and FRR packaging are proven.**

**Pivotal mechanism (confirmed on the live node):** kind's kubelet unit runs
`kubelet … $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS`, sourcing `KUBELET_EXTRA_ARGS`
from `/etc/default/kubelet`. kubeadm writes `--node-ip=<docker>` into `KUBELET_KUBEADM_ARGS`
(kubeadm-flags.env) *after* kubelet.service has started, so we do **not** rewrite that file.
Instead `fabric-preboot` (a `Before=kubelet.service` oneshot) appends `--node-ip=<fabric>` to
`KUBELET_EXTRA_ARGS` — it appears **last**, and a repeated `--node-ip` → **last wins**. So kubelet's
Node InternalIP is the fabric addr regardless of what kubeadm set.

Results:
1. ✅ Node `InternalIP = fd00:db8:0:1::1` (the `/64`'s `::1` on dummy0), node **Ready**; apiserver/kubeconfig stay on docker (hybrid holds).
2. ✅ **Survives a container restart** — even though the docker IP changed on restart (kind's IP-migration case; kubeadm re-pins `--node-ip=<new-docker>`), our `KUBELET_EXTRA_ARGS` `--node-ip` is appended last and wins; `/etc/default/kubelet` has the fabric IP so the entrypoint's old→new docker-IP sed can't match/clobber it. **Resolves research risk #1.**
3. ✅ **FRR baked into the node image**, started by `fabric-preboot`, generating the correct per-node config (`network fd00:db8:0:1::/64`, unnumbered `neighbor eth1`, `maximum-paths 64`, `allowas-in`), active and ready to peer. The node is now its own BGP speaker (no sidecar). An *established* session needs a wired ToR — already proven by the existing sidecar fabric with identical config in the same netns.

Per-node prefix is injected via kind `extraMounts` (`/etc/fabric/prefix`). Optional `/etc/fabric/uplinks` overrides the uplink list (default `eth1`; `eth1 eth2` for dual-homing).

**Phase 1 integration — DONE + validated end-to-end** (`docs/superpowers/plans/2026-07-14-fabric-node-identity-integration.md`, executed): the custom image is wired into the clab fabric (k8s-kind `startup-config` → custom image + per-node `/64` via `extraMounts`; the `host*-frr` sidecars and the dummy0 `clab exec` are gone; `clab-up` builds the image + renders the mount paths). Verified on the live 2-cluster fabric: all node InternalIPs = their fabric `::1` (`fd00:db8:0:{1,2,3}::1`, not docker); in-node FRR sessions to `sw1` **Established** (PfxRcd/PfxSnt=3); cross-cluster underlay routes learned; no sidecars; and the **flowplane cross-cluster overlay ping stays 0% loss** — the dataplane works on the fabric-identity nodes.

**Boot-race finding + fix (kindnet vs BGP convergence):** the fabric-identity model gives the CNI a boot-time dependency on peer reachability. kindnet routes each peer's pod-CIDR via that peer's InternalIP — now the fabric `::1` — so at init it needs BGP converged; it panics with "no route to host, Maximum retries" if it loses the race (kindnet's ~5s retry budget). **Fix (shipped):** `fabric-preboot` now GATES kubelet on BGP convergence — after starting FRR it waits (bounded, `FABRIC_BGP_TIMEOUT=60`s) until the FIB has a BGP-learned route (`ip -6 route proto bgp` non-empty), then lets kubelet start. Because the unit is `Before=kubelet.service`, kubelet (and thus kindnet) doesn't start until the fabric is routed. The earlier deadlock worry was unfounded: **clab wires `eth1` early enough** that FRR converges during preboot, so kind reaches Ready normally (no deadlock; the timeout is just a safety fallback). Verified redeploy: no deadlock, and kindnet crashloop (3+) dropped to **≤1 self-healing restart** with all nodes **auto-Ready, no manual kick**. Residual: on a multi-node cluster a node's kindnet still needs the *peer's* `/64`, which depends on the peer having booted+announced — local gating can't wait for a not-yet-advertised route, so one restart can remain (self-heals). Same pattern holds for the dual-homing phase.

**Phase 2 — dual-homing + ECMP DONE + validated** (`docs/superpowers/plans/2026-07-14-fabric-dual-homing-ecmp.md`, executed): added `sw2` + an `eth2` uplink per node (no `sw1–sw2` interlink), `UPLINKS="eth1 eth2"` via mount, `fabric-fast` BFD in the in-node FRR (and enabled `bfdd` in the image — it was configured-but-dead). Verified on the live fabric: **two Established BGP sessions per node** (sw1/eth1 + sw2/eth2), peer `/64`s installed with **two FIB next-hops (ECMP)**, **two BFD sessions up** per node, **failover** (drop `eth2` → peer `/64` stays reachable via `eth1`, no blackhole), and the **flowplane overlay ping stays 0% loss** (datapath still egresses `eth1`; fabric ECMPs the return). Note: after a *manual* `ip link down/up` flap, BGP re-forms multipath (RIB shows 2 paths) but zebra's kernel nexthop-group can briefly lag at 1 FIB nexthop — an FRR/zebra flap quirk, not a dual-homing issue (fresh deploy + non-flapped nodes show full ECMP).

**Follow-on (separate plan):** active-active egress ECMP in flowplane (two-uplink `LOCAL` + 50/50 WCMP + per-port ToR MAC from netlink neigh, mirroring dpservice) — so *outbound* traffic uses both uplinks, not just `eth1`.

## Datapath ECMP decision
When we build the flowplane egress multipath (phase 3), do **active-active per-flow hashing across both uplinks** (not dpservice's default active/standby `wcmp=100`): in a Clos both uplinks are equal-cost, so there's no reason to prefer one. Mirror dpservice's mechanism (per-PF ToR MAC from kernel neigh, single-nexthop route) but set the WCMP split 50/50 by default. See the dpservice egress model above.

## Top risks / unknowns
1. **Entrypoint-vs-preboot ordering** (highest): our unit must re-assert node-ip after kindest/node's entrypoint sed but before kubelet — prove empirically across a restart.
2. **Per-node identity plumbing**: distinct `/64`s via custom image + `extraMounts` + hostname, and kubelet actually reporting the fabric addr; FRR advertising each `/64`.
3. **Uplink timing**: clab wires `eth1` around/after node boot; BGP convergence trails kubelet. Acceptable (identity is local), but confirm node stays Ready and fabric reachability converges without manual nudging.

## References
containerlab: k8s-kind, ext-container, topo-def, vrnetlab, cvx, sonic-vm, min-clos, min-5clos kinds/labs. kind: Configuration docs (per-node image/extraMounts/kubeadmConfigPatches), issues #3071 (restart IP migration), #1732 (kubeconfig host-port). kind source: `pkg/cluster/internal/kubeadm/config.go`, `images/base/files/usr/local/bin/entrypoint`. FRR: BGP unnumbered / maximum-paths docs, issue #7249 (`network /32` needs addr on iface). Prior art: linuxsimba baremetal-Cumulus-Quagga; fedepaol EVPN+FRR on kind; kube-vip BGP; NVIDIA/Cumulus routing-on-the-host.
