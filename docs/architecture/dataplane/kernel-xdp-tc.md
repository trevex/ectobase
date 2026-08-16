# XDP / tc / bpf kernel behaviour (the load-bearing details)

`flowplane` is an XDP + tc datapath, so its correctness depends on a handful of Linux kernel
behaviours that are easy to get wrong and hard to observe. This chapter is the reference for the ones
we hit in practice — each is stated with *what the kernel does* and *how it bit us*, so the constraint
survives independent of any one bug. Most of these are **veth-specific** (the containerlab/kind
fabric): real NICs behave more forgivingly, which is exactly why a clab-green datapath can still have
latent assumptions.

## XDP attach modes: native (driver) vs generic (SKB)

An XDP program attaches in one of two modes:

- **Native / driver (`XDP_FLAGS_DRV_MODE`)** — the program runs in the driver's NAPI poll, on the raw
  `xdp_buff`, *before* an `sk_buff` exists. On `XDP_PASS` the driver **builds a fresh skb** from the
  (possibly modified) frame and hands it to the stack, so `eth_type_trans` runs on the *current* bytes.
- **Generic / SKB (`XDP_FLAGS_SKB_MODE`)** — the program runs in `netif_receive_skb`, *after* the skb
  already exists and `eth_type_trans` has already set `skb->protocol` and `skb->pkt_type`. On
  `XDP_PASS` the *same* skb continues up the stack; its metadata is **not** recomputed.

The loader (`attach_xdp_mode`) prefers native (`XdpFlags::default()`) and falls back to SKB; setting
`FLOWPLANE_SKB_MODE=1` forces generic.

### `skb->protocol` is not re-derived on a generic `XDP_PASS`

If a program decaps (e.g. strips outer Eth+IPv6 to expose inner IPv4) and returns `XDP_PASS`:

- **native**: the rebuilt skb runs `eth_type_trans` → `skb->protocol = ETH_P_IP` → the packet reaches
  `ip_rcv` / `ip_rcv_core`. Works.
- **generic**: `skb->protocol` was set to the *outer* ethertype (`ETH_P_IPV6`) before the program ran
  and stays stale → the inner IPv4 is dispatched to `ipv6_rcv` (or nowhere) and never reaches the IPv4
  stack. Silent.

**How it bit us:** the WAN edge's `edge_local_deliver` decaps then `XDP_PASS`es the inner IPv4 to
VyOS. Under generic XDP it vanished before `ip_rcv_core`; switching the edge to **native** fixed it.
Consequence: the edge *must* run native XDP. (See [the clab fabric page](../../guides/local-fabric.md) for
the per-role mode split.)

## `pkt_type` / `PACKET_OTHERHOST`: the delivered frame's dst MAC must match the iface

`eth_type_trans` also sets `skb->pkt_type`: if the Ethernet **destination MAC ≠ the receiving
interface's MAC** (and isn't broadcast/multicast), it is `PACKET_OTHERHOST`, and `ip_rcv_core` drops
it with `SKB_DROP_REASON_OTHERHOST` — the L3 stack never sees it. So a program that decaps and hands
the frame to the *local* stack must rewrite the inner Ethernet **dst = the receiving interface's own
MAC**.

**How it bit us:** `edge_local_deliver` writes `dst = LOCAL.uplink_mac`. When that map value was stale
(a shared-bpffs collision left the *other* edge's MAC there), every decapped packet died as
`OTHERHOST` in `ip_rcv_core` — visible only via the `kfree_skb` drop-reason tracepoint.

## `bpf_xdp_adjust_head` for decap/encap

Encap/decap move the data pointer with `bpf_xdp_adjust_head` (negative = grow headroom / prepend
outer headers; positive = shrink / strip). It only edits the **front**; header fields the program
touches are in the linear head, so direct packet access stays valid after the adjust. It does **not**
touch `skb->protocol`/`pkt_type` — those are re-evaluated (or not) per the mode rules above.

## veth native XDP has an MTU ceiling

The `veth` driver supports native XDP, but only when the frame fits its linear buffer — in practice
**MTU ≲ 3500** (a page-minus-headroom limit). Above that the attach fails with
`veth: Peer MTU is too large to set XDP` and the loader falls back to generic. Native at jumbo needs a
multi-buffer (`xdp.frags` / `BPF_F_XDP_HAS_FRAGS`) program.

`uplink_rx`, `xdp_uplink_v6`, and `wan_rx` are declared `#[xdp(frags)]` (aya sets
`BPF_F_XDP_HAS_FRAGS` at load) so native XDP *can* attach at jumbo MTU. This is safe because the
datapath only touches front headers (all access is const-offset within the guaranteed linear head)
and uses incremental delta checksums — it never reads the payload, which is what lives in the frags.
The verifier is stricter for frags programs, so a stray past-`data_end` read would be rejected; the
programs verify + stay byte-identical to the sim.

**Jumbo on clab vs. hardware.** On containerlab, compute nodes are *pinned to generic/SKB XDP*
(`FLOWPLANE_SKB_MODE`): native XDP redirect into a guest veth returns `-95/EOPNOTSUPP` on clab veths,
so the guest-delivery path must use the skb path. Generic/SKB XDP carries non-linear (jumbo) skbs
fine, so the fabric runs jumbo end-to-end — the compute-node underlay uplinks are **MTU 9000** (guest
MTU 8960 = 9000 − 40 encap), exercised by `TestPodOverlayPing` (an 8000-byte DF ping across the
overlay). The native `#[xdp(frags)]` *fast path* is therefore HW-gated (like DPDK): it needs a real
NIC whose driver advertises XDP scatter-gather (`NETDEV_XDP_ACT_RX_SG` / `NDO_XMIT_SG`), and is
covered by the byte-parity anchor rather than the clab datapath.

**Guest-MTU probe.** `flowplane serve` probes each uplink's advertised `xdp-features` (`ip -d link
show`) and only hands guests a jumbo MTU when the datapath can carry it — generic/SKB mode (always),
or a native uplink advertising `rx-sg`. Otherwise it clamps the guest to the standard 1500-derived
MTU rather than a jumbo one the native path would drop. An explicit `--guest-mtu` overrides the probe.

## Guest MTU provisioning

One node-wide guest MTU is derived at `serve`: `min(uplink MTU over --uplink/--extra-uplink) − 40`
(outer IPv6; outer Eth is off-L3-MTU; the overlay is IP-in-IPv6 with no inner Eth/UDP/VXLAN, so 40 is
the whole overhead — *less* than VXLAN's 50). Override with `--guest-mtu`. That single value drives:

- **The veth link MTU** — set on both veth ends at attach (`attach.rs::setup_veth`). Because the
  dataplane owns the veth lifecycle, it sets the MTU itself; the CNI needs no MTU knowledge, and since
  the link MTU is already the tunnel-adjusted value, no separate route MTU (`RTAX_MTU`) is needed (this
  differs from Cilium, which keeps the link at the device MTU and relies on route MTU — see memory
  `cilium-mtu-model`).
- **PLPMTUD** — `net.ipv4.tcp_mtu_probing=1` set in the guest netns at attach, so TCP self-discovers
  the path MTU without relying on ICMP (Cilium's default).
- **DHCPv4 option 26** — for self-configuring guests/VMs that run a DHCP client.
- **The IPv6 RA MTU option** — for self-configuring IPv6 VMs. DHCPv6 has no MTU option (MTU is RA-only
  in IPv6), so the guest edge answers a Router Solicitation (ICMPv6 type 133) with a **Managed** Router
  Advertisement (`ra_reply` in `flowplane-core/src/arp_nd.rs`, mirroring `nd_reply`): M-flag set +
  router-lifetime + a Source-Link-Layer-Address option + the **MTU option (type 5)** carrying this
  value. No SLAAC prefix (addressing stays with our DHCPv6 / control-plane IPAM). The eBPF glue grows
  the skb (RA is larger than the RS) and redirects the reply back to the guest.

There is no ICMP "packet too big" generation in the datapath (even Cilium punts on this in native
routing); correct provisioning + PLPMTUD covers the TCP case, and a guest that force-raises its own
MTU past what we set is out of our control.

## XDP redirect into a veth: `-95/EOPNOTSUPP`, and why devmap

An XDP program delivers a packet elsewhere with `bpf_redirect(ifindex, 0)` or
`bpf_redirect_map(devmap, key, 0)`. On a **veth** target this uses `ndo_xdp_xmit`, which has a **peer
requirement**: a *native*-mode XDP redirect into a veth whose peer isn't set up for XDP fails with
`-95` (`EOPNOTSUPP`) — the redirect is counted on `xdp:xdp_redirect_err`, and the packet is dropped
*after* the program returned `XDP_REDIRECT` (so the program's own logic looks fine). The **generic**
path redirects via `dev_forward_skb` (an skb hop) and has no such requirement.

**How it bit us:** compute-node `uplink_rx` delivers to guests by redirecting into the guest veth
(`GUEST_DEV` devmap). Flipping nodes to native broke delivery with `err=-95`; nodes must stay
**generic**. (Contrast the edge, which needs native and does no guest-veth redirect.) Two consequences
baked into the code: overlay guest delivery uses a **devmap** redirect (not a plain `bpf_redirect`),
and the ToR's edge-facing port carries a trivial `xdp_pass` (`sw{1,2}-pass`) so the edge's `wan_rx`
`bpf_redirect` back over the fabric veth is accepted.

## tc / tcx: runs after `eth_type_trans`, can re-inject

tc (clsact) and tcx programs run in the skb path, **after** `eth_type_trans` has set
`skb->protocol`/`pkt_type` — so on ingress they see correct L3 metadata regardless of any prior XDP
decap, and there is **no** native-MTU ceiling (tc is always skb-based). To hand a modified packet back
to the stack with freshly-derived metadata, `bpf_redirect(ifindex, BPF_F_INGRESS)` re-injects it at
that device's ingress, which re-runs `eth_type_trans`. This is the tc-side alternative to the
native-XDP-`PASS` requirement (the guest edge is tcx: `tc_guest_tx` on the guest veth). Note the
`BPF_F_INGRESS` flag is a tc feature — XDP `bpf_redirect` cannot re-inject into its *own* ingress.

## bpffs: kernel-global maps, pinning, and netns

BPF maps and programs are **kernel-global** objects, not namespaced. Two consequences we rely on and
one that bit us:

- **Global observability.** One kernel backs every clab container, and prog IDs + tracepoints
  (`xdp:*`, `skb:kfree_skb`) are global — so a single `bpftrace`/`bpftool` on the host sees drops and
  redirects across *every* netns at once (this is what a single host-side `bpftrace` drop
  monitor exploits).
- **Pinning is per-bpffs-mount.** A pinned map lives at a bpffs inode; it outlives the creating
  process, and two processes that open the **same** pin path on the **same** bpffs share the map.
- **netns does *not* scope bpffs.** Two processes in *different* netns that mount the *same*
  `/sys/fs/bpf` and pin under the same dir **collide** on one map set. This is exactly the two-edge
  `LOCAL` collision — separate netns, shared host bpffs, one `LOCAL` map. Isolation comes from separate
  **pin dirs** (or separate bpffs mounts, as each kind node / real host already has), *not* from netns.

## `skb:kfree_skb` drop reasons — the debugging primitive

Since ~5.17 the `skb:kfree_skb` tracepoint carries a `reason` enum (`SKB_DROP_REASON_*`) plus
`skb->protocol` and the freeing function. Because it's kernel-global, aggregating
`(reason, protocol, ksym(location))` over a failing flow tells you *where and why* a packet died — the
cilium-drop-monitor pattern (a host-side `bpftrace` on `skb:kfree_skb`). It is the fastest way to distinguish, say,
`OTHERHOST` (wrong MAC) from `NETFILTER_DROP` (a firewall rule) from `IP_*` (header/checksum) — all of
which look identical to `tcpdump`, which taps *before* these drops. Reach for it before theorizing.
