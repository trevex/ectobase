# tc / tcx / Geneve kernel behaviour: the load-bearing details

`flowplane`'s forwarding path is a set of tc (tcx) classifiers over a kernel Geneve `collect_md`
overlay. Its correctness depends on a handful of Linux kernel behaviours that are easy to get wrong
and hard to observe. This chapter is the reference for the ones the datapath hits in practice, each
stated with what the kernel does and how it bit us, so the constraint survives independent of any one
bug. Several are veth/netkit-specific (the containerlab/Talos fabric); real NICs behave more
forgivingly, which is why a clab-green datapath can still carry latent assumptions.

## The overlay is kernel Geneve, not a hand-rolled tunnel

The datapath does not write outer-header bytes. The kernel geneve `collect_md` device builds the outer
Ethernet/IPv6/UDP/Geneve header on transmit and strips it on receive. eBPF interacts with the tunnel
only through skb tunnel metadata:

- Egress: a tc program resolves a `{vni, remote underlay}` decision, stamps it as the skb's tunnel
  key with `bpf_skb_set_tunnel_key` (plus `bpf_skb_set_tunnel_opt` for the DSR Geneve option), and
  `bpf_redirect`s to the geneve device. The device reads the metadata back and emits the wire frame.
- Ingress: the geneve device decaps before any eBPF program runs, then delivers the inner frame to
  its own tcx ingress hook. A tc program recovers the VNI with `bpf_skb_get_tunnel_key` (and the DSR
  option with `bpf_skb_get_tunnel_opt`).

`bpf_skb_set_tunnel_key` is an skb-only helper; it has no XDP counterpart, because XDP runs before an
skb (and its tunnel metadata) exists. That is one reason the overlay path is tc, not XDP.

## Where XDP still appears

XDP is used for exactly one program, `xdp_inspect`, a debug packet-dump attached by `flowplane
inspect`. It attaches native (`XdpFlags::default()`) and falls back to generic
(`XdpFlags::SKB_MODE`). The native-vs-generic distinction (driver NAPI poll on an `xdp_buff` before
the skb exists, versus `netif_receive_skb` after `eth_type_trans` has set `skb->protocol`/`pkt_type`)
therefore matters only for that inspector, never for forwarding. No forwarding program is XDP, and no
program is pinned as an XDP link.

The one other place XDP features are consulted is the guest-MTU jumbo probe (below): it reads an
uplink's advertised XDP scatter-gather as a conservative capability signal, not because the fabric
path runs native XDP.

## tcx: runs after `eth_type_trans`, no native/generic split, no MTU ceiling

tc (clsact) and tcx programs run in the skb path, after `eth_type_trans` has set
`skb->protocol`/`pkt_type`, so on ingress they see correct L3 metadata. There is no native-driver
mode and no linear-buffer MTU ceiling: tc is always skb-based and carries non-linear (jumbo) skbs
unchanged. The tradeoffs versus XDP are the usual ones — tc runs later (after skb allocation, so
higher per-packet cost) but is portable across every device type and needs no driver XDP support.

Verdicts the datapath returns:

- `TC_ACT_OK` passes the skb up the local stack (a final verdict for the last program on the hook).
- `TC_ACT_UNSPEC` (`TCX_NEXT`) yields to the next tcx program on the same hook. `uplink_dsr_note`
  returns this so `uplink_rx` runs after it.
- `TC_ACT_SHOT` drops.
- Delivery is a `bpf_redirect(ifindex, 0)` or `bpf_redirect_peer(ifindex, 0)` to the target device;
  overlay egress is a `bpf_redirect` to the geneve device after the tunnel key is stamped.

`bpf_redirect_peer` moves the skb directly into a veth/netkit peer's netns ingress in one hop
(cheaper than a plain redirect and it re-runs ingress in the peer namespace), which is why local
delivery to a pod prefers it when the device has a peer.

## `pkt_type` / `PACKET_OTHERHOST`: the delivered frame's dst MAC must match the receiving device

`eth_type_trans` sets `skb->pkt_type`: if the Ethernet destination MAC is not the receiving device's
MAC (and is not broadcast/multicast), it is `PACKET_OTHERHOST`, and `ip_rcv_core` drops it with
`SKB_DROP_REASON_OTHERHOST` before the L3 stack sees it. Any path that hands a frame to a local stack
must therefore rewrite the inner Ethernet destination to the receiving device's own MAC.

Two places rely on this:

- WAN edge local-deliver: `edge_local_deliver` rewrites the inner Ethernet destination to
  `LOCAL.uplink_mac` before `TC_ACT_OK`. When that map value was stale (a shared-bpffs collision left
  the other edge's MAC there), every delivered packet died as `OTHERHOST` in `ip_rcv_core`, visible
  only via the `skb:kfree_skb` drop-reason tracepoint.
- L3 netkit pod delivery: an NOARP L3 netkit device does destination-MAC filtering and accepts only
  its own device MAC (all-zero) or broadcast/multicast. So `decap_and_rewrite` writes the all-zero
  destination MAC for an L3 pod and the guest MAC for an L2 tap/veth; an arbitrary unicast would drop
  as `PACKET_OTHERHOST`.

## skb resizing on the reply paths

The overlay path does not grow or shrink packets: the kernel owns outer-header add/strip, and encap
is a metadata stamp, so the inner frame is never resized on the forward path. The programs that do
resize are the local responders that build a reply larger than the request: `tc_guest_dhcp` grows the
skb to the fixed reply length with `bpf_skb_change_tail` (after `bpf_skb_pull_data` makes the head
linear for direct packet access), and the IPv6 RA responder grows the RS into a larger RA the same
way. These use skb helpers, not the `bpf_xdp_adjust_head` an XDP tunnel would need.

## MTU and encap overhead

Geneve-over-UDP-over-IPv6 adds `GENEVE_OVERHEAD` = 56 bytes on top of the inner frame: outer IPv6
(40) + outer UDP (8) + Geneve header (8). The outer Ethernet (14) is link framing on the fabric NIC,
not part of the L3/L4 overhead a guest's own MTU must budget for. This is more than VXLAN's 50 (VXLAN
has an 8-byte header like Geneve but Geneve carries option TLVs), and far more than the 40 a bare
IP-in-IPv6 tunnel would add.

The datapath subtracts a slightly larger figure, `ENCAP_OVERHEAD_V6` = 80 = the 56-byte Geneve base
plus the 24-byte DSR Geneve option (`flowplane_core::dsr::DSR_OPT_BUF_LEN`). The DSR option is
subtracted fleet-wide, not only on nodes that host LB backends, so a full-MTU inner frame plus the
option always fits the underlay path MTU however the traffic ends up routed.

### Guest MTU provisioning

One node-wide guest MTU is derived at `serve`: the smallest uplink L3 MTU over
`--uplink`/`--extra-uplink`, minus `ENCAP_OVERHEAD_V6` (80), floored at 576 (default 1500 − 80 =
1420). `--guest-mtu` overrides the derivation. That single value drives:

- The guest link MTU, set on both ends of the guest device at attach. Because the dataplane owns the
  device lifecycle it sets the MTU itself; the CNI needs no MTU knowledge, and since the link MTU is
  already the tunnel-adjusted value no separate route MTU (`RTAX_MTU`) is needed. This differs from
  Cilium, which keeps the link at the device MTU and relies on route MTU.
- PLPMTUD: `net.ipv4.tcp_mtu_probing=1` in the guest netns at attach, so TCP self-discovers the path
  MTU without relying on ICMP.
- DHCPv4 option 26: for self-configuring guests/VMs that run a DHCP client.
- The IPv6 RA MTU option: DHCPv6 has no MTU option (MTU is RA-only in IPv6), so the guest edge answers
  a Router Solicitation (ICMPv6 type 133) with a Managed Router Advertisement (`ra_reply` in
  `flowplane-core/src/arp_nd.rs`) carrying the MTU option (type 5) with this value. No SLAAC prefix;
  addressing stays with DHCPv6 / control-plane IPAM.

There is no ICMP "packet too big" generation in the datapath (Cilium also punts on this in native
routing); correct provisioning plus PLPMTUD covers the TCP case, and a guest that force-raises its own
MTU past the provisioned value is out of the datapath's control.

### Jumbo gating

Jumbo is offered only where the datapath is known to carry it: `FLOWPLANE_SKB_MODE` forces the skb
path (which handles non-linear frames), or an uplink advertises XDP scatter-gather (`rx-sg` in `ip -d
link show`'s `xdp-features`). Otherwise the guest is clamped to the standard 1500-derived MTU rather
than handed a jumbo value that could degrade. This probe is a conservative capability gate; the
forwarding path itself is tcx and skb-based. On containerlab the compute-node uplinks run MTU 9000
end-to-end (guest MTU 8920 = 9000 − 80), exercised by `TestPodOverlayPing`.

## tcx attach and pinned links: the loader model

The loader attaches every forwarding program as a tcx classifier (`SchedClassifier` +
`TcAttachType::Ingress`) and, when `--pin-links` is set (default), pins the resulting FdLink to
bpffs. Two ordering and lifecycle facts matter:

- Ordered attach: `uplink_dsr_note` is attached with `TcAttachOptions::TcxOrder(LinkOrder::first())`
  so the kernel runs it ahead of `uplink_rx` on the shared geneve ingress hook; `uplink_rx` attaches
  with the default (append) order.
- Zero-gap restart: a pinned link survives the process. On restart the loader reloads the program and
  re-points the surviving pinned link at it atomically (`bpf_link_update`), so the datapath is never
  detached. The re-attach mechanism is chosen by device kind: a netkit primary is driven via
  `BPF_LINK_UPDATE`, while a veth/tap uses the tcx re-adopt path; mismatching them would unpin a live
  link. See [HA & graceful restart](../ha-graceful-restart.md).

## bpffs: kernel-global maps, pinning, and netns

BPF maps and programs are kernel-global objects, not namespaced. Two consequences the datapath relies
on and one that bit us:

- Global observability. One kernel backs every clab container, and prog IDs plus tracepoints
  (`tc:*`, `skb:kfree_skb`) are global, so a single `bpftrace`/`bpftool` on the host sees drops and
  redirects across every netns at once.
- Pinning is per-bpffs-mount. A pinned map lives at a bpffs inode; it outlives the creating process,
  and two processes that open the same pin path on the same bpffs share the map. The state maps are
  declared `pinned`, so the loader must be given a pin dir; a fresh run uses an ephemeral per-run dir,
  a restart uses the persistent bpffs dir to re-bind the surviving maps.
- netns does not scope bpffs. Two processes in different netns that mount the same `/sys/fs/bpf` and
  pin under the same dir collide on one map set. This is exactly the two-edge `LOCAL` collision:
  separate netns, shared host bpffs, one `LOCAL` map. Isolation comes from separate pin dirs (or
  separate bpffs mounts, as each Talos node / real host already has), not from netns.

## `skb:kfree_skb` drop reasons — the debugging primitive

Since ~5.17 the `skb:kfree_skb` tracepoint carries a `reason` enum (`SKB_DROP_REASON_*`) plus
`skb->protocol` and the freeing function. Because it is kernel-global, aggregating
`(reason, protocol, ksym(location))` over a failing flow reveals where and why a packet died. It is
the fastest way to distinguish `OTHERHOST` (wrong MAC) from `NETFILTER_DROP` (a firewall rule) from
`IP_*` (header/checksum), all of which look identical to `tcpdump`, which taps before these drops.
Reach for it before theorizing.
