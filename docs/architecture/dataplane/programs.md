# Programs and hooks

flowplane's datapath is a set of tc classifiers attached through tcx and netkit, working with the
kernel's Geneve device. This page goes through each program: where it attaches, what it does, and the
kernel behaviour it depends on. Each program body is thin glue around a function in
[the pure core](pure-core.md); the entry points named here are in `flowplane/flowplane-ebpf/src/`.

## The programs

| Program | Type | Attached to | Direction |
|---|---|---|---|
| `tc_guest_tx` | tc classifier | each guest device: the netkit primary through a `BPF_NETKIT_PEER` link; a veth, tap or VF representor through tcx ingress | guest → overlay |
| `tc_guest_dhcp` | tc classifier | not attached; tail call from `tc_guest_tx` (`GUEST_PROGS_TC` slot 0) | DHCPv4 and DHCPv6 responder |
| `tc_guest_nat64` | tc classifier | not attached; tail call (slot 2) | guest IPv6 to `64:ff9b::/96`, NAT64 |
| `tc_guest_egress_v6` | tc classifier | not attached; tail call (slot 3) | guest IPv6 overlay egress |
| `uplink_dsr_note` | tc classifier | `fp-geneve0` tcx ingress, ordered first | DSR note, then hand on |
| `uplink_rx` | tc classifier | `fp-geneve0` tcx ingress | overlay → local delivery |
| `xdp_uplink_v6` | tc classifier | not attached; tail call from `uplink_rx` (`UPLINK_PROGS` slot 0) | overlay IPv6 → local delivery |
| `wan_rx` | tc classifier | the WAN uplink's tcx ingress, edge role only | internet → overlay |
| `xdp_inspect` | XDP | any interface, by `flowplane inspect` | debugging only |

Every forwarding program is a tc classifier. `xdp_uplink_v6` keeps an old name from before the
datapath moved off XDP; it is a tc program reached only by tail call.

### Why tc and not XDP

The overlay is built on skb tunnel metadata. `bpf_skb_set_tunnel_key`, `bpf_skb_get_tunnel_key` and
the tunnel option helpers exist only for skb-based programs; XDP runs before an skb exists, so it has
none of them. tc programs also run after `eth_type_trans`, so they see a correct `skb->protocol` and
packet type, and they carry non-linear (jumbo) packets with no linear-buffer MTU limit. The cost is
running later in the receive path than XDP would.

### Why tail calls

The eBPF verifier gives a program 512 bytes of stack across its whole call chain. The IPv6 firewall
and conntrack structures, NAT64 and the DHCP responders do not fit on top of `tc_guest_tx` or
`uplink_rx`. A tail call replaces the running program and starts with a fresh stack, so each of those
paths is its own program reached through a program array. tc programs can only tail-call tc programs,
so the guest side (`GUEST_PROGS_TC`) and the uplink side (`UPLINK_PROGS`) each have their own array.
If a slot is empty the tail call returns and the packet is passed to the stack unchanged.

## tc_guest_tx: guest egress

`tc_guest_tx` sees everything a guest sends. It looks up the device's `PORT_META` entry (no entry:
pass), then dispatches on the ethertype:

1. ARP for the gateway: answered in place and redirected back to the guest.
2. IPv6:
    - a destination in `64:ff9b::/96` tail-calls `tc_guest_nat64`;
    - a Neighbor Solicitation for the gateway is answered in place;
    - a Router Solicitation is answered with a Router Advertisement carrying the MTU. The reply is
      larger than the request, so the program grows the skb with `bpf_skb_change_tail` first;
    - DHCPv6 (UDP 547) tail-calls `tc_guest_dhcp`;
    - anything else tail-calls `tc_guest_egress_v6`.
3. DHCPv4 (UDP 67) tail-calls `tc_guest_dhcp`.
4. IPv4 runs the egress pipeline (`forward_decision_v4` in `egress.rs`): conntrack and the
   egress firewall, the DSR reply rewrite, floating-IP rewrites, the route lookup, NAT on an external
   route, conntrack tracking and public-lane metering, then the deliver decision.

The deliver decision has three outcomes:

- Local (the destination is in `INTERFACES` on this node): run the destination's ingress firewall
  on a new flow, rewrite the inner Ethernet header and `bpf_redirect` to the destination device.
- Encapsulate: stamp a departure time for EDT pacing if the interface has an egress rate, stamp the
  tunnel key from the route, and `bpf_redirect` to `fp-geneve0`. The fabric uplink carries an `fq`
  qdisc, which honours the departure time.
- Pass: no route; the packet goes to the host stack.

[The overlay](../overlay.md#the-egress-walk) walks through the same steps with the reasons.

## tc_guest_dhcp, tc_guest_nat64, tc_guest_egress_v6

- `tc_guest_dhcp` answers DHCPv4 with a fixed-layout reply built by `flowplane_core::dhcp` (address,
  gateway, MTU, DNS, host name), growing the skb to the reply length first. It answers DHCPv6 with
  code in the eBPF crate, because the DHCPv6 reply's option block has a length only known at run time.
  On a DHCPv4 request it also learns the guest's MAC and writes it into `PORT_META` and `INTERFACES`.
- `tc_guest_nat64` translates IPv6 to IPv4 (`process_guest_tx_nat64`), shrinking the packet by 20
  bytes with `bpf_skb_adjust_room`, then routes the IPv4 packet and encapsulates it like any other.
- `tc_guest_egress_v6` is the IPv6 counterpart of the IPv4 pipeline (`process_guest_tx_v6`):
  firewall and conntrack, the DSR reply rewrite, NAT66 on an external route, route and deliver.

## uplink_dsr_note and uplink_rx: overlay ingress

Both attach to `fp-geneve0`, not to a physical NIC. The kernel decapsulates on that device's receive
path, so one attachment covers every fabric uplink a dual-homed node has. When the programs run, the
packet is already the inner frame, and the VNI comes from `bpf_skb_get_tunnel_key`.

### uplink_dsr_note

`uplink_dsr_note` runs first because the loader attaches it with `LinkOrder::first()`. If the frame
carries the DSR option, it records the load-balancer address in the `DSR` map, keyed by the reply's
5-tuple, so `tc_guest_tx` can rewrite the reply's source later.

It always returns `TC_ACT_UNSPEC`, which tcx treats as `TCX_NEXT`: run the next program. Returning
`TC_ACT_OK` would be a final verdict and skip `uplink_rx` for every packet. It is a separate program
for stack reasons: inlined into `uplink_rx` it pushes the combined stack over 512 bytes, and moved
into an out-of-line helper the verifier rejects it, because a helper that takes the packet and calls
map functions cannot keep its packet bounds across the call.

### uplink_rx

`uplink_rx` dispatches on the inner ethertype: IPv6 tail-calls `xdp_uplink_v6`, IPv4 runs
`process_uplink_rx`. The core decides the target in this order:

1. Load balancer: Maglev selects a backend for a load-balancer address. A local backend is
   delivered to; a remote one gets a new tunnel key toward its VTEP and goes straight back out through
   `fp-geneve0`.
2. NAT return: a reply to a registered NAT address has a reverse conntrack entry that restores the
   guest's address (and for NAT64, expands the IPv4 reply back to IPv6). No ingress firewall runs: it
   is the reply to a flow the guest started.
3. Local interface: `INTERFACES[(VNI, destination)]` names a local device. A new flow meets the
   interface's ingress firewall, the inner Ethernet header is rewritten, and the packet is delivered.
4. Edge local deliver: on a WAN edge, a miss on `INTERFACES` finds the edge sentinel in `UNDERLAY`
   and hands the packet to the local kernel.
5. Drop: any other miss. A decapsulated overlay packet with no local owner never reaches the
   node's own stack.

The glue then executes the result: a tunnel key and redirect to `fp-geneve0`, a `bpf_redirect`, a
`bpf_redirect_peer`, a hand-off to the stack, or a drop.

### Delivery and the destination MAC

The kernel's `eth_type_trans` marks a frame whose destination MAC is not the receiving device's own
(and not broadcast or multicast) as `PACKET_OTHERHOST`, and `ip_rcv` drops it before routing. Every
delivery path has to account for this:

- L2 guests (veth, tap, the VM's netkit L2 pair, a VF) get destination = the guest's MAC.
- L3 netkit pods get the all-zero MAC. An L3 netkit device has no ARP and filters on destination
  MAC, accepting only its own all-zero address or broadcast and multicast.
- The WAN edge's local delivery cannot fix this with a MAC rewrite alone, because the kernel marked
  the packet type when the inner frame surfaced on `fp-geneve0`, before tc ran. The glue reclassifies
  the skb as `PACKET_HOST` with `bpf_skb_change_type`, and `fp-geneve0` carries the gateway MAC so the
  rewritten destination matches it.

`bpf_redirect_peer` is used only when `uplink_rx` delivers to a container (veth or netkit L3), whose
peer is the pod's interface. See [the overlay](../overlay.md#bpf_redirect_peer) for why VMs, VFs and
the same-host path use a plain redirect.

## wan_rx: the edge's WAN side

On an edge (`serve --role edge`), `wan_rx` attaches to the WAN uplink's tcx ingress and runs
`process_wan_rx` on traffic arriving from the internet:

- Load-balancer address: Maglev selects a backend. The program rewrites the inner destination to
  the backend's own overlay address, keeps the client as the source, stamps a tunnel key toward the
  backend's VTEP, then attaches the DSR option with `bpf_skb_set_tunnel_opt` (which must come after the
  key) and redirects to `fp-geneve0`.
- NAT return: a packet to a NAT address and port is looked up in `NAT_OWNERS` (an LPM trie over
  address and port prefixes), and relayed with a tunnel key toward the owning node's VTEP, carrying the
  owner's VNI so the owner's reverse conntrack entry matches.
- Anything else is passed to the edge router's stack.

See [the WAN edge](../../features/ns-edge.md).

## xdp_inspect

`xdp_inspect` is the only XDP program. `flowplane inspect --iface <dev>` attaches it in native mode,
falling back to generic mode, and prints the first bytes of the latest packet every 500 ms from the
`INSPECT` map. It is a debugging aid and has no role in forwarding.

## Attaching and re-attaching

- `uplink_dsr_note` and `uplink_rx` are tcx links on `fp-geneve0`, `wan_rx` a tcx link on the WAN
  uplink, and `tc_guest_tx` a tcx link or a netkit link on each guest device.
- With `--pin-links` (the default) every link is pinned in bpffs. On restart the loader re-points a
  surviving link at the newly loaded program with `BPF_LINK_UPDATE`, so the hook is never empty. A
  netkit link must be re-pointed through the netkit path; the tcx re-adopt path would unpin the live
  link.
- If `fp-geneve0` had to be recreated, its ifindex changed and the old pinned links point at a device
  that no longer exists, so the loader attaches fresh instead of re-pointing.

[HA and restarts](../ha-and-restarts.md) covers adoption as a whole.

## Notes for debugging

- Maps and programs are kernel-global. Pinning is per bpffs mount, not per network namespace. Two
  flowplane instances that mount the same bpffs and use the same pin directory share one set of maps,
  whatever namespaces they run in; isolate them with separate pin directories.
- Use drop reasons. The `skb:kfree_skb` tracepoint carries the drop reason. Aggregating reason and
  location over a failing flow tells a `PACKET_OTHERHOST` drop from a netfilter drop or a header error,
  which all look the same to `tcpdump`.
- Run the verifier. `make verifier` (root) loads every program through the kernel verifier. A
  stack-budget regression only shows up there.

## Where to go next

- [Maps and state](maps.md): what each program reads and writes.
- [The pure core](pure-core.md): the shared logic behind every program here.
- [The overlay network](../overlay.md): the end-to-end packet walk.
- [The flowplane CLI](cli.md): the commands that load and attach these programs.
