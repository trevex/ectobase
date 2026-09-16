# Routing & multi-VNI tenancy

Every overlay forwarding decision in `flowplane` is a per-VNI route lookup. Tenants are
VNIs (VXLAN network identifiers); a VNI is a self-contained routing domain — its own
VRF. Routes never cross VNIs implicitly, so two tenants may use overlapping overlay
address space without collision. The only sanctioned way for a route to appear in another
tenant's table is an explicit [VPC peering](vpc-peering.md) import, and even then
reachability is a separate concern from firewall permission (see below).

## The route table: an LPM trie per VNI

Overlay routes live in a single BPF `LPM_TRIE` map, `ROUTES` (and its IPv6 sibling
`ROUTES6`). The VNI is folded into the key so one physical map holds every tenant's
table without them ever aliasing:

- The trie key is `RouteLpmData { vni: [u8; 4] (big-endian), ipv4: [u8; 4] }` — the VNI in
  the high 32 bits, the overlay address in the low bits.
- Because the VNI is stored big-endian and matched MSB-first, it acts as a fully specified
  32-bit VRF discriminator: the trie can only match an entry whose VNI bits agree
  completely, so a lookup in VNI A can never resolve to a route in VNI B.
- Stored routes use `prefix_len = 32 + ipv4_prefix_len` (for IPv4; `32 + ipv6_prefix_len`
  for IPv6). A `/32` host route is just a max-length entry that always wins.
- Lookups use the full key length (`64` for IPv4, `160` for IPv6). The trie returns the
  value of the longest matching prefix — standard longest-prefix-match — so a specific
  host route beats a covering supernet.

The matched value is a `RouteValue { nexthop_vni: u32, nexthop_ipv6: [u8; 16], is_external, .. }`:
`nexthop_ipv6` is the underlay address of the node (or edge) that owns the destination, and
`nexthop_vni` is the VNI to deliver under (usually the key's own VNI; see
[VPC peering](vpc-peering.md)).

> LPM tries must be created with `BPF_F_NO_PREALLOC`; the program load fails otherwise.

## Host routes and the node-VTEP nexthop

Each workload interface gets an overlay address, and its underlay address is simply its host
node's single VTEP — the one fabric address every interface on that node shares. The node
announces a host route for every overlay IP it owns:

- IPv4 overlay IP → a `/32` route.
- IPv6 overlay IP → a `/128` route.

The nexthop of that host route is the owning node's VTEP. This is the pivot of the whole
overlay: a sender stamps a Geneve tunnel key `{vni, remote = that VTEP}`, the fabric routes the
outer packet to the owning node, and that node demuxes `INTERFACES[(vni, inner dst)]` to a local
tap and guest MAC for delivery. The VNI rides the tunnel header, so the outer address only has to
identify the *node* — never the individual endpoint. (Wider routes — alias prefixes, external
defaults, imported peer prefixes — are the same shape: a prefix pointing at some node VTEP.)

## Routing in the datapath

Routing is split across the two guest-facing programs. The map-driven lookup and the
local-vs-encap decision are shared, pure-core code (`flowplane_core::egress`), so the same
logic runs in the kernel, in the simulator, and in unit tests.

```mermaid
flowchart TD
    tx["guest egress packet<br/>(tc_guest_tx)"] --> lookup["route4/route6<br/>LPM lookup in (vni, dst)"]
    lookup -->|no match| pass["Pass<br/>(no overlay route)"]
    lookup -->|RouteValue| deliver{"INTERFACES[(vni, dst)]<br/>resolves to a<br/>LOCAL interface?"}
    deliver -->|yes<br/>same host| local["Deliver::Local<br/>rewrite inner Eth,<br/>redirect to tap<br/>(ingress firewall applies)"]
    deliver -->|no| encap["Deliver::Encap<br/>stamp Geneve tunnel key toward the nexthop VTEP,<br/>redirect to the geneve device"]

    rx["inner frame on the geneve device<br/>(uplink_rx)"] --> decap["VNI from the tunnel key,<br/>rewrite inner Eth for guest"]
    decap --> redirect["redirect to local tap"]
```

- `route4` / `route6` look up `(vni, dst)` in `ROUTES` / `ROUTES6`. No match means the
  destination has no overlay route, and the wrapper returns `Pass`.
- `deliver` turns a matched route into an action. If `INTERFACES[(vni, dst)]` (or
  `INTERFACES6` for IPv6) resolves to an interface flagged local (`is_local != 0`), the
  destination is on this same host — the packet is delivered locally without ever touching
  the wire (the same-host fast path), subject to the destination's ingress firewall. This
  overlay-keyed demux is what replaced the old per-interface `UNDERLAY` self-route lookup.
  Otherwise the packet's Geneve tunnel key is stamped toward the nexthop VTEP and it is
  redirected to the `collect_md` geneve device, which builds the outer header. If there is
  no local node identity at all, the result is `Pass`.
- On the receiving node the kernel strips the outer header on the geneve device's own RX
  path, so `uplink_rx` sees the inner frame directly. It takes the VNI from the tunnel
  key, rewrites the inner Ethernet for the target guest, and redirects to its tap.

See [The overlay: Geneve over an IPv6 underlay](../concepts/overlay.md) for the exact
encap format and [Datapath programs](../architecture/dataplane/programs.md) for the full program flow.

## How routes are learned and announced: the route bus

`flowplane` never discovers routes on its own. Route distribution is the job of the
route bus — a custom, per-VNI publish/subscribe channel between the per-node agents
and the reflector on the dispatch. It is metalbond-analog pub/sub, not BGP; BGP appears only
at the [WAN edge](ns-edge.md) for announcing public prefixes upstream.

Each node agent, driven purely by the [`CompiledNIC`](../architecture/compile-sync-materialize.md)
objects scheduled to it:

1. Subscribes to the VNI of every local NIC (plus the reserved public VNI, to learn
   external defaults, and any peer VNIs it imports).
2. Announces a host route for every overlay IP its NICs own, nexthop = this node's own
   VTEP (every NIC on the node shares it).
3. Learns the routes other nodes announce for the same VNI (reflected by the
   reflector) and programs them into its own `ROUTES` / `ROUTES6` trie.

Because the nexthop is always the owning node's VTEP, a learned route is
self-describing: it tells the receiver exactly which underlay address to encapsulate
toward, and the receiving node picks the individual interface out by `(VNI, overlay IP)`.
When a NIC moves, disappears, or a new one attaches, the agent re-announces and
the reflector fans the delta out to subscribers — no central routing table, no BGP in the
hot path.

## Reachability is not permission

Learning a route only makes a destination reachable. It does not grant the
firewall permission to send to it. The [distributed firewall](firewall.md) is
deny-by-default and evaluated independently: a packet is forwarded only if a route exists
and an explicit allow rule matches. This two-step split is what lets, for example, a
peered VPC's routes be imported for reachability while traffic still requires an explicit
`FirewallPolicy` to be admitted.

## How it's wired

```
NetworkInterface (overlay IPs, VPCRef)
        │  CompiledNICReconciler resolves the VPC's VNI, copies overlay IPs
        ▼
CompiledNIC.Spec { VNI, OverlayIPs, … }   (no underlay — node-local state)
        │  agent.Desired() — for each CompiledNIC on this node,
        │  underlay from the local DataplaneNode.ListInterfaces
        ▼
route-bus announce: Route{ Vni, Prefix=/32 or /128, Nexthop=node VTEP }
        │  reflector fans out per-VNI to subscribers
        ▼
peer agents program ROUTES / ROUTES6 (LPM trie, keyed by vni++addr)
        │  DataplaneNode gRPC → BPF map write
        ▼
datapath: route4/route6 lookup → deliver (local tap via INTERFACES | encap to node VTEP)
```

- CRD → compiler. The `CompiledNICReconciler` resolves each `NetworkInterface`'s
  effective VNI (from the NIC's `status.vni`, falling back to its VPC's `status.vni`) and
  stamps `VNI` and `OverlayIPs` into a `CompiledNIC`. The spec deliberately carries no
  underlay: that is node-local state the dataplane owns at attach time.
- Compiler → agent. The agent reads only `CompiledNIC`s (never the raw
  `NetworkInterface`/`VPC`). For each local NIC it announces one host route per overlay IP
  and subscribes to that VNI, taking this node's VTEP as the nexthop from its local
  `DataplaneNode.ListInterfaces` rather than from the compiled spec.
- Agent → dataplane. Announced and learned routes are written into `ROUTES`/`ROUTES6`
  via the `DataplaneNode` gRPC. Alias prefixes (a CIDR routed to an interface) are the same
  mechanism with a shorter prefix length.

## Related

- [The overlay: Geneve over an IPv6 underlay](../concepts/overlay.md)
- [Control/data split & the route bus](../architecture/route-bus.md)
- [Distributed firewall](firewall.md)
- [VPC peering](vpc-peering.md)
- [North-South WAN edge](ns-edge.md)
