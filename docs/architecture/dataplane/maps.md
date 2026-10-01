# Maps and state

flowplane keeps all of its forwarding state in BPF maps. The eBPF programs read policy and
configuration from them and write only connection state; userspace writes everything else. This page
lists every map declared in `flowplane/flowplane-ebpf/src/maps.rs`: its type and capacity, its key
and value, and who writes it. The key and value types are `#[repr(C)]` structs in `flowplane-common`,
shared byte for byte by the eBPF programs and userspace, with layout tests.

## Who writes what

| Writer | What it writes |
|---|---|
| The control core (`flowplane-control`, through the daemon's aya map writer) | All policy and configuration: interfaces, routes, firewall, NAT, load balancers, meters' rates, DHCP settings. Driven by `DataplaneNode` gRPC calls. |
| The loader (`flowplane`) | Node identity (`LOCAL`), the Geneve device's ifindex, the tail-call program arrays. |
| The eBPF programs | Connection state: `CONNTRACK`, `CONNTRACK6`, `NAT_CT6`, `DSR`, `DSR6`, meter state in `METER`, and the guest MAC learned from DHCPv4 (into `PORT_META`, `INTERFACES` and `INTERFACES6`). |
| The userspace sweepers | Conntrack aging (every 10 s), and the offload manager when enabled. |

Almost every map is pinned under the pin directory (`/sys/fs/bpf/flowplane` by default), so the maps
and the flows in them survive a restart of the daemon. See [HA and restarts](../ha-and-restarts.md).

## Interfaces and node identity

| Map | Type (capacity) | Key → value | Holds |
|---|---|---|---|
| `INTERFACES` | hash (1024) | `(VNI, IPv4)` → `IfaceValue` | The local-delivery table. Value: device ifindex, `is_local`, the node VTEP, guest MAC, and `peer_capable` (may use `bpf_redirect_peer`). |
| `INTERFACES6` | hash (1024) | `(VNI, IPv6)` → `IfaceValue` | The IPv6 counterpart. |
| `PORT_META` | hash (1024) | device ifindex → `PortMeta` | Per-device data `tc_guest_tx` needs: VNI, guest IPv4 and IPv6, gateways, guest MAC, VTEP, the `l3` flag (netkit L3 edge) and the `offloaded` flag (SR-IOV representor). |
| `IFACE_META` | hash (1024) | interface id → `IfaceMetaVal` | The restart journal: VNI, addresses, device, VTEP and `l3` flag of every attached interface. Written on attach, removed on detach, read on restart. The datapath never reads it. |
| `LOCAL` | array (1) | 0 → `Local` | This node: the primary uplink's ifindex and MAC, and the VTEP. `gateway_mac` is no longer read by the datapath. |
| `GENEVE_IFINDEX` | array (1) | 0 → ifindex | The `fp-geneve0` device every encapsulating redirect targets. |
| `UNDERLAY` | hash (4096) | underlay `/128` → `UnderlayValue` | Not the delivery table (that is `INTERFACES`). Two writers remain: the WAN edge's local-deliver sentinel, keyed by the edge's own VTEP with `tap_ifindex = u32::MAX`, and an overlay-relay load balancer (`vni != 0`). `uplink_rx` reads it only to check for the edge sentinel. |

## Routing

| Map | Type (capacity) | Key → value | Holds |
|---|---|---|---|
| `ROUTES` | LPM trie (65536) | `VNI ++ IPv4`, prefix length 32 + route length → `RouteValue` | Per-VNI IPv4 routes. Looked up with prefix length 64 (the whole VNI and address), so the longest matching route in the VNI wins. |
| `ROUTES6` | LPM trie (65536) | `VNI ++ IPv6`, prefix length 32 + route length → `RouteValue` | Per-VNI IPv6 routes, looked up with prefix length 160. |

`RouteValue` is the nexthop VTEP (`nexthop_ipv6`), the VNI to deliver under (`nexthop_vni`, see
[the delivery VNI](../overlay.md#the-sender-stamps-the-delivery-vni)), and `is_external`, which marks
a route whose traffic is NAT-translated. Every local interface has a self-route here pointing at the
node's own VTEP. The control core keeps a shadow of each trie so a self-route can hold its key while a
mesh route waits behind it (see [held keys](../route-bus.md#local-host-keys-and-held-keys)).

## Firewall

The firewall is a two-stage classifier per scope, where a scope is one interface's rules in one
direction. See [the firewall](../../features/firewall.md).

| Map | Type (capacity) | Key → value | Holds |
|---|---|---|---|
| `FW_BIND` | hash (1024) | device ifindex → `FwBind` | The interface's ingress and egress scope ids. A missing entry or scope 0 denies at the datapath; where a VPC's policy leaves a direction open, the compiler writes an explicit allow-all rule instead. Rebinding is one write. |
| `FW_CLASS`, `FW_CLASS6` | hash of maps (4096 scopes) | scope id → LPM trie (up to 4096 entries) | Stage 1: the peer address prefix → a class local to the scope. |
| `FW_POLICY`, `FW_POLICY6` | hash of maps (4096 scopes) | scope id → LPM trie (up to 16384 entries) | Stage 2: `[class, protocol, port]` → a precedence. |
| `FW_EPOCH` | array (1) | 0 → `u32` | The node's firewall epoch, bumped after every `FW_BIND` change. A conntrack entry records the epoch it was checked under, so an established flow meets a changed policy again. |

The four map-of-maps are BTF-defined, which aya cannot mark as pinned, so the loader pins them by
name.

## Connection state

| Map | Type (capacity) | Key → value | Holds |
|---|---|---|---|
| `CONNTRACK` | LRU hash (1,048,576) | `CtKey` (VNI, 5-tuple) → `CtEntry` | IPv4 flows: last seen, NAT translation, flags, TCP state, firewall epoch. Pre-allocated; `--conntrack-max` or `FLOWPLANE_CONNTRACK_MAX` changes the size at load. |
| `CONNTRACK6` | LRU hash (1,048,576) | `CtKey6` → `CtEntry` | IPv6 flows for the firewall. |
| `NAT_CT6` | LRU hash (1,048,576) | `CtKey6` → `CtEntry6` | NAT66 flows, which need an IPv6 translation address. |
| `DSR`, `DSR6` | LRU hash (65536) | reply 5-tuple → `DsrLbIP` | The load-balancer address noted by `uplink_dsr_note`, used to rewrite the reply's source. A separate map because adding it to `CtEntry` pushed `uplink_rx` over its stack budget. |
| `METER` | hash (1024) | device ifindex → `MeterState` | Three QoS lanes: egress total (EDT pacing cursor), egress public and ingress (token buckets). The control core sets the rates; the datapath updates the state. |

Userspace ages `CONNTRACK` entries: 30 s idle for most flows, 24 hours for established TCP. The other
LRU maps evict under pressure.

## NAT and floating IPs

| Map | Type (capacity) | Key → value | Holds |
|---|---|---|---|
| `NAT` | hash (1024) | `(VNI, guest IPv4)` → `NatValue` | A local source's NAT address and port block. |
| `NAT6` | hash (1024) | `(VNI, guest IPv6)` → `NatValue6` | The NAT66 counterpart. |
| `NAT_IPS`, `NAT_IPS6` | hash (1024) | `(VNI, NAT address)` → 1 | Marks an address as a NAT address, so ingress looks up the return entry. |
| `NAT_OWNERS`, `NAT_OWNERS6` | LPM trie (65536) | `NAT address ++ port` prefix → `NatOwner` | Blocks owned by other nodes, stored as port prefixes; the value is the owner's VTEP, VNI and block. Read by `wan_rx` to relay returns. |
| `FLOATING_IPS` | hash (1024) | `(VNI, address)` → IPv4 | 1:1 floating IPs, both directions: guest → floating for egress, floating → guest for ingress. |

See [NAT](../../features/nat.md).

## Load balancing

| Map | Type (capacity) | Key → value | Holds |
|---|---|---|---|
| `LB`, `LB6` | hash (1024) | `(VNI, address, port, protocol)` → `LbValue` | A load-balancer service and its Maglev table id and size. VNI 0 is the WAN edge's service space. |
| `MAGLEV` | hash (65536) | `(table id, slot)` → `LbBackend` | The Maglev lookup tables of both families: each slot names a backend's VTEP, overlay address and VNI. |

See [load balancing](../../features/loadbalancer.md).

## DHCP

| Map | Type (capacity) | Key → value | Holds |
|---|---|---|---|
| `DHCP_CONFIG` | array (1) | 0 → `DhcpConfig` | The node's guest MTU and DNS servers (IPv4 and IPv6). |
| `DHCP_META` | hash (1024) | device ifindex → `DhcpMeta` | Per-interface host name and PXE boot settings. |

## Program arrays and debugging

| Map | Type (capacity) | Holds |
|---|---|---|
| `GUEST_PROGS_TC` | program array (8) | Guest-side tail calls: slot 0 `tc_guest_dhcp`, slot 2 `tc_guest_nat64`, slot 3 `tc_guest_egress_v6`. Slot 1 is reserved. |
| `UPLINK_PROGS` | program array (4) | Uplink-side tail calls: slot 0 `xdp_uplink_v6`. |
| `INSPECT` | array (1) | The packet capture `xdp_inspect` writes. Not pinned. |
| `CONFIG` | array (1) | Declared and pinned but read and written by nothing; left over from an early single-peer prototype. |

There are no device maps (`DEVMAP`): every delivery is a `bpf_redirect` or `bpf_redirect_peer` on the
skb.

## Sizing

The capacities above are compile-time defaults. The loader overrides a few at load time from
environment variables: `FLOWPLANE_CONNTRACK_MAX` (also `--conntrack-max`), `FLOWPLANE_ROUTES_MAX`,
`FLOWPLANE_INTERFACES_MAX`, `FLOWPLANE_MAGLEV_MAX`, `FLOWPLANE_NAT_MAX`, `FLOWPLANE_LB_MAX` and
`FLOWPLANE_PORT_META_MAX` (`flowplane/flowplane/src/loader.rs`).

## Access through the Maps trait

The core logic never names these maps. It calls the [`Maps` trait](pure-core.md), whose kernel
implementation (`GlobalMaps` in `coreimpl.rs`) is a set of thin wrappers over exactly these maps
(`route4_get` → `ROUTES`, `fw_bind` → `FW_BIND`, `conntrack_insert` → `CONNTRACK`, and so on). The
simulator implements the same trait with `HashMap`s.

## Where to go next

- [Programs and hooks](programs.md): which program reads and writes which map.
- [The pure core](pure-core.md): the `Maps` trait over these maps.
- [The route bus](../route-bus.md): where `ROUTES` entries come from.
- [HA and restarts](../ha-and-restarts.md): how pinned maps are adopted after a restart.
