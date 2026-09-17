# BPF maps and state model

`flowplane` is a map-driven dataplane: the eBPF programs make no distributed
decisions, they only read (and, for connection state, write) BPF maps. All policy lives
in those maps, written by the userspace control plane. This chapter documents the real
maps declared in `flowplane-ebpf/src/maps.rs`, what each holds, and who writes it.

## Who writes what

There are three writers:

- the loader (`flowplane`) — fixes map capacities at load time and, on a graceful
  restart, re-opens the pinned maps and reseeds bookkeeping.
- the control plane (`flowplane`'s `DataplaneNode` gRPC / CLI) — writes the
  policy/config maps (interfaces, routes, firewall, NAT, LB, LB address, meter, DHCP, underlay,
  neighbor-NAT) in response to control-plane calls.
- the datapath itself — writes only the connection-state maps: `CONNTRACK` (flow
  entries) and `METER` (token-bucket state).

Most policy maps are pinned to bpffs (default `/sys/fs/bpf/flowplane`) so they — and
the flow state in them — survive a control-plane restart. See
[HA & graceful restart](../ha-graceful-restart.md).

## Policy and config maps: control-plane written

| Map | Type | Key → Value | Holds |
|---|---|---|---|
| `INTERFACES` | HashMap (1024) | `IfaceKey` → `IfaceValue` | per-interface overlay identity (VNI + IPs → tap ifindex, underlay endpoint). |
| `IFACE_META` | HashMap (1024) | `IfaceMetaKey` → `IfaceMetaVal` | restart journal — `interface_id → (vni, v4/v6, device, underlay, tap)`. Written on attach, removed on detach, scanned on restart to rebuild in-memory bookkeeping and re-attach guest programs. Never read by the datapath. |
| `ROUTES` | LPM trie (65536) | `(VNI ++ IPv4, prefix)` → `RouteValue` | per-VNI IPv4 overlay routes → next-hop underlay `/128`. Queried at prefix_len 64 (32 VNI + 32 host). |
| `ROUTES6` | LPM trie (65536) | `(VNI ++ IPv6, prefix)` → `RouteValue` | per-VNI IPv6 overlay routes. Queried at prefix_len 160 (32 VNI + 128 host). |
| `UNDERLAY` | HashMap (4096) | underlay `/128` → `UnderlayValue` | residual node-identity markers — **not** the local-delivery path (that is `INTERFACES`/`INTERFACES6`, keyed on `(VNI, overlay IP)`). Under `collect_md` the datapath never sees an outer dst, and a plain interface writes nothing here (the node VTEP is shared, so writing it would clobber the edge sentinel). `serve` has two writers left: `Control::attach_edge` (the local-deliver sentinel, keyed under the edge's own `LOCAL.underlay_ipv6`) and `create_lb` for an overlay-relay LB address (`vni != 0` only); the only reader is the edge-sentinel check in `uplink_rx`. `tap_ifindex = UNDERLAY_LOCAL_DELIVER` marks a WAN-edge local-deliver underlay; `tap_ifindex = 0` marks a VNI-only entry (e.g. a NAT-gateway node with no local interface). |
| `CONFIG` | Array (1) | `[0]` → `Config` | server-wide datapath config. |
| `LOCAL` | Array (1) | `[0]` → `Local` | this host's identity: `uplink_ifindex` (the redirect target for every uplink-bound verdict), `uplink_mac` (the inner-Ethernet dst the WAN-edge local-deliver rewrites to), and `underlay_ipv6` — this node's VTEP, used for the LB local-vs-remote test (`backend.node_vtep == local.underlay_ipv6`) and to key the edge local-deliver sentinel lookup. `gateway_mac` is now the geneve device's own link address, not an outer-Ethernet dst — the kernel builds outer frames, so the datapath no longer reads the field. |
| `PORT_META` | HashMap (1024) | ifindex → `PortMeta` | per-interface datapath metadata (overlay gateway v4/v6, guest v6, underlay identity). |
| `FLOATING_IPS` | HashMap (1024) | `FloatingIPKey` → `[u8;4]` | 1:1 LB address mapping. `(vni,G)→V` for egress SNAT, `(vni,V)→G` for ingress DNAT. |
| `NAT` | HashMap (1024) | `NatKey` → `NatValue` | network-NAT config per `(vni, guest-ipv4)`: `nat_ip` + port range. |
| `NAT_IPS` | HashMap (1024) | `FloatingIPKey` → `u8` | marks a `(vni, nat_ip)` as a NAT IP so ingress can answer ICMP echo to it in-datapath. |
| `LB` | HashMap (1024) | `LbKey` → `LbValue` | load-balancer service definition (LB address+port+proto → Maglev table handle). |
| `MAGLEV` | HashMap (65536) | `MaglevKey` → `LbBackend` | Maglev lookup table: hashed slot → the selected backend (underlay VTEP /128 + overlay IP + VNI + family). |
| `FW_RULES` | HashMap (16384) | `FwRuleKey` → `FwRule` | firewall rule slots, keyed `(ifindex, slot)`. |
| `FW_META` | HashMap (1024) | ifindex → `FwMeta` | per-interface firewall rule counts per direction (ingress/egress). Absence ⇒ deny (deny-by-default). |
| `NEIGHBOR_NAT` | HashMap (64) | slot → `NeighborNatEntry` | distributed NAT-gateway return: `nat_ip:port-range@owner-underlay@vni`, so return traffic is reforwarded to the owning node. |
| `NEIGHBOR_NAT_COUNT` | Array (1) | `[0]` → `u32` | number of populated `NEIGHBOR_NAT` slots (the datapath scans `0..count`). |
| `DHCP_CONFIG` | Array (1) | `[0]` → `DhcpConfig` | server-wide DHCP: MTU + DNS server lists (v4/v6). |
| `DHCP_META` | HashMap (1024) | ifindex → `DhcpMeta` | per-interface DHCP: hostname + PXE. |

## Connection-state maps: datapath written

| Map | Type | Key → Value | Holds |
|---|---|---|---|
| `CONNTRACK` | LRU HashMap (1,048,576) | `CtKey` → `CtEntry` | the unified stateful conntrack table (NAT/NAT64/firewall flows). LRU pre-allocated (~80–100 MB, memcg-accounted); sized to dpservice's `DP_FLOW_TABLE_MAX` order. Capacity is fixed at load time and overridable via `--conntrack-max` / `FLOWPLANE_CONNTRACK_MAX`. |
| `METER` | HashMap (1024) | ifindex → `MeterState` | per-interface egress srTCM token-bucket state. Read and refilled by the datapath meter; the cap is programmed by the control plane. |

## Redirect / devmap helpers: loader written

XDP `bpf_redirect` into a veth only delivers if the veth peer has an XDP program
attached — a constraint that bites in the containerlab veth harness (but not on real
NICs). These devmaps route redirects through `bpf_redirect_map` instead, which does not
carry the peer-program requirement:

| Map | Type | Purpose |
|---|---|---|
| `UPLINK_DEV` | DevMap (1) | single-slot fabric uplink ifindex, used by the edge `wan_rx` → fabric encap redirect. |
| `GUEST_DEV` | DevMapHash (1024) | per-guest-tap ifindex → itself, used by `uplink_rx`'s guest-delivery redirect. |
| `GUEST_PROGS_TC` | ProgramArray (8) | tc tail-call targets for the guest-edge split. Slot `GUEST_PROG_DHCP` holds `tc_guest_dhcp`; other slots hold `tc_guest_nat64`. tc classifiers can only tail-call other tc programs, hence a dedicated array. |

## Debug maps

| Map | Type | Purpose |
|---|---|---|
| `INSPECT` | Array (1) | first-packet capture written by `xdp_inspect`. |

## Relationship to the pure-core `Maps` trait

The datapath never touches these globals directly — it reads them through the
[`Maps` trait](pure-core.md), whose production impl (`GlobalMaps`) is a set of zero-cost
wrappers over exactly these statics (`route4_get` → `ROUTES`, `fw_rule` → `FW_RULES`,
`conntrack_get`/`_insert` → `CONNTRACK`, and so on). The simulator's `MemMaps` backs the
same trait with `HashMap`s, which is why the same core logic runs in both. The
`#[repr(C)]` key/value structs (`RouteValue`, `CtEntry`, `FwRule`, `NatValue`, …) live in
`flowplane-common` with layout tests, shared byte-for-byte between eBPF and userspace.

## Where to go next

- [The pure-core seam](pure-core.md) — how the datapath reads these maps abstractly.
- [Datapath programs](programs.md) — which program touches which map.
- [Distributed firewall](../../features/firewall.md), [NAT gateway](../../features/nat.md),
  [Load balancing](../../features/loadbalancer.md) — the features these maps encode.
