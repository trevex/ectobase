# The flowplane CLI

`flowplane` is one binary. `serve` is the production daemon; the other subcommands are lab and
debugging tools. Every mode loads the eBPF bytecode embedded in the binary; they differ in what they
attach and how the maps get filled. This page documents the subcommands in
`flowplane/flowplane/src/main.rs` and `flowplane/flowplane/src/cli/`.

| Subcommand | Use | Fills the maps from |
|---|---|---|
| `serve` | production daemon, one per node and per WAN edge | `DataplaneNode` gRPC calls |
| `bringup` | legacy static lab datapath | command-line flags |
| `tc-bringup` | one guest device, for DHCP and tap tests | command-line flags |
| `load` | attach `uplink_rx` to one interface | nothing |
| `inspect` | dump packets with `xdp_inspect` | nothing |
| `infer-underlay` | print the inferred underlay `/64` | nothing |

## serve

`serve` runs the datapath for real. On start it:

1. resolves the node's VTEP;
2. creates or confirms `fp-geneve0` and attaches `uplink_dsr_note` and `uplink_rx` to it, or adopts
   the pinned maps and links of a previous run;
3. on an edge, attaches `wan_rx` to the WAN uplink and writes the local-deliver sentinel; attaches
   any extra uplinks;
4. derives the guest MTU;
5. starts conntrack aging and, with `--offload`, the offload manager;
6. on adopt, re-points or re-attaches the guest program of each recovered interface;
7. serves `DataplaneNode` and the gRPC health service.

All map state then comes from gRPC: the CNI plugin attaches interfaces, and the agent programs
routes, NAT, load balancers, firewalls and QoS. See [the dataplane overview](index.md).

| Flag | Meaning |
|---|---|
| `--addr` | Required. A `unix://` path binds a Unix socket with mode `0600` (the deployed form: `unix:///run/flowplane/dataplane.sock`); anything else is parsed as a TCP address. |
| `--uplink` | Required. The primary fabric uplink: its MAC and ifindex go into `LOCAL`, it gets the `fq` qdisc for EDT pacing, and its MTU feeds the guest MTU. `uplink_rx` does not attach here; it attaches to `fp-geneve0`. |
| `--extra-uplink` | More fabric uplinks (repeatable). They count toward the guest MTU and each gets an `fq` qdisc. `serve` still attaches `uplink_rx` to each, where it sees only encapsulated frames and passes them; decapsulation happens on `fp-geneve0`, which receives from every uplink. |
| `--role node\|edge` | `node` (default) or `edge`. An edge also attaches `wan_rx` and writes the local-deliver sentinel into `UNDERLAY`. |
| `--wan-uplink` | The WAN-facing interface `wan_rx` attaches to. Required with `--role edge`. |
| `--local-underlay` | The node's VTEP. Overrides every other source. |
| `--underlay-within` | The expected node underlay aggregate, for example `fd00:cafe::/32`. The VTEP is the host address inside it. Takes precedence over `HOST_IP`/`NODE_IP` and interface inference. |
| `--gateway-mac` | Required. The MAC set on `fp-geneve0`. The device carries inner Ethernet, so this must equal the destination MAC of frames handed to the local stack on an edge. It is not an outer Ethernet address; the kernel builds that from the fabric's neighbour table. |
| `--gateway` | Required. The overlay IPv4 gateway the datapath answers ARP for (`169.254.0.1` in the pool chart). |
| `--gateway6` | The overlay IPv6 gateway the datapath answers ND and RS for. |
| `--guest-mtu` | Override the derived guest MTU. `--dhcp-mtu` is a deprecated alias. |
| `--dhcp-dns`, `--dhcpv6-dns` | DNS servers the DHCP responders offer (repeatable). |
| `--pin-dir` | The bpffs pin directory. Default `/sys/fs/bpf/flowplane`. If it already holds pinned maps, `serve` adopts them. |
| `--pin-links` | Pin program links too, so a restart re-points them with no gap in forwarding. Default on; also `FLOWPLANE_PIN_LINKS`. Turn it off to force a fresh attach. |
| `--conntrack-max` | `CONNTRACK` capacity in entries. Also `FLOWPLANE_CONNTRACK_MAX`. |
| `--offload` | Run the SR-IOV flow-offload manager. Off by default (see [attaching workloads](../attaching-workloads.md#sr-iov-vf-offload)). |

### The VTEP

Without `--local-underlay`, `serve` resolves the VTEP in this order: the host address inside
`--underlay-within`; `HOST_IP` or `NODE_IP`, if it holds an IPv6 address; the
address on a `lo` or `dummy*` fabric loopback. It fails if none applies. The pool chart sets neither
environment variable, so deployed nodes rely on `--underlay-within` (the chart's `underlayWithin`
value) or on loopback inference.

### The guest MTU

The guest MTU is the smallest MTU across `--uplink` and `--extra-uplink`, minus 80, floored at 576.
Jumbo values are only handed out when `FLOWPLANE_SKB_MODE` is set or every uplink advertises XDP
scatter-gather; otherwise the uplink counts as 1500. The name `FLOWPLANE_SKB_MODE` is historical: it
is the jumbo gate and changes nothing about how programs attach. The lab sets it because its veth
uplinks advertise no XDP features. See [the overlay](../overlay.md#the-mtu-budget).

### Checksum offload

When the uplink has no `/sys/class/net/<uplink>/device` link, as with a veth in the lab, `serve`
turns off transmit checksum offload on guest devices at attach. A software veth never finalizes a
partial checksum, so an encapsulated guest packet would reach the wire with a wrong inner checksum. On
a real NIC offload stays on.

### Shutdown

On `SIGTERM` or `SIGINT`, `serve` stops the gRPC server and exits without unpinning anything, so the
next process adopts the datapath. See [HA and restarts](../ha-and-restarts.md).

## bringup

!!! warning "Legacy"
    `bringup` predates the move to Geneve and was only kept compiling. It does not create
    `fp-geneve0`, attaches `uplink_rx` straight to `--uplink`, and uses the old addressing model, in
    which each guest has its own underlay `/128` and an `UNDERLAY` entry. It cannot carry overlay
    traffic between nodes. Some older scripts under `test/` still call it.

`bringup` loads the datapath, fills every map from repeatable flags, and idles. It needs no gRPC and
no Kubernetes.

| Flag | Programs |
|---|---|
| `--guest <ifname>=<ipv4>=<mac>=<underlay>=<vni>` | a local guest: `PORT_META`, `INTERFACES`, `UNDERLAY`, and `tc_guest_tx` on the device |
| `--guest6 <ifname>=<ipv6>=<underlay>=<vni>` | the guest's IPv6 side |
| `--remote <ipv4>=<nexthop>=<vni>`, `--remote6` | routes in `ROUTES`, `ROUTES6` |
| `--external <ipv4>` | mark a remote route external (NAT applies) |
| `--floating-ip <guest>=<floating>` | both `FLOATING_IPS` directions |
| `--lb <ip>:<port>:<proto>:<underlay>`, `--lb-target <lb>=<backend underlay>` | a load-balancer service and its backends |
| `--nat <guest>=<nat ip>:<min>:<max>` | a local NAT source |
| `--neigh-nat <nat ip>:<min>:<max>@<owner>@<vni>` | another node's NAT block in `NAT_OWNERS`, half-open `[min, max)` |
| `--underlay-marker <ipv6>:<vni>` | a VNI-only `UNDERLAY` entry |
| `--fw-rule <ifname>:<in\|eg>:<accept\|drop>:<proto>:<src>:<dst>:<dport\|*>` | a firewall rule; each interface's rules are compiled into its classifier scopes |
| `--meter <ifname>=<total>:<public>` | egress rates in `METER` |
| `--pin-dir`, `--adopt` | pin the maps; with `--adopt`, reopen a pinned conntrack and resume aging instead of loading |

## tc-bringup

`tc-bringup` attaches `tc_guest_tx` to one device (`--tap`) and programs that device's `PORT_META`,
the DHCP settings and, optionally, `LOCAL` (`--uplink`) and routes (`--remote`, `--remote6`). It
exercises the guest edge on its own: the DHCP and ND responders and the egress decision. It does not
create `fp-geneve0`. `test/tc-dhcp-netns.sh` and `test/tc-egress-netns.sh` use it.

## load and inspect

- `load --uplink <iface>` attaches `uplink_rx` to `<iface>`'s tcx ingress and idles. `serve` never
  does this: it attaches `uplink_rx` to `fp-geneve0`.
- `inspect --iface <iface>` attaches `xdp_inspect` in native mode, falling back to generic mode, and
  prints the first bytes of the latest packet every 500 ms.

## infer-underlay

`infer-underlay` prints the `/64` of the host's underlay address, preferring a `lo` or `dummy*` fabric
loopback, and exits. It reads `ip -6 -o addr`, needs no root and touches no datapath.

## Where to go next

- [The dataplane overview](index.md): what `serve` runs and how it is called.
- [Programs and hooks](programs.md): the programs these commands attach.
- [Maps and state](maps.md): the maps the flags fill.
- [The lab](../../guides/lab.md): where `serve` runs in the test environment.
