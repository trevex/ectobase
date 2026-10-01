# The in-process sim

`flowplane-sim` runs the real `flowplane-core` datapath functions over in-memory packets and maps,
with no kernel, no lab and no root. `make sim` runs it, together with the core's own unit tests,
in seconds. It is the everyday loop for datapath work and the main oracle for byte-level
behaviour. This page covers what the sim models, how a test drives one node or a whole fabric,
and how it connects to the Go compiler's output.

The sim is not a second implementation. Each `SimNode` method composes the same core functions
the eBPF program calls, in the same order and behind the same gates. Where the eBPF side has
dispatch glue of its own, such as the load-balancer branch of `uplink_rx`, the sim composes the
same glue, and an anchor checks that the bytecode agrees (see
[Testing strategy](strategy.md#the-anchors)).

## The trait implementations

`flowplane-core` is generic over `Pkt` (packet access and resizing) and `Maps` (the BPF maps). The
sim supplies both:

- `VecPkt` (`pkt.rs`) is a `Vec<u8>`-backed packet with the core's `grow_head`, `shrink_head` and
  `set_tail` semantics, so header pushes and pops behave byte for byte as they do on an skb.
- `MemMaps` (`maps.rs`) holds an in-memory mirror of every map the datapath reads: routes as LPM
  tables for v4 and v6, `CONNTRACK` and `CONNTRACK6`, the DSR maps, load balancers and the Maglev
  table, NAT and NAT ownership for both families, floating IPs, interfaces, `PORT_META`, DHCP
  configuration, meters, and the firewall classifier (`FW_BIND`, the class and policy tries per
  family, `FW_EPOCH`).

Tests seed an interface's firewall as an ordered rule list with `add_fw_rule` (or
`add_fw_rule6`). `MemMaps` compiles that list with the dataplane's own classifier compiler from
`flowplane-control`, so every scenario runs the classifier the kernel runs.

## SimNode: one node

`SimNode` (`sim.rs`) models one node: its `MemMaps`, its underlay identity (`Local`), the ingress
interface for egress calls (`src_ifindex`), a controllable clock (`now`, standing in for
`bpf_ktime_get_ns`), and the departure time the last shaped egress recorded (`last_tstamp`), so
tests can assert pacing without a kernel qdisc. Its methods map onto the eBPF entry points:

| `SimNode` method | Models |
|---|---|
| `guest_tx` | `tc_guest_tx`: IPv4 egress from a guest |
| `guest_tx_v6` | `tc_guest_egress_v6`: IPv6 egress from a guest |
| `guest_tx_nat64` | `tc_guest_nat64`: v6-to-v4 translation and encap |
| `uplink_rx` | `uplink_rx` as a whole: dispatches an established NAT return to reverse DNAT, everything else to the load-balancer and base path |
| `uplink`, `uplink_nat_return` | the two `uplink_rx` branches on their own |
| `uplink_dsr`, `uplink_v6_dsr` | `uplink_dsr_note` followed by `uplink_rx`, for a DSR-forwarded frame |
| `uplink_v6` | the IPv6 ingress path (`xdp_uplink_v6`, reached by tail call) |
| `uplink_nat64_ingress` | NAT64 reply reconstruction on ingress |
| `host_uplink`, `host_uplink_peer`, `host_uplink_v6` | seed a local guest's interface entry, then run ingress; the `_peer` variant marks a veth or netkit target, so the core chooses `bpf_redirect_peer` |
| `wan_rx` | the edge's `wan_rx`: Maglev selection for a WAN load-balancer address |
| `guest_arp_nd` | the guest-facing ARP and IPv6 ND responder |
| `guest_dhcp4` | the DHCPv4 OFFER and ACK responder |

Ingress methods take the frame after decap, as the kernel's Geneve `collect_md` device hands it to
the tcx program, and the VNI as a separate argument, standing in for the tunnel key. There is no
outer header in the bytes, because none reaches a program in production either.

Each method returns a `SimOut`: the verdict (`action`: redirect, peer redirect, drop or pass),
the resulting frame (`pkt`), the encap decision when the verdict is an overlay send (`tunnel`, a
`TunnelEncap` with VNI and remote underlay), and, from `wan_rx`, the DSR option. Tests assert on
the exact bytes and on the encap decision. The doc comment on each method says which core
functions it composes and which interleaved steps it leaves out, such as a conntrack refresh that
does not change the emitted bytes.

## Fabric: flows across nodes

`Fabric` (`fabric.rs`) holds several `SimNode`s and a table from underlay /128 to node.
`Fabric::deliver` runs a program on the ingress node and follows the result: when a hop's verdict
is an encap, it finds the node owning the `TunnelEncap` remote and runs that node's `uplink_rx`
with the encap's VNI. It stops when the frame is delivered to a guest, dropped or passed, and
returns a `Trace` of every hop with its outcome. An eight-hop limit catches forwarding loops
(`Outcome::LoopHalted`).

Hops follow the encap decision, not packet bytes, for the same reason the ingress methods take
post-decap frames: under `collect_md` there is no outer header in the frame.

```mermaid
flowchart LR
    ext["WAN or guest frame"] --> n1["ingress node<br/>wan_rx or uplink_rx"]
    n1 -->|"TunnelEncap{vni, remote}"| n2["owning node<br/>uplink_rx"]
    n2 -->|"reforward to remote backend"| n3["backend node<br/>uplink_rx"]
    n3 --> tap["delivered to guest tap"]
```

That makes multi-node scenarios cheap to run:

- north-south load balancing from the edge's `wan_rx` to a backend (`lb_scenario_test`,
  `ns_scenario_test`, `ns_scenario_v6_test`);
- east-west load balancing, including the reforward to a remote backend, and convergence without
  loops (`lb_scenario_test`, `reforward_test`);
- NAT return relayed from a non-owner to the owner of a port block (`neighbor_nat_test`,
  `nat6_test`), and ICMP errors relayed back to the right guest (`icmp_error_relay_test`,
  `nat_icmp_error_test` and their v6 siblings).

`lb_scenario_test` also pins the reason load-balanced traffic can be dropped at a backend. A
north-south connection reaches the backend with the external client as its source, so a backend
policy that admits only internal sources drops it; the backend's ingress policy has to admit the
clients on the service port. The dataplane denies by default, and load-balancer membership never
generates firewall rules.

## The CompiledNIC bridge

The sim also checks the seam between the Go compiler and the datapath. `compilednic.rs` mirrors
the `CompiledNIC` JSON the compiler produces, and `compilednic::apply()` lowers its firewall into a
node's `MemMaps`, in the agent's order: the ingress rules, then the egress rules.

```mermaid
flowchart LR
    go["Go compiler<br/>(mesh/controllers)"] --> json["flowplane-sim/testdata/<br/>compilednic.json"]
    json --> apply["compilednic::apply()"]
    apply --> maps["SimNode MemMaps"]
    maps --> core["flowplane-core"]
```

The fixture is written by the Go side. `TestCompile_WritesFixture` in
`mesh/controllers/compilednic_test.go` compiles a fixed set of objects and compares the result
with the committed `compilednic.json`; it fails when the compiler's output drifts, and
`UPDATE_FIXTURES=1` regenerates the file. The Rust side reads the same file, so a policy that
compiles to something the datapath does not enforce as intended fails in the sim without a real
interface.

## Running it

```sh
make sim          # flowplane-core and flowplane-sim tests: no root, no lab
make sim-anchor   # the verifier, then the BPF_PROG_TEST_RUN anchors (sudo)
```

## Where to go next

- [Testing strategy](strategy.md): where the sim sits among the tiers, and the one-core rule.
- [Conformance map](conformance-map.md): every behaviour of the retired dpservice suite mapped
  to its sim, anchor or live test.
- [The pure core](../../architecture/dataplane/pure-core.md): the `Pkt` and `Maps` traits.
