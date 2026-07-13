# Overlay Route Distribution for the eBPF (aya/Rust) SDN Dataplane

Research spike — 2026-07-02
Author: node-agent / dataplane team

## TL;DR / Recommendation

Build a **custom metalbond-style route-distribution protocol in Rust**, co-located
with the aya dataplane, and program the eBPF `ROUTES`/`ROUTES6`/`UNDERLAY` maps
directly from it. Do **not** put BGP EVPN on the critical path for v1. Keep the
door open to EVPN as a **northbound/interop** control plane (peering with the FRR
ToRs or a future DPU eswitch) via an **embedded gobgp-in-Go sidecar/route-server**,
because EVPN-for-a-non-VXLAN-encap is *feasible but a bend* and not worth blocking
v1 on.

- **Custom vs EVPN:** custom (metalbond-style) protocol for the intra-fleet fast
  path; EVPN only at the fabric edge / for hardware offload interop.
- **BGP impl (when we need BGP):** **gobgp embedded as a Go library** (the Cilium
  pattern). Rust BGP options are not ready for EVPN.
- **Language:** **Rust** for the node agent (same binary/process family as the aya
  dataplane, direct map access). Go only if/where we embed gobgp for EVPN interop.

**EVPN-for-non-VXLAN verdict: FEASIBLE BUT A BEND (control-plane-only).** You can
announce `(VNI, prefix, nexthop=node-underlay-IPv6)` as EVPN Type-5 and learn it
elsewhere, treating EVPN purely as the control plane while doing your own
IP-in-IPv6 encap in eBPF. The encap signalling has a clean hook — IANA BGP Tunnel
Encapsulation **tunnel type 7 = "IP in IP"** is registered and non-deprecated
([IANA registry](https://www.iana.org/assignments/bgp-tunnel-encapsulation/bgp-tunnel-encapsulation.xhtml),
[RFC 9012](https://www.rfc-editor.org/rfc/rfc9012.html)) — but no shipping stack
maps "Type-5 + tunnel-type-7" onto a bespoke IP-in-IPv6 datapath for you. You would
be using EVPN as a *transport for (prefix, nexthop, VNI) tuples* and ignoring its
VXLAN datapath semantics. That works, but it inherits BGP's operational weight for
a job a 300-line custom protocol already does. **Needs an implementation spike to
confirm gobgp's Type-5 `gw`/nexthop/encap fields round-trip our tuple cleanly.**

---

## 1. metalbond analysis

metalbond (github.com/ironcore-dev/metalbond, Go, ~86% Go) is the route reflector
used by ironcore's metalnet/dpservice stack. It is deliberately **not** BGP — it's
a minimal pub/sub route bus purpose-built for VNI-scoped overlays.

### Wire protocol (confirmed from `docs/metalbond_protocol.md` + `pb/metalbond.proto`)

- **Transport:** TCP over IPv6, default port **4711**. Framing is a 4-byte header
  (`Version=1` | 2-byte big-endian length | 1-byte msg type) followed by a
  protobuf payload capped at **1188 bytes** (whole message ≤1220 to avoid IPv6
  fragmentation at 1280 MTU).
- **Message types:** `1 HELLO`, `2 KEEPALIVE`, `3 SUBSCRIBE`, `4 UNSUBSCRIBE`,
  `5 UPDATE`.
- **`Hello { uint32 keepaliveInterval; bool isServer }`** — keepalive interval is
  negotiated in the hello; `isServer` distinguishes reflector from client.
- **`Subscription { uint32 vni }`** — a client subscribes per-VNI; it only receives
  routes for VNIs it subscribed to. This is the core scaling lever (a node pulls
  only the overlays whose endpoints it hosts).
- **`Update { Action action; uint32 vni; Destination destination; NextHop nextHop }`**
  where `Action ∈ {ADD, REMOVE}` (explicit withdraw), and:
  - **`Destination { IPVersion ipVersion; bytes prefix; uint32 prefixLength }`**
  - **`NextHop { bytes targetAddress; uint32 targetVNI; NextHopType type;
    uint32 natPortRangeFrom; uint32 natPortRangeTo }`**, with
    `NextHopType ∈ {STANDARD, NAT, LOADBALANCER_TARGET}`.

### Nexthop / encap model

The nexthop is `targetAddress` = the **remote node's underlay IPv6** (the tunnel
endpoint), plus an optional `targetVNI` for VNI-to-VNI stitching, plus a type tag
for NAT / LB-target semantics. **There is no encapsulation-type field** — the encap
is *implicitly* IP-in-IPv6. The reference client literally sets up an `ip6tnl`
(kernel IP-in-IPv6 tunnel) and writes routes into per-VNI kernel route tables
(`--install-routes 23#100 --tun overlay-tun`, announce format
`vni#prefix#nexthop`). This is a **1:1 match for our eBPF map model**
(`(vni, prefix) -> nexthop_underlay_ipv6` + `underlay -> {tap, mac, is_local}`) —
metalbond's data model is essentially our maps expressed on the wire.

### Architecture

Server ("reflector") accepts client connections, holds the route table, and
reflects each client's announcements to the other subscribers of that VNI. Clients
(node agents) both **announce** local routes and **subscribe** to VNIs. Redundancy
is achieved by clients dialling **multiple servers** — the servers do not gossip
among themselves in-protocol; each client connection is an independent full session.

### KNOWN LIMITATIONS / what a "done properly" version improves

- **Reflector HA is client-side and dumb.** Redundancy = "connect to N servers";
  there is no reflector-to-reflector state sync, no election, no anti-entropy. Two
  reflectors can diverge; the client is responsible for merging. *Improve:* a proper
  HA reflector cluster (raft/gossip or shared store) or make reflectors stateless
  over a durable log.
- **No graceful-restart / end-of-RIB semantics.** BGP has End-of-RIB markers and
  graceful-restart (stale-route retention). metalbond has none — on reconnect a
  client re-subscribes and the server re-sends; there's no explicit "table
  complete" marker and no defined stale-route hold, so a reflector restart risks a
  churn/blackhole window. *Improve:* add an EoR marker + stale-preserve-on-restart.
- **No ECMP / multipath.** `Update` carries a single `NextHop` per `(vni,dest)`.
  Multiple equal-cost remote nexthops for one prefix aren't modelled. *Improve:*
  allow a nexthop **set** per destination and program ECMP into the datapath.
- **Liveness is coarse.** Keepalive over a single TCP session; failure detection is
  bounded by the keepalive interval (seconds), no BFD-grade sub-second detection.
  For a latency-sensitive fabric this is the weakest link. *Improve:* faster
  keepalives / integrate with underlay BFD / decouple liveness from the route bus.
- **MTU-bound messages (≤1188B protobuf).** Fine for single routes, awkward for bulk
  resync. *Improve:* chunked/streamed full-table transfer.
- **No route attributes / policy.** No communities, no metric, no tie-break beyond
  "last writer". *Improve:* minimal attribute set (metric, origin-node, generation)
  for deterministic selection and loop/staleness detection.

A "done properly" v2 keeps metalbond's **subscribe-by-VNI + explicit ADD/REMOVE +
underlay-IPv6 nexthop** core (it's the right model) and adds: HA reflector, EoR +
graceful restart, nexthop-set ECMP, faster/decoupled liveness, and a small
attribute set.

---

## 2. BGP EVPN for a non-VXLAN dataplane — the crux

### Route type semantics

- **Type-2 (MAC/IP Advertisement):** advertises a `(MAC, optional IP)` bound to a
  VTEP for a given VNI/EVI — host-granular L2/L3 reachability. Carries a BGP
  Encapsulation Extended Community (RFC 9012) naming the tunnel type
  ([Arista route-type overview](https://arista.my.site.com/AristaCommunity/s/article/Common-EVPN-Route-Types)).
- **Type-5 (IP Prefix, RFC 9136):** advertises an **IP prefix** for a VRF/VNI for
  inter-subnet/L3 forwarding, decoupled from any MAC — a "pure Type-5" carries a
  Router-MAC ext-community and a gateway/nexthop so remote nodes can resolve the
  overlay nexthop without a companion Type-2
  ([RFC 9136](https://datatracker.ietf.org/doc/html/rfc9136)). **This is the natural
  fit for us**: our endpoints are `(vni, prefix, nexthop=node-underlay-IPv6)` — i.e.
  L3 host routes/prefixes, exactly Type-5's shape.

### The nexthop / encapsulation model

In standard EVPN-VXLAN, the **BGP nexthop = the VTEP underlay IP**, and the
**Encapsulation Extended Community (RFC 9012, tunnel type 8 = VXLAN)** tells the
receiver "encap to that VTEP as VXLAN with this VNI." The datapath then does VXLAN.
The key realisation: RFC 9012 is a *generic* tunnel-encapsulation signalling
framework; VXLAN is just tunnel type 8. The IANA registry also defines
**tunnel type 7 = "IP in IP"** (registered, **not** deprecated;
[IANA BGP Tunnel Encapsulation registry](https://www.iana.org/assignments/bgp-tunnel-encapsulation/bgp-tunnel-encapsulation.xhtml)).
So there IS a standards-sanctioned code point to say "IP-in-IP, not VXLAN."

### Can we use EVPN purely to DISTRIBUTE routes while doing our OWN IP-in-IPv6 encap?

**Yes, mechanically.** The plan:

1. Node announces each local endpoint as an **EVPN Type-5** route:
   `RD` = per-node, `RT`/`etag`/VNI = overlay VNI, `prefix` = endpoint,
   **BGP nexthop = this node's underlay IPv6** (the tunnel source/dest), optionally
   `encap` = IP-in-IP (type 7).
2. Other nodes' agents **learn** these routes over BGP and program the eBPF maps:
   `ROUTES[(vni,prefix)] = nexthop_underlay_ipv6` and
   `UNDERLAY[nexthop] = {tap?, mac, is_local=false}`.
3. eBPF does its own IP-in-IPv6 encap to the nexthop — **EVPN is control plane
   only; its VXLAN datapath is never invoked.**

**This is a bend, not the paved road.** Precedent for "BGP/EVPN as control plane,
custom datapath below" is strong in spirit — **Cilium embeds gobgp and drives its
own eBPF datapath, with BGP purely advertising reachability, not doing the
forwarding** ([Cilium BGP control plane docs](https://docs.cilium.io/en/stable/network/bgp-control-plane/bgp-control-plane/),
[pkg/bgpv1/gobgp](https://fossies.org/linux/cilium/pkg/bgpv1/gobgp/server.go)).
EVPN-with-IPv6-underlay and Type-5-with-IPv6-nexthop are also well-trodden in
vendor land ([Juniper EVPN-VXLAN IPv6 underlay](https://www.juniper.net/documentation/us/en/software/junos/evpn/topics/topic-map/vxlan-ipv6-underlay-overview.html)).
What is **not** off-the-shelf is a stack that consumes "Type-5 + tunnel-type-7" and
programs a bespoke IP-in-IPv6 eBPF datapath — **we would write that mapping
ourselves** in the agent. At that point EVPN buys us wire-format standardisation and
ToR/DPU interop, at the cost of dragging in RD/RT/route-target plumbing and a full
BGP stack to move tuples our custom protocol already moves.

**Flag for implementation spike:** confirm gobgp's Type-5 `add prefix … gw <gw>
etag <etag> label <label> rd <rd> rt <rt> [encap <type>]` cleanly carries
`nexthop=underlay-IPv6` + our VNI, and that the receiving side surfaces all of
`(prefix, nexthop, VNI, encap)` via the watch API. gobgp's documented `encap`
examples are VXLAN; whether it accepts/round-trips tunnel-type-7 "IP in IP" (or
whether we ride the BGP nexthop + RT/etag and ignore encap-community) is unproven
and must be validated ([gobgp EVPN docs](https://github.com/osrg/gobgp/blob/master/docs/sources/evpn.md)).

---

## 3. BGP implementations to embed/drive

| Impl | Lang | EVPN Type-5 | Programmatic inject/learn | Embeddable | Maturity | Verdict |
|---|---|---|---|---|---|---|
| **gobgp** | Go | **Yes** (`-a evpn add prefix … rd/rt/etag/label/gw/encap`) | **Yes** — gRPC `AddPath` + `WatchEvent`; also usable as a **Go library** (`server.NewBgpServer`, `AddPath`, `WatchEvent`) | **Yes, as Go lib** (Cilium ships it embedded) | Mature, widely deployed | **Best BGP option** if/when we need EVPN |
| **RustyBGP** | Rust | **No EVPN** (basic eBGP/iBGP, RPKI, BMP, MRT only); mirrors gobgp gRPC | gRPC (gobgp-compatible) | Daemon | Experimental/perf-focused | Not viable for EVPN |
| **holo** | Rust | **No EVPN** (BGP-4 ~60% YANG coverage; no L2VPN EVPN AF) | gRPC/gNMI/YANG | Daemon-only, not lib | Young, growing | Not viable for EVPN today |
| **FRR** | C | **Yes**, most mature EVPN | Learn via zebra **FPM/dplane-fpm** or BGP-peer with it | Separate daemon | Very mature | Heavy; good as the *fabric* stack, not embedded in the agent |

Notes:
- **gobgp** ([repo](https://github.com/osrg/gobgp),
  [EVPN docs](https://github.com/osrg/gobgp/blob/master/docs/sources/evpn.md),
  [lib docs](https://github.com/osrg/gobgp/blob/master/docs/sources/lib.md)):
  multiprotocol incl. EVPN; `AddPath`/`WatchEvent` gRPC API; embeds as a Go library.
  The Cilium precedent (embedded gobgp, own eBPF datapath) is exactly our shape.
- **RustyBGP** ([repo](https://github.com/osrg/rustybgp)): explicitly "very basic BGP
  features … eBGP/iBGP, RPKI, BMP, MRT"; gobgp-compatible gRPC; **no EVPN**. Fast and
  multicore, but a non-starter for EVPN Type-5.
- **holo** ([repo](https://github.com/holo-routing/holo)): Rust, BGP-4 present but
  ~60% YANG coverage and **no EVPN address family**; daemon-oriented (YANG/gNMI/gRPC
  mgmt), not designed as an embeddable lib. Promising long-term, not for this.
- **FRR:** to consume its EVPN in a local agent you'd either peer BGP with it or tap
  the **FPM/dplane-fpm** route stream from zebra; either way it's a second heavyweight
  daemon per node. Right tool for the **ToR fabric** (we already run it there), wrong
  tool to embed in the dataplane agent.

**No maintained Rust BGP stack supports EVPN Type-5 + a programmatic API today.**
That is the decisive constraint: choosing EVPN forces Go (gobgp) or C (FRR) into the
agent, breaking the "one Rust process family" property.

---

## 4. Integration fit

Requirements: (a) announce local endpoints with `nexthop = this node's underlay
IPv6`; (b) learn remote routes and program eBPF `ROUTES`/`UNDERLAY` **fast**.

- **Custom (metalbond-style) in Rust:** the agent *is* the dataplane's control side.
  Learn a route → write the map. No RD/RT translation, no BGP RIB, no second daemon,
  no cross-language boundary. Lowest latency, smallest surface. Data model already
  matches our maps 1:1. **Cleanest, lowest-latency path.**
- **EVPN via gobgp (embedded Go):** agent runs an embedded gobgp, `WatchEvent`s
  EVPN Type-5, translates `(prefix, BGP-nexthop, VNI/etag)` → eBPF maps. Adds a
  Go↔Rust boundary (separate process + IPC, or cgo) and BGP-RIB/bestpath latency,
  plus RD/RT plumbing. **More moving parts; interop payoff.**
- **EVPN via FRR:** heaviest; a second daemon + FPM tap or BGP peering. Only makes
  sense if we want the node to be a "real" EVPN speaker to the ToR.

**Fabric alignment / future DPU:** we already run **FRR eBGP-unnumbered IPv6 ToRs**;
nodes announce a loopback /64. Two futures argue for *keeping EVPN reachable*:
1. **Nodes could peer EVPN with the ToR** so overlay reachability rides the same
   fabric we already operate (one control plane instead of two).
2. **A future DPU/hardware eswitch speaks EVPN natively** — offload will expect EVPN,
   not our bespoke bus.

But neither requires EVPN *on the intra-fleet fast path now*. The clean architecture:

```
[node agent, Rust]
  ├─ custom route bus (metalbond-style, Rust)  →  fast path: program eBPF maps
  └─ (later) EVPN gateway (embedded gobgp, Go) →  interop: peer ToR / DPU, re-export
                                                    the same routes as Type-5
```

The custom bus is authoritative for intra-fleet; an **EVPN gateway** component
(a handful of route-servers running embedded gobgp, not every node) bridges our
route table to/from EVPN for fabric and hardware interop. This defers the BGP/EVPN
bend to where it pays off (edge/offload) and keeps the hot path pure Rust.

---

## 5. Language recommendation

- **Node agent (co-located with aya dataplane): Rust.** Direct, in-process access to
  the eBPF maps via aya; no FFI/IPC on the hot path; one toolchain, one memory model,
  one supply chain with the dataplane. The custom route protocol is small (protobuf
  or a hand-rolled TLV, TCP/IPv6, subscribe-by-VNI) and squarely in Rust's wheelhouse.
- **Reflector / route-server: Rust** as well (shared types/codec with the agent). If
  we later add the **EVPN gateway**, that specific component is **Go (embedded
  gobgp)** — isolated to the edge, not the datapath.

Choosing custom-in-Rust preserves the single-language property; choosing EVPN-now
would force Go or C into the node agent, which is the main reason to defer it.

---

## Decision

1. **v1: custom metalbond-style route bus, in Rust**, programming eBPF maps directly.
   Improve on metalbond: HA reflector, graceful-restart/EoR, ECMP nexthop-sets,
   faster/decoupled liveness, a minimal attribute set.
2. **Keep EVPN as an edge/interop concern**, implemented later as an **EVPN gateway
   using embedded gobgp (Go)** on a few route-servers — for ToR peering and future
   DPU offload — not on every node and not on the fast path.
3. **Language: Rust** for agent + reflector; Go only inside the EVPN gateway.

Rationale: our data model already *is* metalbond's model, which already *is* our
eBPF maps — the impedance match is near-perfect and pure Rust. EVPN's value is
standardisation and hardware/ToR interop, which we don't need on the intra-fleet hot
path and can add at the edge when a DPU or ToR-EVPN design actually lands.

---

## Open risks — what a follow-up implementation spike must prove

1. **EVPN Type-5 tuple round-trip (highest).** Prove gobgp's Type-5 `add prefix …
   gw/etag/label/rd/rt [encap]` carries `nexthop=underlay-IPv6` + our VNI, and that
   the receiver's watch API surfaces `(prefix, nexthop, VNI, encap)` losslessly.
   Specifically: does gobgp accept/round-trip **tunnel-type-7 "IP in IP"** in the
   encap-community, or do we ride BGP-nexthop + RT/etag and ignore encap? *This is the
   crux claim and is currently unproven.*
2. **Liveness / convergence budget.** Quantify remote-endpoint failover time for the
   custom bus (keepalive interval vs. requirement). Does it need BFD-grade detection?
   metalbond's second-scale keepalive may be too slow for "latency-sensitive."
3. **HA reflector semantics.** Design + prove a reflector-cluster model (sync/election
   or durable log) that avoids the divergence metalbond punts to the client.
4. **ECMP in the datapath.** Confirm the eBPF maps + protocol can represent and
   forward over a nexthop *set* (multiple remote underlays per prefix).
5. **Graceful restart / stale routes.** Prove no blackhole window on reflector or
   agent restart (EoR marker + stale-preserve).
6. **EVPN-gateway re-export correctness.** When the gateway bridges custom↔EVPN,
   prove RD/RT/etag mapping is stable and loop-free (origin marking), and that the
   ToR FRR accepts our Type-5s with IPv6 nexthops.
7. **DPU offload assumptions.** Validate that a target DPU eswitch actually consumes
   EVPN Type-5 with an IP-in-IPv6 (non-VXLAN) datapath — otherwise the EVPN-interop
   rationale weakens.

## Sources

- metalbond: [repo](https://github.com/ironcore-dev/metalbond),
  `docs/metalbond_protocol.md`, `docs/dev_and_usage.md`, `pb/metalbond.proto`
  (transport TCP/IPv6:4711, HELLO/KEEPALIVE/SUBSCRIBE/UNSUBSCRIBE/UPDATE,
  NextHop{targetAddress,targetVNI,type,natPortRange}, `ip6tnl` install).
- [metalnet](https://github.com/ironcore-dev/metalnet) (consumer of metalbond+dpservice).
- EVPN: [RFC 9136 (Type-5 IP Prefix)](https://datatracker.ietf.org/doc/html/rfc9136),
  [RFC 9012 (BGP Tunnel Encapsulation Attribute)](https://www.rfc-editor.org/rfc/rfc9012.html),
  [RFC 5512 (obsoleted)](https://datatracker.ietf.org/doc/html/rfc5512),
  [IANA BGP Tunnel Encapsulation registry — type 7 IP-in-IP, type 8 VXLAN](https://www.iana.org/assignments/bgp-tunnel-encapsulation/bgp-tunnel-encapsulation.xhtml),
  [Arista EVPN route types](https://arista.my.site.com/AristaCommunity/s/article/Common-EVPN-Route-Types),
  [Juniper EVPN-VXLAN IPv6 underlay](https://www.juniper.net/documentation/us/en/software/junos/evpn/topics/topic-map/vxlan-ipv6-underlay-overview.html).
- gobgp: [repo](https://github.com/osrg/gobgp),
  [EVPN docs](https://github.com/osrg/gobgp/blob/master/docs/sources/evpn.md),
  [lib docs](https://github.com/osrg/gobgp/blob/master/docs/sources/lib.md).
- RustyBGP: [repo](https://github.com/osrg/rustybgp) (no EVPN).
- holo: [repo](https://github.com/holo-routing/holo) (BGP-4, no EVPN AF).
- Cilium (BGP-as-control-plane, eBPF datapath, embedded gobgp):
  [BGP control plane docs](https://docs.cilium.io/en/stable/network/bgp-control-plane/bgp-control-plane/),
  [pkg/bgpv1/gobgp](https://fossies.org/linux/cilium/pkg/bgpv1/gobgp/server.go).
