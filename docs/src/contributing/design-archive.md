# Design history (specs & plans archive)

The chapters of this book are the **current source of truth** — evergreen prose about
the system as it exists today. The design documents under `docs/superpowers/` are
something different: a **historical decision record**. Each was written at a point in
time, before or during the implementation of one increment, and captures the intent,
the trade-offs, and the outcome of that increment. They are dated, they may describe
paths not taken, and **they may have been superseded** by later work.

Read them for *provenance* — why a thing is the way it is, what alternatives were
weighed — not as a description of current behavior. When a spec and this book
disagree, the book wins.

## Directory layout

```
docs/superpowers/
├── specs/      point-in-time design docs (the "what and why" of one increment)
├── plans/      the matching implementation plans (the "how", step by step)
└── research/   pre-design investigations (mechanisms, upstream lineage)
```

- **`specs/`** — one design document per increment. Each carries a date and, typically,
  an outcome section including deferred items and their root-cause analyses.
- **`plans/`** — the implementation plan that executed a spec: the ordered, checkable
  steps. Plans and specs are paired by date and theme.
- **`research/`** — investigations that fed a design: how a mechanism works, what an
  upstream project does, what constraints apply.

## How to read them

Filenames are `YYYY-MM-DD-topic`. A newer document on the same topic generally
supersedes an older one — follow the dates. A spec describes the state of the design
*at the time of writing*; later specs (or this book) may have moved on. The lineage
note in the [Overview](../architecture/overview.md) is the shortest guide to the
biggest such shift: the project began as an eBPF reimplementation of IronCore's
`dpservice`, then grew its own control plane, CRD API, route bus, and CNI, and dropped
the dpservice compatibility surface — so the earliest specs describe constraints that
no longer bind.

## Major themes

An index into the decision record, roughly chronological, so a reader can find where a
given part of the system was designed:

- **Datapath foundations & parity** — the original XDP/dpservice design and the
  feature-parity gap analysis: generalized datapath, VIP, Maglev LB, NAT gateway,
  unified conntrack, firewall, multi-VNI, LPM routing, remote LB backends, neighbor
  NAT, rate metering, IPv6 overlay.
- **Guest edge & drop-in** — dynamic taps, in-guest DHCP, the guest-TX tail-call
  split, and the migration of the guest edge onto tc/tcx BPF.
- **Multi-cluster & KubeVirt** — the KubeVirt-on-dataplane platform design and the
  VM-attach subproject.
- **Control plane & API** — the network API (CRD) design, the route-distribution
  control plane, the CompiledNIC firewall pipeline, and LoadBalancer wiring.
- **North-South edge** — the N-S gateway, edge identity / LB / IPAM, public-VNI egress
  and typed channel, and the realistic BGP fabric / node-identity research.
- **Synthetic testing** — the CompiledNIC synthetic datapath sim, the Fabric LB
  coverage design, and the sim-seam polish.
- **Resilience** — graceful restart / pinned maps and link-pinning zero-downtime
  restart, plus the guest-egress inner-checksum root-cause.
- **Consolidation** — the de-dpservice conformance rework, the ectobase
  rename/restructure, VPC peering, and the tcx-unified guest edge + traffic shaping.
- **CNI plumbing & primary-UDN** — the research behind the Multus default-delegate CNI
  model.

## Contributing new designs

When you plan a non-trivial change, add a dated spec (and, when executing it, a plan)
under `docs/superpowers/`. That keeps the *why* recorded. When the change lands and
stabilizes, fold the durable, current-state description into the relevant book chapter
here — the archive keeps the history; the book keeps the truth.

## See also

- [Dev environment & workflows](./dev.md)
- [Overview: the two planes](../architecture/overview.md)
