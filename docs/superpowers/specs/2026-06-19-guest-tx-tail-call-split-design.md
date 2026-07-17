# Egress (guest_tx) Tail-Call Split — Design

**Status:** proposed
**Date:** 2026-06-19
**Context:** Unblocks in-XDP DHCPv6 (ioiab sub-project 2b, Task 4), which currently cannot be
verified because it shares a single XDP program with the IPv4 forwarding datapath.

## Problem

`guest_tx` is one monolithic XDP program. `egress::try_guest_tx` inlines, in order:
ARP → ND → DHCPv4 → DHCPv6 → IPv6-overlay dispatch → the IPv4 forwarding path (conntrack +
firewall + VIP/NAT + routing + encap). The BPF verifier must verify the whole thing as a single
unit against two hard limits:

- **1,000,000-instruction limit.** The IPv4 firewall's `FW_RULES` rule-scan alone costs ~700k
  verifier instructions (`mark_precise` walks it ~26k times). DHCPv4 fits in the remaining
  headroom; DHCPv6's option parse/emit/checksum tips the cumulative total over 1M.
- **512-byte combined-stack limit.** `guest_tx`'s frame is already 456 bytes, leaving ~56 bytes
  for any DHCPv6 subprogram call chain — too little.

At runtime a DHCPv6 frame returns `XDP_TX` long before it ever reaches the IPv4 firewall; the two
only collide inside the verifier because they live in one program. The DHCPv6 datapath itself is
correct and verifies in isolation. This is a "the program does too much in one verification unit"
problem, not a "make DHCPv6 smaller" problem.

Only the **egress** program (`guest_tx`) overflows. `uplink_rx` (ingress) and the other XDP
programs verify within budget today and are out of scope.

## Approach: classify-then-tail-call

Split `guest_tx` into a thin classifier that `bpf_tail_call`s into protocol-specific programs.
Each tail-called program is verified independently, so each gets its **own** fresh 1M-instruction
and 512-byte-stack budget. This is the standard way production XDP datapaths (Cilium, dpservice)
scale past the verifier limits, and it preserves the in-datapath / offload-ready DHCP design.

### Program layout

| Program            | Role                                                                    |
|--------------------|-------------------------------------------------------------------------|
| `guest_tx`         | Classifier (entry, attached to guest taps). PORT_META lookup, ARP, ND inline; then tail-call by protocol. |
| `guest_dhcp`       | DHCPv4 + DHCPv6 responders (`try_dhcpv4_reply`, `try_dhcpv6_reply`).     |
| `guest_ipv4_fwd`   | IPv4 forwarding path (conntrack / firewall / VIP / NAT / route / encap). |
| `guest_ipv6`       | IPv6 overlay path (`v6_guest_tx`).                                       |

`guest_tx` keeps ARP/ND inline because they are tiny, control-plane, and run on every frame; a
tail call for them would cost more than it saves.

### Classification (in `guest_tx`, after ARP/ND)

Read ethertype, and for IP frames the L4 protocol + UDP destination port:

- ethertype IPv4 **and** UDP dport 67  → tail-call `GUEST_PROG_DHCP`
- ethertype IPv6 **and** UDP dport 547 → tail-call `GUEST_PROG_DHCP`
- ethertype IPv6 (anything else)       → tail-call `GUEST_PROG_IPV6`
- ethertype IPv4 (anything else)       → tail-call `GUEST_PROG_IPV4`
- otherwise                            → `XDP_PASS`

`bpf_tail_call` does not return on success. On miss (empty slot / depth limit) it falls through;
the fall-through path returns `XDP_PASS` as a safe default. Each tail-called program re-derives
`ctx.data()` (tail calls invalidate packet pointers) and re-looks-up `PORT_META` by
`ingress_ifindex` (cheap, already how every handler gets `meta`).

### Map and constants

- New `BPF_MAP_TYPE_PROG_ARRAY` map `GUEST_PROGS` (aya `ProgramArray`), 4 entries.
- Index constants in `flowplane-common`: `GUEST_PROG_DHCP = 0`, `GUEST_PROG_IPV4 = 1`,
  `GUEST_PROG_IPV6 = 2`.

### Loader / control plane

At startup the loader loads (verifies) `guest_tx`, `guest_dhcp`, `guest_ipv4_fwd`, `guest_ipv6`,
then inserts the three sub-programs' fds into `GUEST_PROGS` at their indices via
`ProgramArray::set`. The sub-programs are loaded but **not** attached to an interface — they are
tail-call targets only. Per-tap attachment of the `guest_tx` classifier is unchanged (the dynamic
taps feature keeps working as-is). The `GUEST_PROGS` map is populated once and shared.

### Sub-programs keep their bpf-to-bpf subprograms

`guest_dhcp` still calls the existing `d6_parse` / `d6_emit` / `d6_checksum` bpf-to-bpf
subprograms. Combining tail calls with bpf-to-bpf calls is supported on modern kernels (target is
7.0.11). **Risk / fallback:** if this kernel rejects tail-call + bpf2bpf, inline the DHCPv6 helpers
directly into `guest_dhcp` — without the firewall competing for budget, the inlined parse+emit
fits comfortably under that program's own 1M limit.

## What moves where (no behaviour change)

- `egress::try_guest_tx` body lines for the IPv4 forwarding path move verbatim into
  `egress::ipv4_fwd` (called by `guest_ipv4_fwd`). Same conntrack/firewall/NAT/encap logic.
- DHCPv4 + DHCPv6 dispatch moves into `egress::dhcp_handle` (called by `guest_dhcp`).
- `v6::v6_guest_tx` is called by `guest_ipv6` unchanged.
- ARP/ND + classification become the new `egress::try_guest_tx` (classifier).

Runtime semantics are identical: the same packet takes the same logical path; it is only split
across program boundaries.

## Testing

1. **Verifier gate:** every program (`guest_tx`, `guest_dhcp`, `guest_ipv4_fwd`, `guest_ipv6`,
   `uplink_rx`) loads — this is the whole point. Extend `both_programs_pass_verifier` to load all.
2. **Conformance:** the full `test/conformance` suite goes green including `test_dhcpv6.py`
   (target 93/93), confirming DHCPv6 OFFER/REPLY/PXE/DNS on the wire.
3. **Regression:** existing ARP/ND/DHCPv4/v4-forwarding/v6-overlay/NAT/firewall conformance and the
   netns e2e probe still pass — proves the split preserved the datapath.

## Out of scope

`uplink_rx` (ingress) is not split (verifies today). No change to map schemas, the gRPC contract,
or the dynamic-taps attach flow beyond populating `GUEST_PROGS` once at startup.
