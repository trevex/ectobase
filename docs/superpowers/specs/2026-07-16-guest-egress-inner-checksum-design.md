# Correct Inner-L4 Checksum for Encapped Guest Egress — Design

> **STATUS 2026-07-17: DEFERRED (approach D disproven by prototype; clab-only `ethtool` workaround
> retained).** A live prototype (Task 1 of the plan) disproved approach D's premise: **`bpf_skb_adjust_room`
> does not re-point `skb->csum_start` at the inner L4 after our encap.** bpftrace at eth1 xmit showed
> `csum_start` stuck at the guest's *original* absolute offset (constant 288 from `skb->head`) regardless
> of flags — it lands on the inner L4 (off-74) only by coincidence when `headroom` happens to be 206;
> otherwise it points at the inner IP (off-54) → the kernel's `skb_checksum_help` sums the wrong range.
> Both `BPF_F_ADJ_ROOM_NO_CSUM_RESET` (candidate 1) and `BPF_F_ADJ_ROOM_ENCAP_L3_IPV6|FIXED_GSO`
> (candidate 2) failed identically. So "let the kernel finalize" is not reachable via an adjust_room
> flag. Remaining paths are harder: candidate 3 (compute the inner L4 checksum in BPF **and** defeat the
> kernel's re-finalization of the still-`CHECKSUM_PARTIAL` skb — no clean helper to clear PARTIAL), or
> candidate 4 (normalize headroom so `adjust_room` never reallocs — fragile). **Decision:** this is a
> clab/kind all-veth artifact — production real NICs finalize the inner checksum in hardware for both
> containers and vhost taps, so the `ethtool -K … tx-checksum-ip-generic off` line in `attach.rs` is
> load-bearing **only on the test fabric**. We keep it (clab-only), and revisit the datapath fix
> (candidate 3/4) if a real all-software-NIC deployment appears. The root-cause analysis below stands.

> **Context:** The guest tc-egress edge (`tc_guest_tx`) SNATs + encapsulates guest packets into the
> IP-in-IPv6 overlay. Guest TCP/UDP arrives with `CHECKSUM_PARTIAL` (offloaded — the L4 field holds
> only the pseudo-header partial sum, meant to be finalized "by hardware" at real egress). Today the
> inner L4 checksum reaches the wire wrong, dropped by the peer (ICMP is immune). The current
> mitigation — `attach.rs` shelling out to `ethtool -K <guest-veth> tx-checksum-ip-generic off` — is a
> container-only crutch: a vhost-net VM still emits `CHECKSUM_PARTIAL` (you can't `ethtool` inside the
> guest), and disabling offload is a per-guest performance tax.

## Root cause (validated live)

Traced hop-by-hop on the clab fabric (kernel 7.0.11):

1. On a veth fabric, `CHECKSUM_PARTIAL` finalization is deferred to the **egress device**. A veth
   advertises `HW_CSUM` but doesn't actually compute → the partial checksum crosses unfinalized. A
   real NIC (or a device with offload *off*) finalizes it. **This is independent of the encap method**
   — a kernel `ip6tnl`/`ipip` tunnel has the identical problem on veth (spiked and confirmed).
2. Our uplink `eth1` already has tx-offload **off**, so the kernel *does* run
   `skb_csum_hwoffload_help` → `skb_checksum_help` at eth1 xmit and the skb *is* still
   `CHECKSUM_PARTIAL`. But our manual encap leaves **`csum_start` pointing at the inner IP header
   (off 54), not the inner L4 (off 74)** — a 20-byte error (the inner IPv4 header length):

   ```
   eth1 len=105 csum_start=288 headroom=234 off_from_data=54 csum_offset=16   ← WRONG
   eth1 len=114 csum_start=280 headroom=206 off_from_data=74 csum_offset=16   ← correct
   ```

   Wire layout `[outer_eth 14][outer_ipv6 40][inner_ipv4 20][inner_tcp]` → inner L4 at offset 74. With
   `csum_start` at 54, `skb_checksum_help` sums the wrong range and writes the checksum at the wrong
   offset → wrong inner L4 checksum on the wire. `adjust_room(+IPV6_LEN, BPF_ADJ_ROOM_MAC, 0)` +
   `write_outer_v6`'s head-overwrite does not reliably carry `csum_start` to the inner L4.

## Goal

The encapped inner L4 checksum is correct on the wire for `CHECKSUM_PARTIAL` guest packets, **without
disabling guest offload**, for both container **veth** and VM **vhost-tap** sources, on clab (veth
uplink, offload-off → kernel finalizes in SW) and production (real NIC, offload-on → NIC finalizes in
HW). Remove the `ethtool` workaround.

## Non-goals

- TSO/GSO super-packets through the overlay (our manual encap already can't segment them; the guest
  edge operates ≤MTU). Jumbo MTU is fine as long as it's a single (non-GSO) frame.
- Changing the overlay wire format or the XDP decap path.
- The WAN-edge return-path harness issues (separate, environmental).

## Approach (D): keep `csum_start` on the inner L4

Make the encap preserve `CHECKSUM_PARTIAL` with `csum_start`/`csum_offset` pointing at the inner L4
header after encap. The kernel then finalizes correctly at the uplink egress — SW on a veth uplink
(offload off), HW on a real NIC — device-independent and source-independent (veth or tap).

### Mechanism — locked by a prototype loop, not guessed

We have a cheap, exact validator (below), so the implementation's first task tries candidates and
measures, in this preference order:

1. **`BPF_F_ADJ_ROOM_NO_CSUM_RESET`** (bindings: value 32) added to the `adjust_room` flags, so the
   helper stops mangling the checksum metadata and `csum_start` tracks the inserted bytes to land on
   the inner L4 (off 74). Smallest change (one flag per encap call).
2. **Explicit `csum_start` re-establishment** after `write_outer_v6` — if a BPF-settable path exists
   to point `csum_start` at the inner L4 (e.g. via a helper that re-derives it from the current
   headers). Used only if (1) doesn't yield off-74.
3. **Fallback — compute the full inner L4 checksum in BPF** (approach C): after SNAT, sum the inner
   L4 header + payload + pseudo-header over the ≤MTU packet and write a complete checksum, and clear
   the partial-offload state so the kernel does not re-finalize. Bulletproof and device-independent,
   but more code and verifier-heavier; chosen only if (1) and (2) fail.

The chosen mechanism must produce, for a guest TCP packet with offload **on**:
`off_from_data == inner-L4 offset` **and** on-wire `cksum (correct)`. Inner-L4 offset from `data`
(which starts at the outer Ethernet): IPv4-inner = `outer_eth(14)+outer_ipv6(40)+inner_ipv4(20)` =
**74**; IPv6-inner = `14+40+inner_ipv6(40)` = **94**.

## Components / files

- `xdp-dp-ebpf/src/tc.rs` — the two encap branches (IPv4-inner ~line 202, IPv6-inner ~line 132): apply
  the chosen `csum_start`-preserving mechanism to the `adjust_room`/`write_outer_v6` sequence. One
  responsibility: tc guest-egress verdict execution.
- `xdp-dp-ebpf/src/nat64.rs` — the NAT64 encap path (`adjust_room(+IPV6_LEN, …)`): same fix so
  translated IPv4→IPv6 egress is also correct. One responsibility: NAT64 translate+encap.
- `xdp-dp/src/attach.rs` — **remove** the `ethtool -K … tx-checksum-ip-generic off` block (lines
  210-219). One responsibility: veth/netns setup.
- `xdp-dp-core/src/encap.rs` — if the fix needs the inner-L4 offset at encap time, expose it from the
  pure core (it already computes `inner_len`); keep the checksum-offset logic testable in the sim.
- `test/scenario-guest-csum.sh` (new) — the live regression: offload **on**, assert on-wire inner TCP
  `cksum (correct)` on veth (natpod) and, where available, the tap path. One responsibility: checksum
  regression.

## Data flow (unchanged except the csum-metadata handling)

Guest TCP (`CHECKSUM_PARTIAL`, pseudo-partial in the L4 field) → `tc_guest_tx` ingress on the host
veth/tap → SNAT (incremental `csum_replace4/2`, which correctly updates the *pseudo-header* partial
for the new addresses) → encap (`adjust_room` + `write_outer_v6`) **preserving `csum_start` at the
inner L4** → `bpf_redirect(eth1)` → kernel finalizes the inner L4 at eth1 xmit (SW: veth offload-off;
HW: real NIC). The incremental SNAT on the pseudo-partial is already correct once the kernel does the
final fold — the only bug is the lost `csum_start`.

## Testing

- **Unit / sim (`xdp-dp-core`, `xdp-dp-sim`):** the pure encap computes the correct inner-L4
  offset/`csum_offset` for IPv4-inner and IPv6-inner; assert the offset the datapath will hand the
  kernel. (The sim can't model skb offload, so on-wire correctness is a live test — noted.)
- **Verifier anchors:** the existing `sudo -E cargo test --test anchor_*`/`verify_edge_wan_rx` must
  still pass (the new flag must not break the tc program's verification).
- **Live (the decisive test):** with guest offload **ON** (bug-inducing), on `natpod` (veth):
  - bpftrace: `off_from_data == inner-L4 offset` at eth1 xmit;
  - `tcpdump -vv` on eth1: inner TCP `cksum (correct)`;
  - a full TCP round trip (HTTP GET → 200/301) once the WAN path is clean.
  - Repeat on the tap path via `test/tap-vm-smoke.sh` (VM/tap source), asserting the same on-wire
    `cksum (correct)` — proving the fix is source-independent (the whole point vs the ethtool crutch).

## Risks / rollback

- **Mechanism (1)/(2) may not achieve off-74** on this kernel/aya — mitigated by the prototype loop
  with the exact validator, and the compute-in-BPF fallback (3) which is device-independent.
- **Verifier budget:** the tc program is already near limits (dlog! blows it). The fix must be
  checksum-metadata-only where possible (a flag) to avoid new packet-bounds proofs; the compute-in-BPF
  fallback needs careful bounded loops.
- **Egress-device assumption:** a veth uplink left with offload *on* would still not finalize —
  document that the uplink must be a real NIC (offload on) or a veth with offload off (clab already
  is). The fallback (3) removes this dependency entirely if it becomes a problem.
- **Rollback:** the change is confined to the encap csum-metadata handling; reverting restores the
  (buggy-on-partial) behavior. The `ethtool` removal is independent — if the datapath fix regresses,
  re-adding the ethtool line restores the container-only mitigation.
