# IPv4-only / IPv6-only / dual-stack overlays — design

Date: 2026-07-25
Status: designed, approved

## Problem

Both dataplanes (eBPF `flowplane`, DPDK `flowplane-dpdk`) currently REQUIRE an
overlay IPv4 on every attached interface. `ControlCore::program_interface`
programs the v4 self-route (`/32`) and the v4 `INTERFACES` key UNCONDITIONALLY,
while the v6 self-route (`route6` `/128`) is already conditional (`if ipv6 !=
[0;16]`); the eBPF attach enforces it via `primary_ipv4(...).context("attach
requires at least one IPv4")?` and the DPDK attach mirrors it. So a true
IPv6-only overlay interface cannot be attached (it would program a bogus
`0.0.0.0/32` route + a colliding `(vni, 0.0.0.0)` INTERFACES entry).

We want to support **IPv4-only, IPv6-only, and dual-stack** overlays on both
backends. (The underlay is always IPv6 — unaffected.)

## Key finding: the datapath is already IP-family-agnostic

Same-host local delivery is **route + UNDERLAY driven**, not INTERFACES-driven:
`egress::deliver` takes the resolved `RouteValue` and returns `Deliver::Local`
when `UNDERLAY[route.nexthop_ipv6]` resolves to a local tap. The `route6` `/128`
self-route already gives v6 the same local fast path as v4. `INTERFACES`
(`IfaceKey{vni, ipv4}`) is **not read on the delivery hot path** — it is only a
MAC-learning shadow written in `dhcp.rs`. The ARP/ND/RA responders key on the
*gateway* IP + packet type (a v6-only guest uses ND/RA, never ARP).

**Consequence: this is a control-plane + guest-provisioning feature, with NO
changes to the verifier-sensitive eBPF datapath programs.**

## Guest provisioning (decided)

- **Containers (veth):** the agent deterministically configures the pod netns at
  attach (address + per-family default route). Robust, CNI-idiomatic, no
  dependency on the container running a DHCP client / accepting RA.
- **VMs (Tap/PodTap):** unchanged — self-configure via the EXISTING datapath
  responders (DHCPv4 addr+gw, DHCPv6 addr, RA v6-gateway/MTU). The agent cannot
  configure inside a VM's stack. These responders already cover all families.

## Change set

### 1. Symmetric interface programming (flowplane-control — shared)

`ControlCore::program_interface`: gate the v4 self-route (`route_upsert(vni,
ipv4, 32, …)`) AND the v4 `INTERFACES` write (`iface_upsert(IfaceKey::new(vni,
ipv4), …)`) on `ipv4 != [0u8; 4]`, mirroring the existing `if ipv6 != [0u8; 16]`
guard around `route6_upsert`. Result:

| overlay | route4 /32 | INTERFACES(v4) | route6 /128 |
|---------|-----------|----------------|-------------|
| v4-only | yes | yes | no |
| v6-only | no | no | yes |
| dual    | yes | yes | yes |

Both backends inherit this (single shared fn). No datapath change. The
`IfaceMeta` restart-journal row keeps storing both `ipv4` and `ipv6` (0 for the
absent family) — unchanged.

### 2. Attach validation (both backends)

Replace "require IPv4" with "require at least one overlay IP":
- eBPF `attach.rs`: `primary_ipv4(requested_ips)` becomes optional (default
  `[0;4]`, like `primary_ipv6` already is); bail only if BOTH `ipv4 == [0;4]`
  AND `ipv6 == [0;16]` ("attach requires at least one overlay IP").
- DPDK `node.rs` `attach_interface`: the `ipv4 == [0;4]` reject becomes
  `ipv4 == [0;4] && ipv6 == [0;16]` → `InvalidArgument`.

The `AttachInterfaceResponse.ips` becomes the set of present overlay IPs (the v4
string if present, the v6 string if present) — both backends identical.

### 3. Deterministic guest-netns config for containers (flowplane-device — shared)

New `flowplane_device::configure_guest_netns(spec: &GuestNetConfig)` (subprocess
`ip`/`ip netns exec`, same style as `create_veth_pair`), called by BOTH backends'
**veth** attach right after `create_veth_pair`. For each present family
(Cilium-style point-to-point veth, `onlink` so no shared subnet is assumed):
- v4 (if `ipv4 != 0`): `ip addr add <ipv4>/32 dev <guest>`; `ip route add
  <gw4> dev <guest>` (on-link host route to the gateway); `ip route add default
  via <gw4> dev <guest>`.
- v6 (if `ipv6 != 0`): `ip -6 addr add <ipv6>/128 dev <guest>`; `ip -6 route add
  default via <gw6> dev <guest>` (the ND responder answers NS for `gateway_ipv6`
  — the on-link gateway link-local).
`GuestNetConfig { netns_path, guest_ifname, ipv4:[u8;4], gateway_ipv4:[u8;4],
ipv6:[u8;16], gateway_ipv6:[u8;16] }`; a zero family is skipped. Best-effort
sysctls stay in `create_veth_pair`. `Tap`/`PodTap` do NOT call this.

This also runs for the **eBPF container path** (shared fn) — a de-drift + a
behavior add: eBPF containers now get deterministic config in addition to the
DHCP responders. The static values equal what DHCPv4 would hand out, so the two
are consistent; this MUST be regression-verified on the v4/dual container flow.

### 4. Responder gating (verify + tighten)

Ensure each responder no-ops for the absent family so a v6-only guest is never
answered a bogus v4 (and vice-versa): the v4 ARP responder / DHCPv4 responder
must not answer when `gateway_ipv4 == 0` / `guest_ipv4 == 0`; ND/RA/DHCPv6 must
not answer when `gateway_ipv6 == 0` / `guest_ipv6 == 0`. Most are already
implicitly gated (they only fire on a matching ARP/ND/DHCP request, which a
single-family guest won't send), but add explicit `!= 0` guards where a
zero-gateway could otherwise be advertised. Verify against `arp_nd.rs` +
`dhcp.rs` and tighten only where needed.

## Scope boundaries (YAGNI)

- **In:** symmetric `program_interface`; attach validation (≥1 family, both
  backends); `configure_guest_netns` for containers (both backends via the shared
  device crate); responder-gating verification.
- **Out:** any datapath/eBPF-program change (delivery is already family-agnostic);
  Tap/PodTap provisioning change (VMs keep DHCP/RA); B2b af_xdp polling; NAT/LB
  v6 semantics beyond what already exists.
- Untouched: eBPF datapath programs, sim byte-parity, `flowplane-node`, the
  DHCP/ND/RA responder logic (only their zero-gateway gating verified).

## Testing

1. **flowplane-control** unit tests (`MemMapWriter`, no root): `program_interface`
   for v4-only (route4 `/32` + INTERFACES present, NO route6), v6-only (route6
   `/128` present, NO route4/INTERFACES), dual (all three). Assert the exact
   map writes.
2. **flowplane-device** tests: `configure_guest_netns` into a throwaway netns
   (`#[ignore]` + sudo) — for v4-only, v6-only, dual, assert the guest end has the
   expected `ip addr` + default route(s) for the present family/families and none
   for the absent one.
3. **Attach validation:** both backends reject the all-zero-IP request and accept
   v4-only / v6-only / dual (unit where possible; the DPDK EAL integration test
   extended with a v6-only + a dual case).
4. **eBPF regression:** the existing container attach (v4 + dual) stays green; the
   privileged eBPF/clab container path is unchanged in behavior (static config
   equals the DHCP-assigned values). `make test`/`sim`/`sim-anchor` unaffected
   (control/host-plane only).
