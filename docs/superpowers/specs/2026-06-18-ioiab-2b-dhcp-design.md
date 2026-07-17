# Sub-project 2b — In-eBPF DHCPv4 + DHCPv6 server (ioiab drop-in)

**Status:** Design (2026-06-18)
**Parent effort:** ioiab drop-in. Decomposed into **2a** dynamic taps + gRPC (done, 88/89) ·
**2b** (this) DHCPv4/v6 · **2c** ioiab deployment.
**Goal:** Full DHCP **feature parity with dpservice** — the same flags, the same DHCPv4 and DHCPv6
options, served **in the XDP datapath** (mirroring dpservice's `dhcp_node.c` / `dhcpv6_node.c`),
alongside the existing in-datapath ARP/ND responders. Closes the last conformance test → **89/89**.

## 1. Why in-eBPF

dpservice answers DHCP **in-datapath** (DPDK graph nodes), not via a userspace server. We mirror that:
the responders live in XDP next to `arp_nd.rs`. This keeps every guest-facing control packet (ARP,
ND, DHCP) in the one datapath layer that hardware offload eventually mirrors — an AF_PACKET/userspace
server would handle DHCP *outside* that layer (a side socket after `XDP_PASS`), which is
architecturally inconsistent and not how dpservice works. DHCP is a low-rate exception path, so there
is no offload cost to handling it in XDP.

## 2. Flags (mirrored exactly from dpservice `src/dp_conf_opts.c`)

| Flag | Semantics | Default |
|---|---|---|
| `--dhcp-mtu=SIZE` | MTU field in DHCPv4 responses, 68–1500 | **1500** |
| `--dhcp-dns=IPv4` | DNS server in DHCPv4 responses; **repeatable** (array) | none |
| `--dhcpv6-dns=ADDR6` | DNS server in DHCPv6 responses; **repeatable** (array) | none |

Same long-option names, same value ranges, same repeatable-array semantics. Added to both `serve`
(production) and `bringup` (lab). dpservice's per-interface DHCP inputs are `hostname` and
`pxe_config{next_server, boot_filename}`, both already on `CreateInterfaceRequest`.

## 3. DHCPv4 — every option dpservice's `dhcp_node.c` emits

**Server constants** (from `include/nodes/dhcp_node.h`): BOOTP server port 67, client port 68, magic
`0x63825363`, lease `DP_DHCP_INFINITE = 0xffffffff`, subnet mask `DP_DHCP_MASK_NL = 0xffffffff`
(link-local /32), server-id = the overlay gateway IPv4.

**Request handling (`parse_options`):** read `DHCP_OPT_MESSAGE_TYPE` (DISCOVER=1 → reply OFFER=2;
REQUEST=3 → reply ACK=5); detect PXE via `DHCP_OPT_VENDOR_CLASS_ID` (→ TFTP/PXE) and
`DHCP_OPT_USER_CLASS` containing the iPXE marker (→ HTTP/iPXE).

**Reply options, in dpservice's exact order (`add_dhcp_options`):**
1. `MESSAGE_TYPE` (2 OFFER / 5 ACK)
2. `IP_LEASE_TIME` = `0xffffffff` (infinite)
3. `SERVER_ID` = gateway IPv4
4. `CLASSLESS_ROUTE` (opt 121) = `169.254.0.0/16 → 0.0.0.0` **and** `0.0.0.0/0 → gateway`
   (byte-exact per the `classless_route_prefix` layout in `dhcp_node.c`)
5. `SUBNET_MASK` = `0xffffffff`
6. `INTERFACE_MTU` = `--dhcp-mtu`
7. `ROUTER` = gateway **only when `pxe_mode != NONE`** (dpservice quirk: non-PXE clients route via
   the classless-route option, so ROUTER is omitted)
8. `DNS` = the `--dhcp-dns` array (only if any configured)
9. `HOSTNAME` = the interface's hostname (only if set)
10. `END`

**BOOTP fields:** `yiaddr` = the interface's configured IPv4; `chaddr` echoed; in PXE mode also set
the BOOTP `siaddr`/`file` boot fields per dpservice. UDP src 67 / dst 68, IP src = gateway, dst =
broadcast/`yiaddr`; recompute IP + UDP checksums.

## 4. DHCPv6 — every option dpservice's `dhcpv6_node.c` emits

**Message handling:** `DHCP6_Solicit` → Advertise (or Reply when `RAPID_COMMIT` present);
`DHCP6_Request` → Reply; `DHCP6_Confirm` → Reply. Detect PXE via `VendorClass` (enterprise 343 →
TFTP) vs `UserClass` "iPXE" (→ HTTP).

**Reply options (byte-exact per the `dhcpv6_*` structs in `include/nodes/dhcpv6_node.h` /
`dhcpv6_node.c`):**
- **IA_NA** (echoed `iaid`, `t1=t2=DHCPV6_INFINITY`) → **IAADDR** (addr = the interface's IPv6,
  `preferred=valid=INFINITY`) → **STATUS_CODE = SUCCESS**.
- **ClientId** = echoed client DUID.
- **ServerId** = DUID-LL (`type` DUID_LL, `hw_type`, our MAC).
- **BootFileUrl** = `tftp://[<pxe_ip>]/<boot_filename>` (PXE) or `http://[<pxe_ip>]/<boot_filename>`
  (iPXE), `<pxe_ip>` = the interface's `pxe_config.next_server`.
- **RapidCommit** = echoed when the client sent it.
- **DNSServers** = the `--dhcpv6-dns` array.

UDP src 547 / dst 546, to the client's link-local; IPv6 + UDP checksum over the v6 pseudo-header
(same technique as the ND responder).

## 5. Architecture & components

```
flowplane-ebpf/src/
  dhcp.rs            # NEW: try_dhcpv4_reply, try_dhcpv6_reply (+ option builders, checksums)
  egress.rs          # guest_tx dispatches DHCP after ARP/ND, before the forwarding pipeline
  maps.rs            # + DHCP_CONFIG (Array<DhcpConfig>), DHCP_META (HashMap<u32, DhcpMeta>)
flowplane-common/src/lib.rs
                     # + DhcpConfig{ mtu, dns4[N]+len, dns6[N]+len }, DhcpMeta{ hostname[64]+len,
                     #   pxe_ip[16], boot_filename[64]+len }; layout tests
flowplane/src/
  maps.rs            # userspace DhcpConfigMap, DhcpMetaMap wrappers
  control.rs         # set_dhcp_config(); create_interface writes DHCP_META (hostname + pxe)
  grpc.rs            # create_interface decodes hostname + pxe_config -> DhcpMeta
  main.rs            # serve + bringup: --dhcp-mtu/--dhcp-dns/--dhcpv6-dns -> DHCP_CONFIG;
                     #   bringup per-guest hostname/pxe fields for the lab
env/netns-e2e.sh     # v4 + v6 DHCP probe tests
test/conformance/conftest.py  # RESTORE request_ip in prepare_ipv4 (un-defer DHCP from 2a)
```

1. **`dhcp.rs`** — two responders, dispatched from `guest_tx` immediately after the ARP/ND
   responders and before the IPv4/IPv6 forwarding pipeline. Each: detect its DHCP request, build the
   reply **in place** (fixed/bounded option layout, constant offsets), `bpf_xdp_adjust_tail` to size
   the option block, recompute checksums, `XDP_TX`. Non-DHCP/malformed → `None` (fall through). This
   is the proven `arp_nd.rs`/NAT64 construction pattern (fixed-size, verifier-safe).
2. **`DHCP_CONFIG`** (server-wide, entry 0): `mtu: u16`, `dns4: [[u8;4]; N]` + `dns4_len`,
   `dns6: [[u8;16]; N]` + `dns6_len`. `N` sized for the conformance set + headroom (e.g. 8). Set from
   the flags at bringup/serve.
3. **`DHCP_META`** (`ifindex → DhcpMeta`): `hostname: [u8;64]` + `hostname_len`, `pxe_ip: [u8;16]`,
   `boot_filename: [u8;64]` + `boot_filename_len`. Keeps `PortMeta` lean. The guest IPv4/IPv6/MAC for
   the reply come from `PORT_META`.
4. **MAC learning** (`test_l2_addr_once`): on a DHCPv4 request whose BOOTP `chaddr` differs from
   `meta.guest_mac`, the responder writes `PORT_META[ifindex].guest_mac = chaddr` in-datapath, so
   subsequent delivery uses the learned MAC (dpservice's representor-then-actual-MAC behaviour).
5. **Plumbing**: `serve`/`bringup` parse `--dhcp-mtu/--dhcp-dns/--dhcpv6-dns` → `DHCP_CONFIG`.
   `grpc create_interface` decodes `hostname` + `pxe_config{next_server, boot_filename}` → `DHCP_META`
   (and the bringup CLI gains an optional per-`--guest` hostname/pxe for the lab).

## 6. Data flow (family-agnostic)

Guest broadcasts DISCOVER (UDP 68→67, IPv4 bcast) or sends Solicit (UDP 546→547, to `ff02::1:2` /
the v6 gateway) on its tap → `guest_tx` RX → `try_dhcpv4_reply` / `try_dhcpv6_reply` builds the reply
in place → `XDP_TX` back out the same tap → guest. The assigned address is always the interface's
configured IP; all lifetimes/leases are infinite (stateless — exactly like dpservice).

## 7. Verifier strategy

Fixed-layout construction with constant offsets (proven by `arp_nd::try_nd_reply` and `nat64.rs`):
build the option block at compile-time-known offsets; cap `hostname`/`boot_filename` at 64 bytes with
a stored length and an unrolled/bounded copy; `bpf_xdp_adjust_tail` then re-fetch `data`/`data_end`
and re-bounds-check before writing; IPv6/UDP checksum folded over fixed-size stack buffers (no
variable-offset packet loops — the lesson from the NAT64 checksum work). The DNS arrays are bounded
(`N` known), so the DNS option is an unrolled, length-gated append.

## 8. Testing

**Conformance (the gate → 89/89):**
- `test_dhcpv4_vf0`, `test_dhcpv4_vf1` — DISCOVER/OFFER/REQUEST/ACK with MTU, DNS×2, hostname,
  assigned-IP asserts (via the restored `request_ip`).
- `test_dhcpv6_vf0` (PXE) + `test_dhcpv6_vf1` (iPXE) — Solicit/Advertise/Request/Reply/Confirm with
  DUID echo, IA_NA/IAADDR address, DNSv6×2, and the **BootFileUrl** (tftp vs http) asserts.
- `test_arp::test_l2_addr_once` — MAC learning across re-DHCP with changed `chaddr`.
- **Restore `request_ip` in the `prepare_ipv4` fixture** (it was commented out in 2a to defer DHCP);
  this re-enables a real DHCP exchange in every test's IP-init, so DHCP is exercised suite-wide.

**Regression:** the existing 88 non-DHCP conformance tests stay green; `env/netns-e2e.sh` (15) + HA
smoke stay green; `flowplane-common` layout tests pass; eBPF verifier accepts both programs.

**Lab:** add a netns DHCPv4 + DHCPv6 probe (scapy or `dhcpcd`) proving a guest obtains its IP, MTU,
and DNS from the datapath over both families.

## 9. Out of scope — *only* what dpservice itself does not implement

DHCP **relay**, dynamic **lease pools / renewal state** (dpservice always offers the one configured
IP with an infinite lease — stateless), and DHCPv6 **prefix delegation**. Every option and behaviour
that dpservice's `dhcp_node.c` / `dhcpv6_node.c` implement is in scope; the implementation pins
byte-exact values (subnet mask, classless-route layout, DUID/IAADDR/status structs, BootFileUrl
format) directly from those source files.
