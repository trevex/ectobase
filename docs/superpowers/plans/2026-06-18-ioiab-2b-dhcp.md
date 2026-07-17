# ioiab 2b — In-eBPF DHCPv4 + DHCPv6 Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve DHCPv4 + DHCPv6 in the XDP datapath at full dpservice feature parity (same flags, same options), so guests obtain their configured IP/MTU/DNS/hostname/PXE in-datapath — closing the last dpservice conformance test to reach **89/89**.

**Architecture:** Two in-XDP responders in `flowplane-ebpf/src/dhcp.rs` (`try_dhcpv4_reply`, `try_dhcpv6_reply`), dispatched from `guest_tx` after ARP/ND, mirroring `arp_nd.rs` and dpservice's `dhcp_node.c`/`dhcpv6_node.c`. They rewrite the request in place into the reply (`bpf_xdp_adjust_tail` to size options), recompute checksums, and `XDP_TX`. Config comes from a server-wide `DHCP_CONFIG` map (`--dhcp-mtu/--dhcp-dns/--dhcpv6-dns`) and a per-interface `DHCP_META` map (`hostname` + `pxe_config`).

**Tech Stack:** Rust + aya/aya-ebpf (rustup `nightly-2026-01-15`, bpf-linker), the dpservice `test/conformance` suite, scapy.

**Spec:** `docs/superpowers/specs/2026-06-18-ioiab-2b-dhcp-design.md`. dpservice references (clone at `/tmp/dpservice`, tag v0.3.22): `src/nodes/dhcp_node.c`, `src/nodes/dhcpv6_node.c`, `include/nodes/dhcp_node.h`, `include/protocols/dp_dhcpv6.h`.

**Starting point (verified):**
- `flowplane-ebpf/src/egress.rs::try_guest_tx`: dispatch order is `try_arp_reply` → `try_nd_reply` → IPv6 ethertype branch (`v6_guest_tx`) → IPv4 pipeline. We insert DHCP dispatch after `try_nd_reply`.
- `arp_nd.rs` shows the in-place rewrite + `XDP_TX` pattern; `try_nd_reply` shows fixed-size IPv6/ICMPv6 build + pseudo-header checksum (`csum16`); `nat64.rs` shows `bpf_xdp_adjust_*` resize with verifier-safe fixed-offset checksums.
- `PortMeta{vni, guest_ipv4, gateway_ipv4, guest_mac, _pad, underlay_ipv6, gateway_ipv6, guest_ipv6}`.
- `flowplane/src/main.rs` `Cmd::Serve` already PARSES `--dhcp-mtu/--dhcp-dns/--dhcpv6-dns` (currently `_dhcp_*` unused). `Cmd::Bringup` does NOT yet.
- `flowplane/src/grpc.rs::create_interface` decodes `ipv4_config`/`ipv6_config`; it does NOT yet read `hostname` (field 10) or `pxe_config` (field 6, `PxeConfig{next_server, boot_filename}`).
- `test/conformance/conftest.py::prepare_ipv4` has `request_ip(...)` commented out (deferred in 2a). `config.py`: `dhcp_mtu=1337`, `dhcp_dns1/2`, `dhcpv6_dns1/2`, `pxe_server`, `pxe_file_name`, `ipxe_file_name`. `VM1.hostname="vm1-host"`.

**dpservice byte-exact facts (pin from source — deterministic):**
- DHCPv4 opt codes (`include/nodes/dhcp_node.h`): SUBNET_MASK=1, ROUTER=3, DNS=6, HOSTNAME=12, INTERFACE_MTU=26, IP_LEASE_TIME=51, MESSAGE_TYPE=53, SERVER_ID=54, VENDOR_CLASS_ID=60, USER_CLASS=77, CLASSLESS_ROUTE=121, END=255, PAD=0. Magic `0x63825363`. Ports srv 67 / cli 68. Lease + mask = `0xffffffff`.
- DHCPv4 option order (`dhcp_node.c::add_dhcp_options`): MESSAGE_TYPE, IP_LEASE_TIME, SERVER_ID, CLASSLESS_ROUTE, SUBNET_MASK, INTERFACE_MTU, [ROUTER **iff pxe_mode != NONE**], [DNS iff configured], [HOSTNAME iff set], END.
- CLASSLESS_ROUTE value (12 bytes): `16,169,254,0,0,0,0` (169.254.0.0/16 → 0.0.0.0) ++ `0` (0.0.0.0/0 prefix-len) ++ `server_ip[4]` (gateway).
- DHCPv6 opt codes (`include/protocols/dp_dhcpv6.h`): CLIENTID=1, SERVERID=2, IA_NA=3, IAADDR=5, STATUS_CODE=13, RAPID_COMMIT=14, USER_CLASS=15, VENDOR_CLASS=16, DNS=23, BOOT_FILE=59. DUID_LL=3, STATUS_SUCCESS=0, INFINITY=`0xffffffff`. Msg types (RFC 8415): SOLICIT=1, ADVERTISE=2, REQUEST=3, CONFIRM=4, REPLY=7. Ports srv 547 / cli 546.

## File Structure

```
flowplane-common/src/lib.rs    # + DhcpConfig, DhcpMeta (POD) + layout tests
flowplane-ebpf/src/
  maps.rs                   # + DHCP_CONFIG (Array<DhcpConfig>), DHCP_META (HashMap<u32, DhcpMeta>)
  dhcp.rs                   # NEW: try_dhcpv4_reply, try_dhcpv6_reply + helpers (option build, checksum)
  egress.rs                 # guest_tx: dispatch DHCP after ARP/ND
  main.rs                   # + mod dhcp;
flowplane/src/
  maps.rs                   # DhcpConfigMap, DhcpMetaMap wrappers
  control.rs                # set_dhcp_config(); create_interface writes DHCP_META
  grpc.rs                   # create_interface decodes hostname + pxe_config
  main.rs                   # serve + bringup: dhcp flags -> DHCP_CONFIG; bringup per-guest hostname/pxe
test/conformance/
  conftest.py               # restore request_ip in prepare_ipv4
  dp_service.py             # add --dhcp-mtu/--dhcp-dns/--dhcpv6-dns to the serve launch cmd
env/netns-e2e.sh            # DHCPv4 + DHCPv6 probe tests
```

---

## Task 1: Common POD types + maps + layout tests

**Files:** Modify `flowplane-common/src/lib.rs`, `flowplane-ebpf/src/maps.rs`, `flowplane/src/maps.rs`

- [ ] **Step 1: Add `DhcpConfig` + `DhcpMeta`** to `flowplane-common/src/lib.rs` (near `PortMeta`):

```rust
/// Max DNS servers per family carried in DHCP replies (dpservice's flags are repeatable; this caps
/// the in-map array — 8 covers the conformance set + headroom).
pub const DHCP_MAX_DNS: usize = 8;

/// Server-wide DHCP config (DHCP_CONFIG[0]). Mirrors dpservice's --dhcp-mtu/--dhcp-dns/--dhcpv6-dns.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DhcpConfig {
    pub mtu: u16,
    pub dns4_len: u8,           // number of valid entries in dns4
    pub dns6_len: u8,           // number of valid entries in dns6
    pub dns4: [[u8; 4]; DHCP_MAX_DNS],
    pub dns6: [[u8; 16]; DHCP_MAX_DNS],
}

/// Per-interface DHCP config (DHCP_META[ifindex]). hostname + PXE; the guest IP/MAC come from PORT_META.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DhcpMeta {
    pub hostname: [u8; 64],
    pub hostname_len: u8,
    pub boot_filename: [u8; 64],
    pub boot_filename_len: u8,
    pub _pad: [u8; 2],
    pub pxe_ip: [u8; 16],       // pxe_config.next_server (v6 string -> 16 bytes); all-zero = no PXE
}

unsafe impl aya::Pod for DhcpConfig {}
unsafe impl aya::Pod for DhcpMeta {}
```
(The `aya::Pod` impls go under the existing `#[cfg(feature = "user")]` block where the other `Pod`
impls live — match the file's existing pattern.) Add layout asserts in the existing `#[cfg(test)]`
module:
```rust
    #[test]
    fn dhcp_layouts() {
        assert_eq!(core::mem::size_of::<DhcpConfig>(), 2 + 1 + 1 + 4 * DHCP_MAX_DNS + 16 * DHCP_MAX_DNS);
        assert_eq!(core::mem::size_of::<DhcpMeta>(), 64 + 1 + 64 + 1 + 2 + 16);
    }
```

- [ ] **Step 2: Declare the eBPF maps** in `flowplane-ebpf/src/maps.rs` (add `DhcpConfig, DhcpMeta` to the `flowplane_common::{...}` import, then append):

```rust
#[map]
pub static DHCP_CONFIG: Array<DhcpConfig> = Array::with_max_entries(1, 0);
#[map]
pub static DHCP_META: HashMap<u32, DhcpMeta> = HashMap::with_max_entries(1024, 0);
```

- [ ] **Step 3: Userspace wrappers** in `flowplane/src/maps.rs` (add `DhcpConfig, DhcpMeta` to imports; mirror the existing `PortMetaMap`/`ConfigMap` wrappers):

```rust
pub struct DhcpConfigMap {
    map: Array<MapData, DhcpConfig>,
}
impl DhcpConfigMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = Array::try_from(ebpf.take_map("DHCP_CONFIG").context("DHCP_CONFIG map missing")?)?;
        Ok(Self { map })
    }
    pub fn set(&mut self, cfg: &DhcpConfig) -> anyhow::Result<()> {
        self.map.set(0, cfg, 0).context("write DHCP_CONFIG[0]")
    }
}

pub struct DhcpMetaMap {
    map: HashMap<MapData, u32, DhcpMeta>,
}
impl DhcpMetaMap {
    pub fn open(ebpf: &mut Ebpf) -> anyhow::Result<Self> {
        let map = HashMap::try_from(ebpf.take_map("DHCP_META").context("DHCP_META map missing")?)?;
        Ok(Self { map })
    }
    pub fn upsert(&mut self, ifindex: u32, meta: DhcpMeta) -> anyhow::Result<()> {
        self.map.insert(ifindex, meta, 0).context("insert dhcp_meta")
    }
    pub fn remove(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.map.remove(&ifindex).context("remove dhcp_meta")
    }
}
```

- [ ] **Step 4: Build + layout test.**

```bash
cargo test -p flowplane-common 2>&1 | tail -3   # dhcp_layouts passes
cargo build -p flowplane 2>&1 | tail -3          # compiles (maps unused yet = ok)
```

- [ ] **Step 5: Commit.**

```bash
cargo fmt --all
git add flowplane-common flowplane-ebpf/src/maps.rs flowplane/src/maps.rs
git commit -m "feat(dhcp): DhcpConfig/DhcpMeta POD + DHCP_CONFIG/DHCP_META maps"
```

## Task 2: Plumbing — flags → DHCP_CONFIG, gRPC/CLI → DHCP_META, harness flags

**Files:** Modify `flowplane/src/control.rs`, `flowplane/src/grpc.rs`, `flowplane/src/main.rs`, `test/conformance/dp_service.py`

- [ ] **Step 1: `Control` opens the DHCP maps + setters.** In `control.rs` `Inner` add `dhcp_config: crate::maps::DhcpConfigMap` and `dhcp_meta: crate::maps::DhcpMetaMap`; open both in `bring_up` (mirror the other `::open` calls) and init them in the `Inner { .. }` literal. Add methods:

```rust
    pub fn set_dhcp_config(
        &self,
        mtu: u16,
        dns4: &[[u8; 4]],
        dns6: &[[u8; 16]],
    ) -> anyhow::Result<()> {
        let mut cfg = flowplane_common::DhcpConfig {
            mtu,
            dns4_len: dns4.len().min(flowplane_common::DHCP_MAX_DNS) as u8,
            dns6_len: dns6.len().min(flowplane_common::DHCP_MAX_DNS) as u8,
            dns4: [[0; 4]; flowplane_common::DHCP_MAX_DNS],
            dns6: [[0; 16]; flowplane_common::DHCP_MAX_DNS],
        };
        for (i, a) in dns4.iter().take(flowplane_common::DHCP_MAX_DNS).enumerate() { cfg.dns4[i] = *a; }
        for (i, a) in dns6.iter().take(flowplane_common::DHCP_MAX_DNS).enumerate() { cfg.dns6[i] = *a; }
        self.inner.lock().unwrap().dhcp_config.set(&cfg)
    }

    pub fn set_dhcp_meta(
        &self,
        interface_id: &[u8],
        hostname: &[u8],
        pxe_ip: [u8; 16],
        boot_filename: &[u8],
    ) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let ifindex = *g.by_ifindex.get(interface_id)
            .ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let mut m = flowplane_common::DhcpMeta {
            hostname: [0; 64], hostname_len: 0,
            boot_filename: [0; 64], boot_filename_len: 0,
            _pad: [0; 2], pxe_ip,
        };
        let hl = hostname.len().min(64); m.hostname[..hl].copy_from_slice(&hostname[..hl]); m.hostname_len = hl as u8;
        let bl = boot_filename.len().min(64); m.boot_filename[..bl].copy_from_slice(&boot_filename[..bl]); m.boot_filename_len = bl as u8;
        g.dhcp_meta.upsert(ifindex, m)
    }
```
Also clear DHCP_META in `detach_interface` (add `let _ = g.dhcp_meta.remove(tap);` next to the other map removals).

- [ ] **Step 2: gRPC `create_interface` writes DHCP_META.** In `grpc.rs::create_interface`, after the interface is created, decode `hostname` (field 10, a `String`) and `pxe_config` (field 6, `Option<PxeConfig>` with `next_server: String`, `boot_filename: String`) and call `set_dhcp_meta`:

```rust
        let hostname = r.hostname.as_bytes().to_vec();
        let (pxe_ip, boot_file) = match &r.pxe_config {
            Some(p) if !p.next_server.is_empty() => {
                // next_server is a printable IP string; store as 16 bytes (v6, or v4-mapped lower 4).
                let ip = p.next_server.parse::<std::net::Ipv6Addr>().map(|a| a.octets())
                    .or_else(|_| p.next_server.parse::<std::net::Ipv4Addr>().map(|a| {
                        let mut b = [0u8; 16]; b[12..].copy_from_slice(&a.octets()); b
                    }))
                    .unwrap_or([0u8; 16]);
                (ip, p.boot_filename.clone().into_bytes())
            }
            _ => ([0u8; 16], Vec::new()),
        };
        control.set_dhcp_meta(&interface_id, &hostname, pxe_ip, &boot_file)
            .map_err(|e| Status::internal(e.to_string()))?;
```
(Confirm the generated `pb` field names: `r.hostname`, `r.pxe_config`, `PxeConfig{next_server, boot_filename}` — the compile error will name them if different.)

- [ ] **Step 3: serve/bringup set DHCP_CONFIG.** In `main.rs` `Cmd::Serve` arm, after `Control::bring_up`, parse the already-captured dhcp flags and call `set_dhcp_config`. Replace the `_dhcp_mtu/_dhcp_dns/_dhcpv6_dns` prefixes with real use:

```rust
            let dns4: Vec<[u8; 4]> = dhcp_dns.iter().filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets())).collect();
            let dns6: Vec<[u8; 16]> = dhcpv6_dns.iter().filter_map(|s| s.parse::<std::net::Ipv6Addr>().ok().map(|a| a.octets())).collect();
            ctrl.set_dhcp_config(dhcp_mtu.unwrap_or(1500) as u16, &dns4, &dns6)
                .map_err(|e| anyhow::anyhow!(e))?;
```
Add the same three flags (`--dhcp-mtu/--dhcp-dns/--dhcpv6-dns`) to the `Cmd::Bringup` variant + arm (mirror the `Serve` clap fields) and call `set_dhcp_config` there too, so the netns lab can drive DHCP. The bringup `--guest` spec gains an optional trailing `hostname` (and the lab can pass it); if absent, hostname stays empty.

- [ ] **Step 4: Harness launches serve with the DHCP flags.** In `test/conformance/dp_service.py`, append to the `flowplane serve` command (using `config.py`'s constants):

```python
            f" --dhcp-mtu={dhcp_mtu}"
            f" --dhcp-dns={dhcp_dns1} --dhcp-dns={dhcp_dns2}"
            f" --dhcpv6-dns={dhcpv6_dns1} --dhcpv6-dns={dhcpv6_dns2}"
```
(`dhcp_mtu`, `dhcp_dns1/2`, `dhcpv6_dns1/2` are imported via `from config import *`.)

- [ ] **Step 5: Build + commit.**

```bash
cargo build -p flowplane 2>&1 | tail -5   # compiles
cargo fmt --all
git add flowplane test/conformance/dp_service.py
git commit -m "feat(dhcp): plumb --dhcp-* flags -> DHCP_CONFIG and hostname/pxe -> DHCP_META"
```

## Task 3: DHCPv4 responder + dispatch + MAC learning

**Files:** Create `flowplane-ebpf/src/dhcp.rs`; Modify `flowplane-ebpf/src/egress.rs`, `flowplane-ebpf/src/main.rs`

- [ ] **Step 1: `dhcp.rs` DHCPv4 responder.** Implement `try_dhcpv4_reply(ctx, meta) -> Option<u32>`. Detection: ethertype `ETH_P_IP`, IPv4 IHL==5, proto UDP(17), UDP dst port 67. Parse the BOOTP/DHCP: magic `0x63825363` at the options start; scan options (bounded loop, cap 64 iterations) for MESSAGE_TYPE (53) → DISCOVER(1)/REQUEST(3); VENDOR_CLASS_ID(60) → PXE/TFTP; USER_CLASS(77) containing the iPXE marker → HTTP. Then rewrite in place:
  - BOOTP: `op=2` (BOOTREPLY), `yiaddr = meta.guest_ipv4`, `chaddr` unchanged, magic kept.
  - Build the option block at `dhcp_options_offset` in dpservice's exact order (Task header bytes): MESSAGE_TYPE(2 OFFER for DISCOVER / 5 ACK for REQUEST), IP_LEASE_TIME(`0xffffffff`), SERVER_ID(`meta.gateway_ipv4`), CLASSLESS_ROUTE(opt 121, 12 bytes: `16,169,254,0,0,0,0,0` ++ `gateway_ipv4`), SUBNET_MASK(`0xffffffff`), INTERFACE_MTU(`DHCP_CONFIG[0].mtu`), ROUTER(`gateway_ipv4`) **iff pxe_mode != NONE**, DNS(the `dns4[..dns4_len]` array) iff len>0, HOSTNAME(`DHCP_META[ifindex].hostname[..len]`) iff len>0, END(255). For PXE, set BOOTP `siaddr`/`file` from `DHCP_META` (boot filename / pxe_ip).
  - L2/L3/L4: swap eth (dst = requester `chaddr`/eth src, src = `GW_MAC`/gateway), IP src = `gateway_ipv4`, dst = broadcast `255.255.255.255` (DISCOVER) or `yiaddr`, proto UDP, ports src 67/dst 68, set IP total-length + UDP length, recompute IP checksum + UDP checksum (UDP checksum may be 0 for DHCP — dpservice sets it; compute it).
  - Resize: if the built reply is longer than the request, `bpf_xdp_adjust_tail` to grow; re-fetch `data`/`data_end`; re-bounds-check before writing the option tail. Use a FIXED maximum option-block length (constant) so all writes are constant-offset (verifier-safe — the `arp_nd`/`nat64` pattern). Pad with PAD(0) to the fixed length if needed.
  - **MAC learning:** if the BOOTP `chaddr` (first 6 bytes) != `meta.guest_mac`, write `PORT_META[ingress_ifindex].guest_mac = chaddr` (the map is writable from XDP: `PORT_META.insert(&ifindex, &updated_meta, 0)`).
  - Return `Some(XDP_TX)`. Any non-DHCP / malformed / unparsable → `None`.

  Model the checksum + fixed-offset construction on `arp_nd::try_arp_reply` (eth/ip rewrite) and `nat64.rs` (IP/UDP checksum over fixed stack buffers). Read `DHCP_CONFIG`/`DHCP_META` via `crate::maps::{DHCP_CONFIG, DHCP_META}`; `DHCP_META.get(&ingress_ifindex)`.

- [ ] **Step 2: Dispatch in `egress.rs`.** In `try_guest_tx`, after the `try_nd_reply` block and before the IPv6 ethertype branch, add:

```rust
    // Answer DHCPv4 in-datapath.
    if let Some(act) = crate::dhcp::try_dhcpv4_reply(ctx, meta) {
        return Ok(act);
    }
```
Add `mod dhcp;` to `flowplane-ebpf/src/main.rs` (alphabetical, near `mod conntrack;`).

- [ ] **Step 3: Build + verifier.**

```bash
cargo build -p flowplane 2>&1 | tail -3
cargo test -p flowplane both_programs_pass_verifier -- --ignored 2>&1 | tail -3   # 1 passed (needs root)
```
If the verifier rejects, the cause is almost always a non-constant offset or an unbounded option loop — constrain to a fixed max option length and a bounded (≤64) parse loop with explicit `data_end` checks.

- [ ] **Step 4: Conformance — DHCPv4 + MAC learning.**

```bash
sudo pkill -f 'flowplane (serve|pass)' 2>/dev/null; ./test/conformance/setup-net.sh down 2>/dev/null; sleep 1
CONF_TESTS="test_dhcpv4.py test_arp.py" ./test/conformance/run.sh -v 2>&1 | grep -E 'PASSED|FAILED|passed|failed'
```
Expected: `test_dhcpv4_vf0`, `test_dhcpv4_vf1`, `test_l2_addr_once` PASS. (Run with `dangerouslyDisableSandbox: true`; `EXIT=127` is the teardown trap — read the pytest summary.)

- [ ] **Step 5: netns regression + commit.**

```bash
./env/netns-e2e.sh run 2>&1 | tail -3   # All tests passed (DHCP path is additive; lab has no DHCP guests yet)
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(dhcp): in-datapath DHCPv4 responder (OFFER/ACK + PXE) + MAC learning"
```

## Task 4: DHCPv6 responder + dispatch

**Files:** Modify `flowplane-ebpf/src/dhcp.rs`, `flowplane-ebpf/src/egress.rs`

- [ ] **Step 1: `try_dhcpv6_reply(ctx, meta) -> Option<u32>`.** Detection: ethertype `ETH_P_IPV6`, IPv6 next-header UDP(17), UDP dst port 547. Parse the DHCPv6 message: msg-type at the first byte (SOLICIT=1 → Advertise=2, or Reply=7 if RAPID_COMMIT present; REQUEST=3 → Reply=7; CONFIRM=4 → Reply=7); transaction-id (3 bytes) echoed; scan options (bounded ≤32 loop) for CLIENTID(1) → capture the client DUID (bounded copy, cap e.g. 32 bytes), IA_NA(3) → capture iaid (4 bytes), RAPID_COMMIT(14) → present-flag, VENDOR_CLASS(16, enterprise 343) → PXE/TFTP, USER_CLASS(15) "iPXE" → HTTP. Build the reply (fixed maximum layout, constant offsets; pin the exact struct bytes from `/tmp/dpservice/include/protocols/dp_dhcpv6.h` + `src/nodes/dhcpv6_node.c`):
  - msg-type + echoed transaction-id.
  - **IA_NA**(opt 3): echoed iaid, t1=t2=`0xffffffff`; nested **IAADDR**(opt 5): addr=`meta.guest_ipv6`, preferred=valid=`0xffffffff`; nested **STATUS_CODE**(opt 13)=SUCCESS(0).
  - **CLIENTID**(opt 1): echoed client DUID.
  - **SERVERID**(opt 2): DUID-LL (type=3, hw-type, our MAC = `meta.guest_mac`).
  - **BOOT_FILE**(opt 59): `tftp://[<pxe_ip>]/<boot_filename>` (TFTP/PXE) or `http://[<pxe_ip>]/<boot_filename>` (HTTP/iPXE); `<pxe_ip>` from `DHCP_META[ifindex].pxe_ip` rendered as a v6 literal. Cap the URL at a fixed length (e.g. 80 bytes), length-prefixed per the option header.
  - **RAPID_COMMIT**(opt 14): include iff the client sent it.
  - **DNS**(opt 23): `DHCP_CONFIG[0].dns6[..dns6_len]`.
  - L2/L3/L4: eth dst = requester eth src, src = `GW_MAC`; IPv6 src = the v6 gateway (`meta.gateway_ipv6`), dst = the requester's link-local src; UDP src 547/dst 546, set IPv6 payload-length + UDP length; **UDP checksum over the IPv6 pseudo-header** (reuse the `csum16`/pseudo-header technique from `arp_nd::try_nd_reply`).
  - `bpf_xdp_adjust_tail` to size the reply (it is larger than the Solicit); re-fetch + re-bounds-check; fixed max layout for verifier-safety. Return `Some(XDP_TX)`; non-DHCPv6/malformed → `None`.

  Rendering `pxe_ip` (16 bytes) to a `[<hex>]` string in eBPF is bounded: write the 8 hextets with a fixed unrolled formatter (or store the printable PXE string directly in `DhcpMeta` instead of 16 bytes — if simpler, change `DhcpMeta.pxe_ip` to a `[u8;46]` printable string + len in Task 1 and have the gRPC plumbing pass the string through; pick whichever keeps the eBPF formatter trivial and document the choice).

- [ ] **Step 2: Dispatch in `egress.rs`.** After the DHCPv4 dispatch line, add:

```rust
    // Answer DHCPv6 in-datapath.
    if let Some(act) = crate::dhcp::try_dhcpv6_reply(ctx, meta) {
        return Ok(act);
    }
```

- [ ] **Step 3: Build + verifier.**

```bash
cargo build -p flowplane 2>&1 | tail -3
cargo test -p flowplane both_programs_pass_verifier -- --ignored 2>&1 | tail -3   # 1 passed
```

- [ ] **Step 4: Conformance — DHCPv6 (PXE + iPXE).**

```bash
sudo pkill -f 'flowplane (serve|pass)' 2>/dev/null; ./test/conformance/setup-net.sh down 2>/dev/null; sleep 1
CONF_TESTS="test_dhcpv6.py" ./test/conformance/run.sh -v 2>&1 | grep -E 'PASSED|FAILED|passed|failed'
```
Expected: `test_dhcpv6_vf0` (PXE → `tftp://...`) and `test_dhcpv6_vf1` (iPXE → `http://...`) PASS. (`dangerouslyDisableSandbox: true`.)

- [ ] **Step 5: netns regression + commit.**

```bash
./env/netns-e2e.sh run 2>&1 | tail -3   # All tests passed
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(dhcp): in-datapath DHCPv6 responder (IA_NA/IAADDR, DUID, BootFileUrl, DNS)"
```

## Task 5: Restore the DHCP fixture, reach 89/89, lab DHCP test

**Files:** Modify `test/conformance/conftest.py`, `env/netns-e2e.sh`

- [ ] **Step 1: Restore `request_ip` in `prepare_ipv4`.** In `test/conformance/conftest.py`, revert the 2a deferral — un-comment the DHCP exchange so every test's IP-init does a real DHCPv4 round-trip:

```python
@pytest.fixture(scope="function")
def prepare_ipv4(prepare_ifaces):
	print("-------- IPs init --------")
	request_ip(VM1)
	request_ip(VM2)
	request_ip(VM3)
	print("--------------------------")
	return prepare_ifaces
```

- [ ] **Step 2: Full conformance — 89/89.**

```bash
sudo pkill -f 'flowplane (serve|pass)' 2>/dev/null; ./test/conformance/setup-net.sh down 2>/dev/null; sleep 1
./test/conformance/run.sh 2>&1 | grep -E 'passed|failed' | tail -1
```
Expected: `89 passed ... 0 failed`. (`dangerouslyDisableSandbox: true`.) If `request_ip` now fails a previously-passing test, the OFFER/ACK options are off — compare against dpservice `dhcp_node.c` byte-for-byte and re-run `CONF_TESTS="test_dhcpv4.py" ... -v`.

- [ ] **Step 3: netns lab DHCP probe (v4 + v6).** Add a Test 16 + 17 to `env/netns-e2e.sh` `cmd_test`: bring up a guest configured for DHCP (the lab's `bringup` now accepts `--dhcp-mtu/--dhcp-dns/--dhcpv6-dns` and a per-guest hostname) and assert it obtains its IP/MTU/DNS over both families. Minimal, scapy-free check using the kernel client is acceptable, e.g.:

```bash
    echo "=== Test 16: DHCPv4 — guesta obtains its lease from the datapath ==="
    sudo ip netns exec guesta ip addr flush dev gA 2>/dev/null || true
    if sudo ip netns exec guesta timeout 8 dhcpcd -4 -T gA 2>/dev/null | grep -q '10.0.0.5'; then
        echo "  DHCPv4 OK: datapath offered 10.0.0.5"
    else
        echo "  WARNING: DHCPv4 lease not obtained (is dhcpcd present? otherwise skip)"
    fi
    echo ""
```
(If `dhcpcd`/`dhclient` is unavailable in the env, make the test best-effort — print a skip — and rely on the conformance suite as the authoritative DHCP gate. Restore guesta's static `10.0.0.5/32` after the probe so Tests 1–15 still pass, or place Test 16/17 last.)

- [ ] **Step 4: Full regression + commit.**

```bash
./test/conformance/run.sh 2>&1 | grep -E 'passed|failed' | tail -1   # 89 passed
./env/netns-e2e.sh run 2>&1 | tail -3                                  # All tests passed
./env/ha-smoke.sh run 2>&1 | tail -3                                   # HA smoke passed
cargo test -p flowplane-common 2>&1 | tail -2                             # layout tests pass
cargo fmt --all
git add test/conformance/conftest.py env/netns-e2e.sh
git commit -m "test(conformance): restore DHCP IP-init; DHCPv4/v6 green -> 89/89; netns DHCP probe"
```

- [ ] **Step 5: Update the 2b spec status.** Set the spec header to `Implemented — 89/89` and commit:

```bash
git add docs/superpowers/specs/2026-06-18-ioiab-2b-dhcp-design.md
git commit -m "docs(spec): 2b DHCP implemented — 89/89 dpservice conformance"
```

---

## Self-Review

**Spec coverage:**
- Flags `--dhcp-mtu/--dhcp-dns/--dhcpv6-dns` (defaults, repeatable) → Task 2 (serve+bringup) + Task 2 Step 4 (harness). ✓
- DHCPv4 full option set + order + classless-route + PXE-only ROUTER + PXE bootfile → Task 3. ✓
- DHCPv4 MAC learning → Task 3 Step 1. ✓
- DHCPv6 full option set (IA_NA/IAADDR/status, ClientId/ServerId DUID, BootFileUrl tftp/http, RapidCommit, DNS) → Task 4. ✓
- In-eBPF responders dispatched from guest_tx after ARP/ND → Tasks 3,4 Step 2. ✓
- `DHCP_CONFIG` + `DHCP_META` maps + per-interface hostname/pxe from gRPC → Tasks 1,2. ✓
- Restore `request_ip`; 89/89 gate; netns lab DHCP; regressions → Task 5. ✓
- Out of scope (relay, lease pools, prefix delegation) — not implemented, consistent with dpservice. ✓

**Placeholder scan:** the DHCPv6 reply struct bytes and the DHCPv4 PXE BOOTP field offsets are pinned via explicit dpservice source references (`dp_dhcpv6.h`, `dhcp_node.c`) — a bounded, deterministic transcription, not a TODO. The `pxe_ip` storage (16 raw bytes vs printable string) is called out as an implementer choice with the trade-off stated (Task 4 Step 1). No "TBD"/"handle edge cases".

**Type consistency:** `DhcpConfig{mtu,dns4_len,dns6_len,dns4,dns6}` + `DhcpMeta{hostname,hostname_len,boot_filename,boot_filename_len,_pad,pxe_ip}` (Task 1) used by `DhcpConfigMap`/`DhcpMetaMap` (Task 1), `set_dhcp_config`/`set_dhcp_meta` (Task 2), and the eBPF responders' `DHCP_CONFIG.get(0)` / `DHCP_META.get(&ifindex)` (Tasks 3,4). Dispatch helpers `try_dhcpv4_reply`/`try_dhcpv6_reply` (Tasks 3,4) match the `egress.rs` call sites.

**Risk note:** the verifier is the main risk for the responders (variable option building). Mitigation is the proven fixed-maximum-layout + constant-offset + bounded-parse-loop pattern (`arp_nd`, `nat64`), with the verifier gate run after each responder (Tasks 3,4 Step 3). The DHCPv6 BootFileUrl + IPv6-pseudo-header UDP checksum is the single most intricate piece; Task 4's PXE-vs-iPXE conformance assertion is the byte-correctness proof.
