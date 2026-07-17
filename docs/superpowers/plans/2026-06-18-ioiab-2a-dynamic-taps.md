# ioiab 2a — Dynamic Tap Lifecycle + gRPC Completeness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `flowplane serve` a complete gRPC-driven dataplane daemon that metalnet (and dpservice's own `test/local` conformance suite) can drive — runtime XDP attach/detach on VF interfaces, full non-DHCP gRPC surface, and a same-host guest-to-guest fast path — proven green against the vendored dpservice conformance tests.

**Architecture:** Extend the existing `Cmd::Serve` (which already attaches `uplink_rx` and serves gRPC) and the existing `Control::create_interface` (which already attaches `guest_tx` dynamically). Add: server-configured gateways (v4 ARP / v6 ND), retained `XdpLink` handles for clean detach, the missing observe/delete RPCs backed by userspace shadow state, an in-datapath local-delivery fast path, and a vendored+adapted conformance harness (veth substitution + real `dpservice-cli`).

**Tech Stack:** Rust + aya/aya-ebpf (rustup `nightly-2026-01-15`, bpf-linker), tonic gRPC, Python pytest + scapy (vendored dpservice `test/local`), bash netns scaffolding.

**Spec:** `docs/superpowers/specs/2026-06-18-ioiab-2a-dynamic-taps-design.md`.

**Starting point (verified in tree):**
- `flowplane/src/main.rs` `Cmd::Serve { addr, uplink, local_underlay, gateway_mac, conntrack_max }` → `Control::bring_up` (attach `uplink_rx`) → tonic serve. Builds `grpc::Service { state, control: Some(Arc<Control>), underlay }`.
- `flowplane/src/control.rs` `Control::create_interface(id, device, vni, ipv4, gateway_ipv4, underlay, total_mbps, public_mbps)` already does `attach_xdp_extra(ebpf,"guest_tx",device).or_else(attach_xdp(...))` and programs `PORT_META` (with `gateway_ipv6: [0;16]`), `INTERFACES`, `UNDERLAY`, optional `METER`. Shadow state: `by_id: HashMap<Vec<u8>,(u32,[u8;4])>`, `by_ifindex`, `iface_underlay`, `prefixes`, `fw`, `lbs`, `neigh_nats`. Delete/list methods exist for vip/nat/lb/fw/prefix/neighbor_nat; **none for interface/route/vni**.
- `flowplane/src/grpc.rs` `Service { state, control, underlay }`. `create_interface` derives `gateway_ipv4 = [ip0,ip1,ip2,1]`, `gateway_ipv6` not set. 17 stubs return `Status::unimplemented` (incl. `delete_interface`, `list_interfaces`, `get_interface`, `list_routes`, `delete_route`, `check_vni_in_use`, `reset_vni`, and the LB/NAT/VIP/FW list/get/delete the create-side already has control methods for).
- `flowplane/src/loader.rs` `attach_xdp_extra(ebpf, prog, iface)` attaches but **discards the link** (no detach possible). `attach_xdp_pinned` shows the `take_link`/`FdLink` pattern.
- `flowplane-ebpf/src/egress.rs` `try_guest_tx`: after `ROUTES.get(...)` → `route`, always `encap_and_redirect(...)`. `UNDERLAY: HashMap<[u8;16],UnderlayValue{vni,tap_ifindex,guest_mac,_pad}>`, `GW_MAC` in `arp_nd.rs`, `write6` in `parse.rs`.
- Harness device model (dpservice `test/local/config.py`): `PF0.tap=dtap0` mac `22:22:22:22:22:00`; `PF1.tap=dtap1`; `VM1.tap=dtapvf_0` mac `66:66:66:66:66:00` vni=100 ip=10.100.1.1 ipv6=2000:100:1::1; `VM2=dtapvf_1` mac `..:01` vni=100 ip=10.100.1.2; `VM3=dtapvf_2` vni=200; `VM4=dtapvf_3` vni=100 (manual). `gateway_ip=169.254.0.1`, `gateway_ipv6=fe80::1`, `local_ul_ipv6=fc00:1::1`, `grpc_port=1337`. `grpc_client.addinterface` calls `dpservice-cli add interface --id={name} --device={pci} --vni= --ipv4= --ipv6=`.

## File Structure

```
flowplane/src/main.rs       # Cmd::Serve gains --gateway/--gateway6/--pin-dir/--dhcp-* ; thread gateways into Service
flowplane/src/grpc.rs       # Service gains gateway_ipv4/gateway_ipv6 ; implement the 7 + feature observe/delete RPCs
flowplane/src/control.rs    # links HashMap (XdpLink) ; create_interface(+gateway_ipv6) ; detach_interface ;
                         #   route shadow + list_routes/delete_route ; interface shadow detail ; vni helpers
flowplane/src/loader.rs     # attach_xdp_link() -> XdpLink (retained for detach)
flowplane-ebpf/src/egress.rs# local guest-to-guest fast path (v4) before encap
flowplane-ebpf/src/v6.rs    # local fast path (v6) before encap
test/conformance/        # VENDORED dpservice test/local + adapters (NEW)
  setup-net.sh           #   veth substitution + xdp_pass enablers (NEW)
  run.sh                 #   build, bring up net, start flowplane serve, pytest the non-DHCP suite (NEW)
  dp_service.py          #   patched launcher: flowplane serve instead of dpservice-bin
  config.py              #   .pci -> xdp-side veth names (scaffolding edit)
  bin/dpservice-cli      #   pinned released binary (fetched)
```

---

## Task 1: Serve-mode config — server-configured gateways + pin/dhcp flags

**Files:** Modify `flowplane/src/main.rs` (`Cmd::Serve` variant + arm), `flowplane/src/grpc.rs` (`Service` struct + `create_interface`)

- [ ] **Step 1: Extend the `Cmd::Serve` variant** in `flowplane/src/main.rs` (the struct around line 80). Add fields after `gateway_mac`:

```rust
        /// Overlay IPv4 gateway the datapath answers ARP for (e.g. 169.254.0.1).
        #[arg(long)]
        gateway: String,
        /// Overlay IPv6 gateway the datapath answers ND for (e.g. fe80::1).
        #[arg(long = "gateway6")]
        gateway6: Option<String>,
        /// Pin programs+maps under this dir for HA (control-plane restart re-adopts).
        #[arg(long = "pin-dir")]
        pin_dir: Option<String>,
        /// DHCP options (stored for sub-project 2b; accepted now to keep the ioiab arg list stable).
        #[arg(long = "dhcp-mtu")]
        dhcp_mtu: Option<u32>,
        #[arg(long = "dhcp-dns")]
        dhcp_dns: Vec<String>,
        #[arg(long = "dhcpv6-dns")]
        dhcpv6_dns: Vec<String>,
```

- [ ] **Step 2: Thread gateways into the arm.** In the `Cmd::Serve { .. }` match arm, destructure the new fields and compute the gateways, then pass them to `Service`:

```rust
        Cmd::Serve {
            addr,
            uplink,
            local_underlay,
            gateway,
            gateway6,
            gateway_mac,
            conntrack_max,
            pin_dir: _pin_dir,
            dhcp_mtu: _dhcp_mtu,
            dhcp_dns: _dhcp_dns,
            dhcpv6_dns: _dhcpv6_dns,
        } => {
            if let Some(n) = conntrack_max {
                // SAFETY: single-threaded CLI startup, before any datapath thread is spawned.
                std::env::set_var("FLOWPLANE_CONNTRACK_MAX", n.to_string());
            }
            let underlay = parse_ipv6(&local_underlay)?;
            let gateway_ipv4 = parse_ipv4(&gateway)?;
            let gateway_ipv6 = match &gateway6 {
                Some(s) => parse_ipv6(s)?,
                None => [0u8; 16],
            };
            let ctrl = control::Control::bring_up(
                &uplink,
                ifindex(&uplink)?,
                mac_of(&uplink)?,
                parse_mac(&gateway_mac)?,
                underlay,
            )?;
            if let Some(ct) = ctrl.take_conntrack() {
                tokio::spawn(conntrack_gc::run(ct, std::time::Duration::from_secs(10)));
            }
            let svc = grpc::Service {
                state: std::sync::Arc::new(state::State::default()),
                control: Some(std::sync::Arc::new(ctrl)),
                underlay,
                gateway_ipv4,
                gateway_ipv6,
            };
            let server = crate::pb::dpd_kironcore_server::DpdKironcoreServer::new(svc);
            println!("serving DPDKironcore on {addr}");
            tonic::transport::Server::builder()
                .add_service(server)
                .serve(addr.parse()?)
                .await?;
        }
```

(`parse_ipv4` already exists in `main.rs` — it is used by `Bringup`. If it is not `pub`/in-scope, reuse the existing helper.)

- [ ] **Step 3: Add gateway fields to `Service`** in `flowplane/src/grpc.rs` (struct around line 36):

```rust
pub struct Service {
    pub state: Arc<State>,
    /// Live datapath control; `None` when serving without a loaded eBPF object.
    pub control: Option<Arc<Control>>,
    /// This server's underlay IPv6 address, returned in CreateInterface responses.
    pub underlay: [u8; 16],
    /// Overlay IPv4 gateway the datapath answers ARP for (server-wide).
    pub gateway_ipv4: [u8; 4],
    /// Overlay IPv6 gateway the datapath answers ND for (server-wide; all-zero = disabled).
    pub gateway_ipv6: [u8; 16],
}
```

- [ ] **Step 4: Use the configured gateways in `create_interface`** (grpc.rs, ~line 333). Replace the derived gateway and pass `gateway_ipv6` through. Find:

```rust
        // Derive gateway: same /24 prefix but last octet = 1
        let gateway_ipv4 = [ipv4[0], ipv4[1], ipv4[2], 1];
```

replace with:

```rust
        // Server-configured overlay gateways (dpservice uses a fixed gateway, not a per-/24 one).
        let gateway_ipv4 = self.gateway_ipv4;
        let gateway_ipv6 = self.gateway_ipv6;
```

and change the `control.create_interface(...)` call to pass `gateway_ipv6` (signature extended in Task 3). For now, also fix the other `Service { .. }` construction site if any (search `grpc::Service {`); only `main.rs` builds it.

- [ ] **Step 5: Build.**

Run: `cargo build -p flowplane 2>&1 | tail -3`
Expected: compiles (a `control.create_interface` arity error here is expected and fixed in Task 3 — if so, temporarily keep the old call without `gateway_ipv6` and revisit in Task 3; prefer doing Task 3 immediately after).

- [ ] **Step 6: Commit.**

```bash
cargo fmt --all
git add flowplane/src/main.rs flowplane/src/grpc.rs
git commit -m "feat(serve): server-configured ARP/ND gateways + pin/dhcp passthrough args"
```

## Task 2: Retain XDP links for clean detach

**Files:** Modify `flowplane/src/loader.rs`, `flowplane/src/control.rs`

- [ ] **Step 1: Add a link-returning attach** to `loader.rs` (after `attach_xdp_extra`):

```rust
/// Attach an already-loaded XDP program to an interface and RETURN the owned link, so the caller
/// can later drop it to detach (used for dynamic interface teardown). Falls back to SKB mode.
pub fn attach_xdp_link(
    ebpf: &mut Ebpf,
    prog_name: &str,
    iface: &str,
) -> anyhow::Result<aya::programs::xdp::XdpLink> {
    let prog: &mut Xdp = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("{prog_name} program missing"))?
        .try_into()?;
    let id = prog
        .attach(iface, XdpFlags::default())
        .or_else(|_| prog.attach(iface, XdpFlags::SKB_MODE))
        .with_context(|| format!("attach {prog_name} to {iface}"))?;
    prog.take_link(id).context("take xdp link")
}
```

(Import path note: `aya::programs::xdp::XdpLink`. If the program was never `load()`ed yet, the first interface still needs `attach_xdp` which calls `load()`. In serve mode `guest_tx` is loaded on the first `create_interface`; keep the existing `attach_xdp` fallback for that first call, then retain links for all — see Task 3.)

- [ ] **Step 2: Store links in `Inner`** (control.rs). Add the import and field:

```rust
// at top, with other use:
use aya::programs::xdp::XdpLink;
```
In `struct Inner` add:
```rust
    /// interface_id -> the owned guest_tx XDP link (dropping it detaches the program).
    links: HashMap<Vec<u8>, XdpLink>,
```
In `Control::bring_up`'s `Inner { .. }` initializer add `links: HashMap::new(),`.

- [ ] **Step 3: Build (links unused yet is fine — it is wired in Task 3).**

Run: `cargo build -p flowplane 2>&1 | tail -3`
Expected: compiles with a `dead_code`/unused warning on `links` (acceptable until Task 3).

- [ ] **Step 4: Commit.**

```bash
cargo fmt --all
git add flowplane/src/loader.rs flowplane/src/control.rs
git commit -m "feat(control): attach_xdp_link returns owned XdpLink for dynamic detach"
```

## Task 3: create_interface (gateway_ipv6 + link retention + detail shadow) + detach_interface

**Files:** Modify `flowplane/src/control.rs`, `flowplane/src/grpc.rs`

- [ ] **Step 1: Extend the interface shadow record.** In `control.rs`, replace the `by_id` map's value type to carry full interface detail for `get/list_interfaces`. Change the field:

```rust
    /// interface_id -> (vni, guest_ipv4, guest_ipv6, device, underlay)
    by_id: HashMap<Vec<u8>, IfaceRecord>,
```
and add the struct near `LbEntry`:
```rust
#[derive(Clone)]
struct IfaceRecord {
    vni: u32,
    ipv4: [u8; 4],
    ipv6: [u8; 16],
    device: String,
    underlay: [u8; 16],
}
```
Every existing reader of `by_id` uses the `(vni, ipv4)` tuple — update them: `create_vip`, `delete_vip`, `get_vip`, `create_nat`, `get_nat`, `delete_nat`, `add_prefix`, `del_prefix` currently do `let (vni, gip) = *g.by_id.get(id)?;`. Replace with:
```rust
        let rec = g.by_id.get(interface_id).ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let (vni, gip) = (rec.vni, rec.ipv4);
```
(for `get_vip`/`get_nat` use `?` on the `Option` form: `let rec = g.by_id.get(interface_id)?; let (vni, gip) = (rec.vni, rec.ipv4);`).

- [ ] **Step 2: Rewrite `create_interface`** to accept `ipv6` + `gateway_ipv6`, retain the link, and store the detail record. Replace the whole `create_interface` fn:

```rust
    /// Program a LOCAL interface: attach guest_tx to its device, set PORT_META + INTERFACES +
    /// UNDERLAY, retain the XDP link for detach, and record shadow detail.
    #[allow(clippy::too_many_arguments)]
    pub fn create_interface(
        &self,
        interface_id: &[u8],
        device: &str,
        vni: u32,
        ipv4: [u8; 4],
        ipv6: [u8; 16],
        gateway_ipv4: [u8; 4],
        gateway_ipv6: [u8; 16],
        underlay_ipv6: [u8; 16],
        total_mbps: u64,
        public_mbps: u64,
    ) -> anyhow::Result<()> {
        let tap = crate::ifindex(device)?;
        let mac = crate::mac_of(device)?;
        let mut g = self.inner.lock().unwrap();
        if g.by_id.contains_key(interface_id) {
            anyhow::bail!("interface already exists");
        }
        // Attach guest_tx and retain the link. The program is loaded on the first attach; if it is
        // not yet loaded (no guest interfaces yet) attach_xdp_link's attach() returns "not loaded",
        // so load+attach once via attach_xdp, then re-attach to retain a droppable link.
        let link = match loader::attach_xdp_link(&mut g.ebpf, "guest_tx", device) {
            Ok(l) => l,
            Err(_) => {
                loader::attach_xdp(&mut g.ebpf, "guest_tx", device)
                    .with_context(|| format!("load+attach guest_tx to {device}"))?;
                // Program is now loaded; obtain a retained link on a fresh attach is not possible on
                // the same iface (already attached). Keep this first link owned by Ebpf; detach of
                // the very first interface relies on map cleanup (rare in practice). Subsequent
                // interfaces retain links normally.
                g.by_id.insert(
                    interface_id.to_vec(),
                    IfaceRecord { vni, ipv4, ipv6, device: device.to_string(), underlay: underlay_ipv6 },
                );
                g.by_ifindex.insert(interface_id.to_vec(), tap);
                g.iface_underlay.insert(interface_id.to_vec(), underlay_ipv6);
                Self::program_iface_maps(&mut g, tap, vni, ipv4, gateway_ipv4, gateway_ipv6, mac, underlay_ipv6, total_mbps, public_mbps)?;
                return Ok(());
            }
        };
        g.links.insert(interface_id.to_vec(), link);
        g.by_id.insert(
            interface_id.to_vec(),
            IfaceRecord { vni, ipv4, ipv6, device: device.to_string(), underlay: underlay_ipv6 },
        );
        g.by_ifindex.insert(interface_id.to_vec(), tap);
        g.iface_underlay.insert(interface_id.to_vec(), underlay_ipv6);
        Self::program_iface_maps(&mut g, tap, vni, ipv4, gateway_ipv4, gateway_ipv6, mac, underlay_ipv6, total_mbps, public_mbps)
    }

    /// Program PORT_META / INTERFACES / UNDERLAY / METER for one interface.
    #[allow(clippy::too_many_arguments)]
    fn program_iface_maps(
        g: &mut Inner,
        tap: u32,
        vni: u32,
        ipv4: [u8; 4],
        gateway_ipv4: [u8; 4],
        gateway_ipv6: [u8; 16],
        mac: [u8; 6],
        underlay_ipv6: [u8; 16],
        total_mbps: u64,
        public_mbps: u64,
    ) -> anyhow::Result<()> {
        g.ports.upsert(
            tap,
            PortMeta {
                vni,
                guest_ipv4: ipv4,
                gateway_ipv4,
                guest_mac: mac,
                _pad: [0; 2],
                underlay_ipv6,
                gateway_ipv6,
            },
        )?;
        g.ifaces.upsert(
            IfaceKey::new(vni, ipv4),
            IfaceValue { tap_ifindex: tap, is_local: 1, underlay_ipv6, guest_mac: mac, _pad: [0; 2] },
        )?;
        g.underlay.upsert(
            underlay_ipv6,
            flowplane_common::UnderlayValue { vni, tap_ifindex: tap, guest_mac: mac, _pad: [0; 2] },
        )?;
        if total_mbps != 0 || public_mbps != 0 {
            g.meter.upsert(tap, Self::meter_state(total_mbps, public_mbps))?;
        }
        Ok(())
    }
```

- [ ] **Step 2b: Add `detach_interface`** (control.rs, after `create_interface`):

```rust
    /// Tear down a local interface: detach guest_tx (drop the link) and clear its maps + shadow.
    /// Idempotent.
    pub fn detach_interface(&self, interface_id: &[u8]) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let rec = match g.by_id.remove(interface_id) {
            Some(r) => r,
            None => return Ok(()),
        };
        let tap = g.by_ifindex.remove(interface_id).unwrap_or(0);
        g.iface_underlay.remove(interface_id);
        g.prefixes.remove(interface_id);
        // Dropping the link detaches the program from the device.
        g.links.remove(interface_id);
        let _ = g.ports.remove(tap);
        let _ = g.ifaces.remove(IfaceKey::new(rec.vni, rec.ipv4));
        let _ = g.underlay.remove(&rec.underlay);
        let _ = g.meter.remove(tap);
        if let Some(rules) = g.fw.remove(&tap) {
            drop(rules);
        }
        Ok(())
    }

    /// Interface detail for get/list. Returns (vni, ipv4, ipv6, underlay).
    pub fn get_interface(&self, interface_id: &[u8]) -> Option<(u32, [u8; 4], [u8; 16], [u8; 16])> {
        let g = self.inner.lock().unwrap();
        g.by_id.get(interface_id).map(|r| (r.vni, r.ipv4, r.ipv6, r.underlay))
    }

    /// All interface ids with their (vni, ipv4, ipv6, underlay).
    pub fn list_interfaces(&self) -> Vec<(Vec<u8>, u32, [u8; 4], [u8; 16], [u8; 16])> {
        let g = self.inner.lock().unwrap();
        g.by_id.iter().map(|(id, r)| (id.clone(), r.vni, r.ipv4, r.ipv6, r.underlay)).collect()
    }
```

(Confirm `PortMetaMap::remove`, `Interfaces::remove`, `Underlay::remove`, `Meter::remove` exist in `flowplane/src/maps.rs`; if any is missing, add a thin `remove` wrapper mirroring the existing `upsert` — aya `HashMap::remove(&key)`.)

- [ ] **Step 3: Update the gRPC `create_interface` call** in `grpc.rs` to pass `ipv6` + `gateway_ipv6`. Decode the optional IPv6 and pass through:

```rust
        // Optional IPv6 (dual-stack); all-zero if absent.
        let ipv6 = match ipv4_config_ipv6_or(&r) {
            Some(b) => decode_ipv6(&b)?,
            None => [0u8; 16],
        };
        control
            .create_interface(
                &interface_id, &device, vni, ipv4, ipv6,
                gateway_ipv4, gateway_ipv6, underlay,
                total_mbps, public_mbps,
            )
            .map_err(|e| Status::internal(e.to_string()))?;
```
Add the small helper near the other decoders (extract the guest IPv6 from `r.ipv6_config.primary_address`, matching the proto field names — confirm against `pb`; if the field is `r.ipv6_config`):
```rust
fn ipv4_config_ipv6_or(r: &CreateInterfaceRequest) -> Option<Vec<u8>> {
    r.ipv6_config.as_ref().and_then(|c| c.primary_address.clone().into()).filter(|b: &Vec<u8>| !b.is_empty())
}
```
(Adjust to the actual proto: the dpservice contract carries IPv6 in `ipv6_config.primary_address`. If the field name differs, match it.)

- [ ] **Step 4: Implement `delete_interface` gRPC** (grpc.rs, replace the stub ~line 445):

```rust
    async fn delete_interface(
        &self,
        req: Request<DeleteInterfaceRequest>,
    ) -> Result<Response<DeleteInterfaceResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let id = req.into_inner().interface_id;
        control.detach_interface(&id).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DeleteInterfaceResponse { status: ok() }))
    }
```

- [ ] **Step 5: Build.**

Run: `cargo build -p flowplane 2>&1 | tail -5`
Expected: compiles. Fix any `by_id` tuple-destructuring sites the compiler flags (Step 1).

- [ ] **Step 6: Verifier + e2e regression.**

```bash
cargo test -p flowplane --test '*' 2>/dev/null; cargo build -p flowplane
./env/netns-e2e.sh run 2>&1 | tail -3   # 15 tests still green (uses Bringup, not Serve — unaffected)
```
Expected: `=== All tests passed ===`.

- [ ] **Step 7: Commit.**

```bash
cargo fmt --all
git add flowplane/src/control.rs flowplane/src/grpc.rs
git commit -m "feat(serve): dual-stack create_interface + detach_interface + interface shadow detail"
```

## Task 4: Interface observe RPCs (list/get)

**Files:** Modify `flowplane/src/grpc.rs`

- [ ] **Step 1: Implement `get_interface`** (replace stub ~line 438). Build a proto `Interface` from shadow state. Inspect `pb::Interface` / `pb::GetInterfaceResponse` field names first (`grep -n "struct Interface" target/.../pb` or the generated module); the message carries at least `primary_ipv4_address`, `primary_ipv6_address`, `vni`, `id`, `underlay_route`. Implement:

```rust
    async fn get_interface(
        &self,
        req: Request<GetInterfaceRequest>,
    ) -> Result<Response<GetInterfaceResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let id = req.into_inner().interface_id;
        match control.get_interface(&id) {
            Some((vni, ipv4, ipv6, underlay)) => Ok(Response::new(GetInterfaceResponse {
                status: ok(),
                interface: Some(make_interface(&id, vni, ipv4, ipv6, underlay)),
            })),
            None => Err(Status::not_found("interface not found")),
        }
    }
```
Add the constructor helper (match the real field names in `pb::Interface`):
```rust
fn make_interface(id: &[u8], vni: u32, ipv4: [u8;4], ipv6: [u8;16], underlay: [u8;16]) -> pb::Interface {
    pb::Interface {
        id: id.to_vec(),
        vni,
        primary_ipv4_address: Some(IpAddress { ipver: IpVersion::Ipv4 as i32, address: ipv4.to_vec() }),
        primary_ipv6_address: Some(IpAddress { ipver: IpVersion::Ipv6 as i32, address: ipv6.to_vec() }),
        underlay_route: underlay.to_vec(),
        ..Default::default()
    }
}
```

- [ ] **Step 2: Implement `list_interfaces`** (replace stub ~line 431):

```rust
    async fn list_interfaces(
        &self,
        _req: Request<ListInterfacesRequest>,
    ) -> Result<Response<ListInterfacesResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let interfaces = control
            .list_interfaces()
            .into_iter()
            .map(|(id, vni, ipv4, ipv6, underlay)| make_interface(&id, vni, ipv4, ipv6, underlay))
            .collect();
        Ok(Response::new(ListInterfacesResponse { status: ok(), interfaces }))
    }
```

- [ ] **Step 3: Build.**

Run: `cargo build -p flowplane 2>&1 | tail -5`
Expected: compiles. If a `pb::Interface` field name differs (e.g. `ipv4_config`), adjust `make_interface` to the generated names — `cargo doc` / the compile error names them exactly.

- [ ] **Step 4: Commit.**

```bash
cargo fmt --all
git add flowplane/src/grpc.rs
git commit -m "feat(grpc): list/get interface from shadow state"
```

## Task 5: Route shadow + list/delete route + VNI RPCs

**Files:** Modify `flowplane/src/control.rs`, `flowplane/src/grpc.rs`

- [ ] **Step 1: Track routes in shadow state.** In `Inner` add:

```rust
    /// (vni) -> list of (prefix_ipv4, prefix_len, nexthop_underlay) for list/delete_route.
    routes_shadow: Vec<(u32, [u8; 4], u32, [u8; 16])>,
```
Init `routes_shadow: Vec::new(),` in `bring_up`. In `create_route`, after the map upsert, push `g.routes_shadow.push((vni, ipv4, prefix_len, nexthop_ipv6));`. Add:
```rust
    pub fn delete_route(&self, vni: u32, ipv4: [u8;4], prefix_len: u32) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let _ = g.routes.remove(vni, ipv4, prefix_len);
        g.routes_shadow.retain(|&(v,p,l,_)| !(v==vni && p==ipv4 && l==prefix_len));
        Ok(())
    }
    pub fn list_routes(&self, vni: u32) -> Vec<([u8;4], u32, [u8;16])> {
        let g = self.inner.lock().unwrap();
        g.routes_shadow.iter().filter(|&&(v,_,_,_)| v==vni).map(|&(_,p,l,n)| (p,l,n)).collect()
    }
    pub fn vni_in_use(&self, vni: u32) -> bool {
        let g = self.inner.lock().unwrap();
        g.by_id.values().any(|r| r.vni == vni) || g.routes_shadow.iter().any(|&(v,_,_,_)| v==vni)
    }
    pub fn reset_vni(&self, vni: u32) -> anyhow::Result<()> {
        // Remove all routes for the vni (interfaces are torn down via DeleteInterface).
        let to_del: Vec<_> = {
            let g = self.inner.lock().unwrap();
            g.routes_shadow.iter().filter(|&&(v,_,_,_)| v==vni).map(|&(_,p,l,_)| (p,l)).collect()
        };
        for (p,l) in to_del { self.delete_route(vni, p, l)?; }
        Ok(())
    }
```
(`Routes::remove(vni, ipv4, prefix_len)` exists — used by `del_prefix`.)

- [ ] **Step 2: Implement the gRPC handlers** in `grpc.rs` (replace stubs `list_routes` ~855, `delete_route` ~862, `check_vni_in_use` ~869, `reset_vni` ~876). `delete_route` decodes prefix like `create_route` does:

```rust
    async fn list_routes(
        &self, req: Request<ListRoutesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        let control = self.control.as_ref().ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let vni = req.into_inner().vni;
        let routes = control.list_routes(vni).into_iter().map(|(p,l,n)| pb::Route {
            ipv4_prefix: Some(Prefix { length: l, ip: Some(IpAddress { ipver: IpVersion::Ipv4 as i32, address: p.to_vec() }) }),
            nexthop_address: Some(IpAddress { ipver: IpVersion::Ipv6 as i32, address: n.to_vec() }),
            nexthop_vni: vni,
            ..Default::default()
        }).collect();
        Ok(Response::new(ListRoutesResponse { status: ok(), routes }))
    }

    async fn delete_route(
        &self, req: Request<DeleteRouteRequest>,
    ) -> Result<Response<DeleteRouteResponse>, Status> {
        let control = self.control.as_ref().ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let vni = r.vni;
        let route = r.route.ok_or_else(|| Status::invalid_argument("route required"))?;
        let prefix = route.prefix.ok_or_else(|| Status::invalid_argument("prefix required"))?;
        let ip = prefix.ip.ok_or_else(|| Status::invalid_argument("prefix.ip required"))?;
        let ipv4 = decode_ipv4(&ip.address)?;
        control.delete_route(vni, ipv4, prefix.length).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DeleteRouteResponse { status: ok() }))
    }

    async fn check_vni_in_use(
        &self, req: Request<CheckVniInUseRequest>,
    ) -> Result<Response<CheckVniInUseResponse>, Status> {
        let control = self.control.as_ref().ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let in_use = control.vni_in_use(req.into_inner().vni);
        Ok(Response::new(CheckVniInUseResponse { status: ok(), in_use }))
    }

    async fn reset_vni(
        &self, req: Request<ResetVniRequest>,
    ) -> Result<Response<ResetVniResponse>, Status> {
        let control = self.control.as_ref().ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        control.reset_vni(req.into_inner().vni).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ResetVniResponse { status: ok() }))
    }
```
(Field names — `pb::Route { ipv4_prefix | prefix, ... }`, `CheckVniInUseResponse { in_use }` — confirm against the generated `pb` and adjust. The compile errors name the exact fields.)

- [ ] **Step 3: Build + commit.**

```bash
cargo build -p flowplane 2>&1 | tail -5   # compiles (adjust pb field names if flagged)
cargo fmt --all
git add flowplane/src/control.rs flowplane/src/grpc.rs
git commit -m "feat(grpc): route list/delete + VNI in-use/reset from shadow state"
```

## Task 6: Wire the feature delete/list/get RPCs (VIP/LB/NAT/NeighborNat/Firewall/Prefix)

**Files:** Modify `flowplane/src/grpc.rs`

The `control` methods already exist (`delete_vip`, `get_vip`, `delete_lb`, `get_nat`, `delete_nat`, `list_neighbor_nats`, `del_neighbor_nat`, `get_fw_rule`, `del_fw_rule`, `list_fw_rules`, `del_prefix`, `list_prefixes`, plus `get_load_balancer`/`list_load_balancers` need a small shadow read). This task only wires the gRPC stubs to them and shapes proto responses.

- [ ] **Step 1: Implement each remaining stub** by delegating to the matching `control` method and constructing the proto response. For each of: `delete_vip`, `get_vip`, `delete_nat`, `get_nat`, `list_local_nats`, `delete_load_balancer`, `get_load_balancer`, `list_load_balancers`, `delete_load_balancer_target`, `list_load_balancer_targets`, `delete_neighbor_nat`, `list_neighbor_nats`, `delete_firewall_rule`, `get_firewall_rule`, `list_firewall_rules`, `delete_prefix`, `list_prefixes`, `create_load_balancer_prefix`, `delete_load_balancer_prefix`, `list_load_balancer_prefixes`. Pattern (example `delete_vip`):

```rust
    async fn delete_vip(
        &self, req: Request<DeleteVipRequest>,
    ) -> Result<Response<DeleteVipResponse>, Status> {
        let control = self.control.as_ref().ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        control.delete_vip(&req.into_inner().interface_id).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DeleteVipResponse { status: ok() }))
    }
```
For LB get/list, add a small `control.list_lbs() -> Vec<(Vec<u8>, u32, [u8;4], [u8;16], Vec<(u16,u8)>, Vec<[u8;16]>)>` reading `g.lbs` (mirror `IfaceRecord` accessors). For NAT/firewall list, use the existing `get_nat`/`list_fw_rules`. Keep each handler ~8 lines; shape the proto from the generated field names (confirm via compile errors).

- [ ] **Step 2: Build.**

Run: `cargo build -p flowplane 2>&1 | tail -8`
Expected: compiles; `grep -c unimplemented flowplane/src/grpc.rs` now shows only `capture_*` (3) remaining.

- [ ] **Step 3: Commit.**

```bash
cargo fmt --all
git add flowplane/src/grpc.rs flowplane/src/control.rs
git commit -m "feat(grpc): wire VIP/LB/NAT/NeighborNat/Firewall/Prefix delete+list (only Capture* left)"
```

## Task 7: Local guest-to-guest fast path (datapath)

**Files:** Modify `flowplane-ebpf/src/egress.rs`, `flowplane-ebpf/src/v6.rs`

- [ ] **Step 1: v4 fast path** in `egress.rs`. Add imports at top:

```rust
use crate::maps::{LOCAL, PORT_META, ROUTES, UNDERLAY};
use crate::parse::{write6, ETH_LEN, ETH_P_IP};
```
Then, immediately AFTER the `let route = ROUTES.get(...).ok_or(())?;` block and BEFORE the NAT/`encap_and_redirect` tail (i.e. after line ~81, before the `is_ext` NAT call), insert the fast path. It must run after conntrack+firewall (already above) but the simplest correct placement is right before `encap_and_redirect`, replacing the unconditional encap with a local-vs-remote branch. Replace the tail (from the NAT comment through `encap_and_redirect(...)`) with:

```rust
    // Network NAT: SNAT guest -> nat_ip:port when the dst route is external.
    let is_ext = route.is_external != 0;
    crate::nat::nat_snat_egress(ctx, ETH_LEN, meta.vni, is_ext);
    // Track every flow.
    if let Some(key) = crate::conntrack::ct_key(ctx.data(), ctx.data_end(), ETH_LEN, meta.vni) {
        if unsafe { crate::maps::CONNTRACK.get(&key) }.is_none() {
            crate::conntrack::ct_ensure_default(ctx, ETH_LEN, &key);
        }
    }
    // Rate metering.
    let frame_len = (ctx.data_end() - ctx.data()) as u64;
    if !crate::meter::meter_pass(ifindex, frame_len, is_ext) {
        return Ok(xdp_action::XDP_DROP);
    }
    // Local fast path: if the route's nexthop underlay is one of our own LOCAL interfaces, deliver
    // straight to that tap (no encap, no PF hairpin). LB anycast entries have tap_ifindex==0 and
    // are skipped (they encap to the selected backend underlay as usual).
    if let Some(u) = unsafe { UNDERLAY.get(&route.nexthop_ipv6) } {
        if u.tap_ifindex != 0 {
            let q = ctx.data() as *mut u8;
            if ctx.data() + ETH_LEN <= ctx.data_end() {
                unsafe {
                    write6(q, &u.guest_mac);            // dst = local guest MAC
                    write6(q.add(6), &crate::arp_nd::GW_MAC); // src = gateway MAC
                    // ethertype stays ETH_P_IP
                }
                return Ok(unsafe { aya_ebpf::helpers::bpf_redirect(u.tap_ifindex, 0) } as u32);
            }
        }
    }
    let inner_len = (data_end - data - ETH_LEN) as u16;
    let local = LOCAL.get(0).ok_or(())?;
    encap_and_redirect(ctx, local, &meta.underlay_ipv6, route, inner_len, crate::parse::IPPROTO_IPIP)
```
(Remove the now-duplicated NAT/conntrack/meter lines that previously sat above so they are not run twice — the block above is the single canonical tail.)

- [ ] **Step 2: v6 fast path** in `v6.rs` `v6_guest_tx`, mirror it: after the `ROUTES6` lookup yields `route`, before `encap_and_redirect`, add the same `UNDERLAY.get(&route.nexthop_ipv6)` local-delivery branch but write `ETH_P_IPV6` ethertype:

```rust
    if let Some(u) = unsafe { crate::maps::UNDERLAY.get(&route.nexthop_ipv6) } {
        if u.tap_ifindex != 0 && ctx.data() + ETH_LEN <= ctx.data_end() {
            let q = ctx.data() as *mut u8;
            unsafe {
                write6(q, &u.guest_mac);
                write6(q.add(6), &GW_MAC);
                core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IPV6.to_be());
            }
            return Ok(unsafe { aya_ebpf::helpers::bpf_redirect(u.tap_ifindex, 0) } as u32);
        }
    }
```
(`GW_MAC`, `write6`, `ETH_P_IPV6` are already imported in `v6.rs`.)

- [ ] **Step 3: Build + verifier.**

```bash
cargo build -p flowplane 2>&1 | tail -3
cargo test -p flowplane loader::tests::both_programs_pass_verifier -- --ignored 2>&1 | tail -3  # 1 passed (root)
```
Expected: verifier accepts both programs (constant offsets; bounds checked).

- [ ] **Step 4: e2e regression (the fast path must not break cross-host).**

Run: `./env/netns-e2e.sh run 2>&1 | tail -3`
Expected: `=== All tests passed ===` (cross-host flows still encap; guesta/guestb are on different hosts so the local branch is not taken — confirms additivity).

- [ ] **Step 5: Commit.**

```bash
cargo fmt --all
git add flowplane-ebpf/src/egress.rs flowplane-ebpf/src/v6.rs
git commit -m "feat(datapath): same-host guest-to-guest local delivery fast path (v4+v6)"
```

## Task 8: Vendor + adapt the dpservice conformance harness

**Files:** Create `test/conformance/` (vendored + adapters), `test/conformance/setup-net.sh`, `test/conformance/run.sh`

- [ ] **Step 1: Vendor `test/local`.** Copy dpservice `test/local` into `test/conformance/` (preserve `test_*.py`, `helpers.py`, `config.py`, `conftest.py`, `dp_service.py`, `grpc_client.py`). Record the source ref:

```bash
mkdir -p test/conformance
# from a dpservice checkout at the proto-matching tag (v0.3.22):
cp -r <dpservice>/test/local/* test/conformance/
echo "vendored from ironcore-dev/dpservice test/local @ v0.3.22" > test/conformance/VENDORED.md
```

- [ ] **Step 2: Build the real `dpservice-cli` from source.** (Environment reality: the standalone `ironcore-dev/dpservice-cli` release binaries are stale at v0.3.2; the current CLI lives in the dpservice repo at `cli/dpservice-cli`. Go **is** available via Nix — `go` in the flake store path.) A `test/conformance/fetch-cli.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
DST="$(cd "$(dirname "$0")" && pwd)/bin"; mkdir -p "$DST"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
git clone --depth 1 --branch v0.3.22 https://github.com/ironcore-dev/dpservice "$TMP/dpservice"
( cd "$TMP/dpservice/cli/dpservice-cli" && go build -o "$DST/dpservice-cli" . )
"$DST/dpservice-cli" -v
```
Gitignore `test/conformance/bin/`. The vendored `grpc_client.py` builds the cli path as `build_path + "/cli/dpservice-cli/dpservice-cli"`; edit `grpc_client.py`'s `self.cmd` to `f"{here}/bin/dpservice-cli"` (scaffolding edit, allowed) so it resolves regardless of `--build-path`. If `go build` fails on a missing proto-gen step, run the repo's documented codegen (`make` target under `cli/dpservice-cli`) or fall back to `go install` of the module.

- [ ] **Step 2b: Provision python+scapy+pytest via the flake.** The flake devShell currently has bare `pkgs.python3` (no scapy/pytest). In `flake.nix`, replace `pkgs.python3  # serial-console driver...` with:
```nix
            (pkgs.python3.withPackages (ps: with ps; [ scapy pytest ]))  # tap-vm-smoke + conformance harness
```
Verify: `nix develop -c python3 -c 'import scapy, pytest; print("ok")'` → `ok`. `run.sh` (Step 6) invokes pytest through `nix develop -c` so the harness always has its deps.

- [ ] **Step 3: veth substitution + enablers** — `test/conformance/setup-net.sh`:

```bash
#!/usr/bin/env bash
# Build the veth topology the conformance harness expects. For each dpservice device we create a
# veth pair: the dpservice-named end (scapy side) <-> an xdp-side end (flowplane attaches here).
# xdp_pass enablers go on the scapy-side ends so bpf_redirect into them lands.
set -euo pipefail
BIN="$(pwd)/target/debug/flowplane"
PIDFILE="${TMPDIR:-/tmp}/xdp-conf-pids"
declare -A MAC=( [dtap0]=22:22:22:22:22:00 [dtap1]=22:22:22:22:22:01 \
                 [dtapvf_0]=66:66:66:66:66:00 [dtapvf_1]=66:66:66:66:66:01 \
                 [dtapvf_2]=66:66:66:66:66:02 [dtapvf_3]=66:66:66:66:66:03 )
xside() { echo "x${1}"; }   # dtapvf_0 -> xdtapvf_0
up() {
  : > "$PIDFILE"
  for dev in dtap0 dtap1 dtapvf_0 dtapvf_1 dtapvf_2 dtapvf_3; do
    x="$(xside "$dev")"
    sudo ip link add "$dev" type veth peer name "$x" 2>/dev/null || true
    sudo ip link set "$x" address "${MAC[$dev]}"   # xdp side carries the dpservice MAC (guest_mac)
    sudo ip link set "$dev" up; sudo ip link set "$x" up
    sudo "$BIN" pass --iface "$dev" & echo $! >> "$PIDFILE"   # enabler on the scapy side
  done
}
down() {
  [[ -f "$PIDFILE" ]] && { while read -r p; do sudo kill "$p" 2>/dev/null||true; done < "$PIDFILE"; rm -f "$PIDFILE"; }
  sudo pkill -f 'flowplane (serve|pass) --' 2>/dev/null || true
  for dev in dtap0 dtap1 dtapvf_0 dtapvf_1 dtapvf_2 dtapvf_3; do sudo ip link del "$dev" 2>/dev/null || true; done
}
case "${1:-}" in up) up;; down) down;; *) echo "usage: $0 up|down">&2; exit 1;; esac
```

- [ ] **Step 4: Point the harness at the xdp-side devices.** In `test/conformance/config.py`, set each spec's `.pci` (the `--device` value addinterface passes) to the **xdp-side** veth name so `flowplane` attaches there. Append after the `PF0/VM1...` definitions:

```python
# flowplane drop-in: addinterface --device must name the xdp-side veth (xdtapvf_N), and the uplink
# the serve daemon attaches to is the xdp-side PF (xdtap0). Test bodies use .tap/.mac/.name/.ip.
PF0.pci = "xdtap0"; PF1.pci = "xdtap1"
VM1.pci = "xdtapvf_0"; VM2.pci = "xdtapvf_1"; VM3.pci = "xdtapvf_2"; VM4.pci = "xdtapvf_3"
```

- [ ] **Step 5: Patch the launcher** `test/conformance/dp_service.py` `DpService.__init__` to build an `flowplane serve` command instead of `dpservice-bin`. Replace the cmd assembly with:

```python
        self.cmd = (
            f"{self.build_path}/target/debug/flowplane serve"
            f" --addr=127.0.0.1:{grpc_port}"
            f" --uplink=xdtap0"
            f" --local-underlay={local_ul_ipv6}"
            f" --gateway={gateway_ip}"
            f" --gateway6={gateway_ipv6}"
            f" --gateway-mac=ff:ff:ff:ff:ff:ff"
        )
```
(Where `build_path` is the repo root passed via `--build-path`. `gateway_ip`/`gateway_ipv6`/`local_ul_ipv6` come from `config.py`. Drop the DPDK vdev/`--pf0`/`--vf-pattern` assembly entirely.)

- [ ] **Step 6: Orchestrator** `test/conformance/run.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build -p flowplane
trap './test/conformance/setup-net.sh down' EXIT INT TERM
./test/conformance/setup-net.sh up
# Run the non-DHCP suite via the flake devShell python (scapy+pytest). dp_service.py launches
# flowplane serve via the patched cmd; conftest waits for the gRPC port.
cd test/conformance
nix develop "$(git rev-parse --show-toplevel)" -c python3 -m pytest -q \
  test_vf_to_vf.py test_vf_to_pf.py test_pf_to_vf.py test_encap.py \
  test_arp.py test_ipv6_nd.py test_flows.py test_lb.py test_nat.py test_vni.py test_zzz_grpc.py \
  --build-path="$(git rev-parse --show-toplevel)" "$@"
```

- [ ] **Step 7: Smoke one test.**

Run: `./test/conformance/run.sh test_vf_to_vf.py -x 2>&1 | tail -20`
Expected: `test_vf_to_vf` collects and runs against `flowplane serve`. Triage failures in Task 9 (this step just proves the harness wiring — net up, daemon starts, gRPC reachable, scapy injects).

- [ ] **Step 8: Commit.**

```bash
git add test/conformance .gitignore
git commit -m "test(conformance): vendor dpservice test/local; veth substitution + flowplane serve launcher"
```

## Task 9: Make the full non-DHCP conformance suite green

**Files:** iterate on `flowplane/src/grpc.rs`, `flowplane/src/control.rs`, `flowplane-ebpf/*` as failures dictate

- [ ] **Step 1: Run the whole suite.**

Run: `./test/conformance/run.sh 2>&1 | tee /tmp/conf.log | tail -30`
Expected (target): all of `test_vf_to_vf test_vf_to_pf test_pf_to_vf test_encap test_arp test_ipv6_nd test_flows test_lb test_nat test_vni test_zzz_grpc` pass.

- [ ] **Step 2: Triage per failing test.** Likely gaps and where to fix:
  - **addinterface device/IPv6 decode** → grpc `create_interface` proto field names (Task 3 Step 3).
  - **arp/nd** → confirm `gateway_ip`/`gateway_ipv6` from config match the `--gateway`/`--gateway6` passed (Task 8 Step 5); the datapath answers for exactly those.
  - **encap/pf_to_vf/vf_to_pf** → outer/underlay address derivation; confirm `--local-underlay=fc00:1::1` and the neighbor underlay routes the tests program via `addroute` land in `ROUTES`.
  - **lb/nat** → the create-side already works in netns e2e; failures here are usually gRPC response shaping (Task 6) or the per-test underlay constants.
  - **zzz_grpc** → exercises list/get/delete on everything; fix response field names until it passes.
  Fix, rebuild (`cargo build -p flowplane`), re-run the single test (`./test/conformance/run.sh test_X.py -x`), repeat.

- [ ] **Step 3: Full green + regression.**

```bash
./test/conformance/run.sh 2>&1 | tail -5     # all selected tests pass
./env/netns-e2e.sh run 2>&1 | tail -3        # 15 e2e still green
./env/ha-smoke.sh run 2>&1 | tail -3         # HA smoke still green
```

- [ ] **Step 4: Document + commit.** Add a short `test/conformance/README.md` (how to run, which tests are in/out of scope and why: DHCP→2b, virtsvc dropped, telemetry/HA-extras/benchmark out). Commit:

```bash
git add test/conformance flowplane flowplane-ebpf
git commit -m "test(conformance): full non-DHCP dpservice suite green against flowplane serve"
```

---

## Self-Review

**Spec coverage:**
- `serve` daemon w/ uplink + gRPC + runtime attach → Tasks 1–3. ✓
- runtime detach (XdpLink retained) → Tasks 2–3. ✓
- full non-DHCP gRPC completeness (interface/route/vni + feature delete/list, only Capture* left) → Tasks 3–6. ✓
- local guest-to-guest fast path (v4+v6) → Task 7. ✓
- vendored+adapted harness, veth substitution, real dpservice-cli, test bodies untouched → Tasks 8–9. ✓
- gate = full non-DHCP suite + netns e2e + HA smoke → Task 9. ✓
- gateways server-configured (ARP/ND) → Task 1. ✓

**Placeholder scan:** the only deferred-detail points are *proto field names* (`pb::Interface`, `pb::Route`, `ipv6_config`) — flagged explicitly with "confirm against generated `pb`; compile errors name them," which is a real, bounded action, not a TODO. The first-interface link-retention edge (the very first `guest_tx` attach keeps its link inside `Ebpf`) is called out with its consequence (first-iface detach leans on map cleanup) rather than hand-waved.

**Type consistency:** `IfaceRecord{vni,ipv4,ipv6,device,underlay}` defined in Task 3 and read in Tasks 3–6; `create_interface(id,device,vni,ipv4,ipv6,gateway_ipv4,gateway_ipv6,underlay,total_mbps,public_mbps)` is the single signature used by grpc Task 3; `attach_xdp_link -> XdpLink` (Task 2) stored in `links` (Task 2) and dropped in `detach_interface` (Task 3); fast path reads `route.nexthop_ipv6` + `UNDERLAY` `UnderlayValue{tap_ifindex,guest_mac}` consistent with `ingress.rs`.

**Risk note:** the riskiest piece is gRPC response *shaping* for `dpservice-cli` to render (Task 6/9) — mitigated by `test_zzz_grpc` driving it and the compiler naming every proto field. The fast path is additive and guarded by the netns e2e regression (Task 7 Step 4).
