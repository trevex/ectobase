# flowplane engineering review — 2026-09-08

Holistic review of the Rust `flowplane/` workspace (7 crates, ~37k lines incl. tests) across five
dimensions: comment quality, module structure, resilience & safety, idiomatic Rust, over-engineering.
Read-only pass — nothing changed. Go `mesh/`/`cni/` are a separate follow-up.

## Overall posture

**Healthy and lean, not bloated.** The 7-crate split is a clean acyclic DAG (`common → core → ebpf`;
`common → control`; `device` standalone; `flowplane` binary at the apex; `sim` reusing `core`/`common`),
and the three traits (`Pkt`, `Maps`, `MapWriter`) are all multiply-instantiated and load-bearing — they
let the exhaustive native sim run the *same* logic as the compiled eBPF. The security boundary
(firewall) is deny-by-default with full v4/v6 × ingress/egress parity; concurrency is disciplined (all
`Control` mutation under `spawn_blocking` + sync locks, no lock held across `.await`, acyclic
`inner → conntrack` ordering); every `unsafe` block has a correct SAFETY comment. **No Critical crash
path or fail-open bug was found.**

The real work is **cleanup, not redesign**, and it clusters into four themes:
1. **Comment history-cruft** — ~224 production comment lines narrate the refactor history (`P2`, `B7c`,
   commit SHAs) instead of documenting current behavior. *(Your top-stated concern.)*
2. **God-files** — a handful of 1.1k–1.7k-line modules concentrate what the crate split otherwise keeps
   clean; the `flowplane-control` crate is the reference-quality pattern to extend.
3. **A few real safety/resilience gaps** — production `unwrap`s, stringly-typed gRPC errors, unsupervised
   background tasks.
4. **Modest dead code + one boilerplate file.**

---

## P0 — do first (safety fixes + cheap, safe wins)

| # | Item | Location | Action |
|---|------|----------|--------|
| P0.1 | `create_dir_all(path.parent().unwrap()).ok()` — panics on parent-less path AND swallows mkdir error | `flowplane/src/loader.rs:317,356,556` | `if let Some(p)=path.parent() { create_dir_all(p).with_context(...)?; }` |
| P0.2 | `backends.get_mut(&tid).unwrap()` panics on malformed `--lb-target` ordering | `flowplane/src/main.rs:1096` | `.entry(tid).or_default()` |
| P0.3 | ~30 needless proto-`String` clones per RPC (cloned only to `println!` after `r` moves into `spawn_blocking`) | `flowplane/src/node.rs` (~146–486) | format the log line before the move, or log inside the closure — **single highest-value idiomatic fix** |
| P0.4 | Dead code (delete) | `maps.rs:498 NatCt6::from_pin`; `parse.rs:89 parse_ipv4`; `flowplane-control/src/lib.rs:100 iface_meta_rows`; `flowplane-sim/src/fabric.rs:61 node_mut`; dead `control/mod.rs:171 geneve_ifindex: u32` field | delete all (verified unreferenced workspace-wide) |
| P0.5 | Unused dependencies | `flowplane/Cargo.toml:22 uuid`; `flowplane-ebpf/Cargo.toml:12 network-types` (+ its orphan copy in root `[workspace.dependencies]`) | drop |
| P0.6 | Stale/misleading `#[allow(dead_code)]` + "not used by the daemon" docs on items that ARE used in production | `maps.rs:40,77,83` (`Interfaces::get`/`Interfaces6::get`/`entries` — reached via `MapWriter` + `control/mod.rs:718`) | remove the attrs + fix the docs |
| P0.7 | Naming inversion: the **used** handle is `_geneve_ifindex` (underscore) while the **dead** `geneve_ifindex` is un-prefixed | `control/mod.rs:168,171` | delete the dead field (P0.4), drop the underscore on the live one |

P0 is ~a half-day, near-zero-risk, and removes every current build warning + two panic classes.

---

## P1 — high value (the user's priorities: comments + structure + resilience)

### P1.1 — Comment cleanup (your top concern)
~224 production cruft lines; 5 files hold >100 of them and sit on the hot datapath:
`flowplane-core/src/datapath.rs` (50), `flowplane-ebpf/src/ingress.rs` (16),
`flowplane-common/src/lib.rs` (16), `flowplane-core/src/conntrack.rs` (12), `flowplane/src/control/mod.rs` (12).
**Style guide to adopt** (and enforce in review):
- Document current behavior + invariants; a comment must read correctly to someone who never saw a diff.
- **No** commit SHAs, phase/task IDs (`P2`, `B7c`, `Task 4b`, `7a9a962`, "spike").
- **Ban evolution verbs**: "used to", "no longer", "formerly", "moved out", "was tried first". If the old
  code is gone, there's nothing to say about it.
- Keep the *conclusion* of a WHY, drop the archaeology: "Not `#[inline(never)]` because it keeps the eBPF
  call chain under the verifier's stack budget" ✅ — the 6-clause version narrating what was tried ❌.
- **Keep** genuine `SAFETY:` comments (all ~30 are good), and the 3 real current-state `KNOWN LIMITATION`
  caveats (`attach.rs:781` VF-reclaim, `lb.rs:161` PMTUD gap, `offload.rs` flush seam). Cut the one
  test-file `DEVIATION` that references a planning doc.

### P1.2 — Split the god-files (extend the `flowplane-control` pattern)
| File (lines) | Split into |
|---|---|
| `core/datapath.rs` (1579) | `hooks/{uplink,guest_tx,nat64,wan_rx,guest_local}.rs`; rename existing helper `uplink.rs`→`decap.rs` to end the hook-vs-helper name overlap |
| `flowplane/src/main.rs` (1704) | `cli/{serve,bringup,tc_bringup,inspect}.rs` (each `fn run(args)`); `main.rs` keeps only clap defs + dispatch; move `parse_mac/ipv4/ipv6` into the existing `parse.rs` |
| `common/src/lib.rs` (1277) | `maps/{iface,route,lb,nat,ct,fw,dhcp}.rs`; move `fw_rule_matches`/`_6` (logic hiding in a types crate) into `firewall.rs`; keep `wire`/`csum` |
| `control/mod.rs` (1159) | `control/bringup.rs` (bring_up/attach_edge) + `control/recover.rs` (rebuild_from_maps/reattach); leave the `Control` struct + lookups in `mod.rs` |
| `attach.rs` (1144) | extract `attach/naming.rs` (deterministic name/MAC derivation — the bulk of the tests) + `attach/tap.rs` |

### P1.3 — Typed errors at the gRPC boundary
Every attach/detach failure → `Status::internal(string)` (`node.rs:62,66,90`), so a `ROUTE_EXISTS`
**client conflict** is indistinguishable from a transient fault — the CNI substring-matches messages and
gRPC clients auto-retry `Internal` (wrong for a conflict). Introduce a `thiserror` enum
(`Conflict/NotFound/Invalid/Internal`) at the attach/control boundary → map to
`AlreadyExists/NotFound/InvalidArgument/Internal`. Bonus: removes the per-line `.map_err(invalid/internal)`
boilerplate in `handlers.rs` via `impl From<Error> for Status`.

### P1.4 — Supervise background tasks
`tokio::spawn` of `conntrack_gc::run` / `offload::run` (`main.rs:601,616,…`) drops the `JoinHandle`; a
panic in either infinite loop dies **silently** (GC halt → CONNTRACK fills → new-flow inserts fail, a
slow undiagnosable degradation). Wrap the loop body to log+restart on panic, or retain handles and
abort the process on unexpected exit.

### P1.5 — `maps.rs` boilerplate → macro
832 lines, 31 near-identical map wrappers; ~25 are pure `open/upsert/remove/get/entries` boilerplate.
A `macro_rules! bpf_hash_map!/bpf_array_map!` cuts it to ~250–300 lines; hand-keep the ~6 with real
logic (`Routes`/`Routes6` LPM, `NatIps`/`6` re-keying, `Conntrack`/`NatCt6`).

### P1.6 — Reject mixed-family firewall rules
`handlers.rs:329-337` a rule with v4 `src` + v6 `dst` takes the V6 branch and zero-fills the other side
to `::/0` — silently **widens** policy. Reject family mismatch with `invalid_argument`.

---

## P2 — polish

- **Stringly-typed CLI → `clap::ValueEnum`**: `role` (`main.rs:548`), `direction`/`action`/`proto`
  (`main.rs:1174,1179,1184`). `DeviceType::parse` (`attach.rs:69`) is the good precedent to follow.
- **Consolidate checksum helpers**: 4 duplicate private fns reimplement the RFC1071 fold + big-endian
  add across `arp_nd.rs`/`dhcp.rs`/`nat64.rs` — move `fold(u32)->u16` + `add_be16` next to the existing
  `csum_replace*` in `conntrack.rs`; unit-test once.
- **Naming consistency**: `entries()` vs `iface_meta_entries()` vs `iface_meta_rows()` for "dump map"
  → standardize on `entries`; the `control/lib.rs:105` 6-tuple `#[allow(type_complexity)]` → named struct.
- **Dedup helper**: `v4_in_16(Ipv4Addr)->[u8;16]` shared by the handlers' v4/v6 arms (`handlers.rs:228`).
- **Device crate tidy**: promote `flower.rs`'s generic `nl` submodule → `flowplane-device/src/nl.rs`
  (shared by veth/netkit/tap/underlay); rename `flowplane-device/src/grpc.rs` (a 40-line uds-path parser,
  no gRPC) → `addr.rs` or move into `cli/serve.rs`.
- **Minor `unwrap`/`assert` misuse-guards** → errors: `tap.rs:49` name-length assert; `main.rs:1096`
  (covered P0.2); `loader.rs` mkdir (covered P0.1).

## Explicitly NOT recommended
- **v4/v6 datapath unification** (`datapath.rs`, `conntrack.rs`, `nat.rs` parallel `_v6` fns): the
  largest duplication cluster, but justified — 4- vs 16-byte addresses, v4-only IP checksum, and
  monomorphized fixed-size code the eBPF verifier can prove. Const-generic unification adds verifier
  risk for little gain. Leave it.
- The `Pkt`/`Maps`/`MapWriter` traits, the enum set, and the hand-rolled checksums (no crate works in the
  verifier) are all justified — not over-engineering.

---

## Suggested sequencing
1. **P0** (½ day, zero-risk): delete dead code + unused deps, fix the two panic classes, kill the
   node.rs clone storm, clear the stale `#[allow]`s. Removes all build warnings.
2. **P1.1 comment sweep** (mechanical, high reader-value) — the 5 hot files first, then the rest, under
   the new style guide.
3. **P1.2 god-file splits** (one file at a time, tests green between each).
4. **P1.3/P1.4** (typed errors + task supervision) — the two genuine resilience upgrades.
5. **P1.5/P1.6 + P2** as capacity allows.
