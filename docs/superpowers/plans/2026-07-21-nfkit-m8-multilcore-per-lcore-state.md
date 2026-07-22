# nfkit M8 — multi-lcore datapath + per-lcore state + symmetric RSS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the shared-nothing per-lcore state model — N worker lcores each running `process_uplink` over their own `DpdkMaps`, concurrently, byte-parity + conntrack isolation — plus the symmetric-Toeplitz RSS key whose symmetry (fwd/rev 5-tuple → same lcore) is unit-tested without hardware.

**Architecture:** nfkit-only (no `flowplane-core`/eBPF change). (1) Make `DpdkMaps` per-lcore-instantiable via unique rte_hash names. (2) A `--no-huge` multi-lcore test: `LcoreRuntime::for_each_worker` launches workers, each builds its own `DpdkMaps` + processes an in-process batch through `process_uplink`; main thread asserts per-lcore byte-parity + CT isolation. (3) A symmetric RSS key set in `Port::configure` + a pure-Rust Toeplitz symmetry test.

**Tech Stack:** Rust, `nfkit` (M2/M3), DPDK `rte_eal_remote_launch`/`rte_hash`. All tests `--no-huge`, `--test-threads=1`, inside `nix develop`.

**Context (grounded — I read these):**
- `DpdkMaps::new(socket_id)` (`flowplane/nfkit/src/dpdk_maps.rs:103`) creates 12 hashes with FIXED names (`"dm_ct"`,`"dm_underlay"`,`"dm_fw_meta"`,`"dm_fw_rules"`,`"dm_lb"`,`"dm_maglev"`,`"dm_nat"`,`"dm_nat_ips"`,`"dm_route4"`,`"dm_route6"`,`"dm_dhcp_meta"`,`"dm_meter"`) → a 2nd coexisting instance fails `rte_hash_create` (names are process-global). `DpdkHash::new(name: &str, entries, socket_id)` copies the name into a `CString`, so a temporary `&format!(...)` is fine. Caps: `CAP_CT` (conntrack), `CAP_STD` (rest).
- `LcoreRuntime::for_each_worker(n_workers: u16, func: F) where F: Fn(u16) + Sync` (`flowplane/nfkit/src/runtime.rs:39`) — runs `func(queue_id)` on the first `n_workers` worker lcores and JOINS (mp_wait_lcore) before returning. A worker panic ABORTS (M2 trampoline) — so do NOT `assert!` inside a worker; record into a result slot and assert after join. `worker_lcore_count()` = total EAL lcores − 1.
- `Mempool` is `Send+Sync` (M2); `rte_pktmbuf_alloc` is MT-safe → one shared pool, workers alloc concurrently.
- `process_uplink<P,M>(pkt, maps, &UplinkIn) -> Action` + `MbufPkt::new(&mut Mbuf)` + `Mbuf` load pattern: see `flowplane/nfkit/tests/parity_uplink.rs` (`run_dpdk`: `pool.alloc()`, `mb.append(len)`, `mb.data_mut().copy_from_slice(frame)`, `MbufPkt::new(&mut mb)`, `process_uplink(...)`, `mp_bytes`). Fixture builders `inner_frame`/`encap_to`/`allow_meta`/`allow_rule` + consts (`VNI=100`,`TAP=42`,`GUEST_MAC`,`GUEST_IP=[10,0,0,10]`,`EXT_IP`,`HOST_UL`) are in `parity_uplink.rs` AND `datapath_pcap.rs` — copy them.
- `Port::configure` (`flowplane/nfkit/src/port.rs:46-53`) sets `conf.rx_adv_conf.rss_conf.rss_hf` when `nq>1`; add the symmetric `rss_key` there. `rss_conf.rss_key` bindgen type is `*mut u8`.
- EAL multi-lcore + rte_hash work `--no-huge` (M2 `runtime.rs`, M3 `dpdk_hash.rs`). Use `-l 0-2` for 2 workers.

**Absolute rules:**
- Cargo inside `nix develop --command bash -c 'cd /home/nik/Development/ironcore-net-xdp/flowplane && <cmd>'`.
- Commit from repo root: `cd /home/nik/Development/ironcore-net-xdp && git ...`.
- rustfmt pre-commit hook active; if the rustup `cargo fmt` shim prints usage, format touched files with `rustfmt --edition 2021 <files>`.
- Each task ends green; run the FULL `cargo test -p nfkit -- --test-threads=1` before the final commit to confirm no regression in the M3–M7 anchors.

---

## File Structure
- `flowplane/nfkit/src/dpdk_maps.rs` — unique per-instance hash names (AtomicU32).
- `flowplane/nfkit/tests/dpdk_maps.rs` — `+ two coexisting instances are isolated`.
- `flowplane/nfkit/tests/multilcore_datapath.rs` — new.
- `flowplane/nfkit/src/rss.rs` — new (`SYMMETRIC_RSS_KEY`, `toeplitz_softrss`, `rss_queue`).
- `flowplane/nfkit/src/port.rs` — set the symmetric rss_key in `configure`.
- `flowplane/nfkit/src/lib.rs` — `mod rss; pub use ...`.
- `flowplane/nfkit/tests/rss_symmetry.rs` — new.

---

## Task 1: Per-lcore-instantiable `DpdkMaps` (unique rte_hash names)

**Files:** Modify `flowplane/nfkit/src/dpdk_maps.rs`, `flowplane/nfkit/tests/dpdk_maps.rs`.

- [ ] **Step 1: Write the failing coexistence test** — append to `flowplane/nfkit/tests/dpdk_maps.rs` (into the EXISTING `#[test]` that already inits EAL — read the file; EAL inits once):
```rust
    // Two DpdkMaps must coexist (per-lcore instantiation) — previously the fixed hash names collided.
    let mut a = DpdkMaps::new(0).expect("maps A");
    let mut b = DpdkMaps::new(0).expect("maps B"); // must NOT fail on a name clash
    let ka = CtKey { vni: 1, src_ip: [10, 0, 0, 1], dst_ip: [10, 0, 0, 2], src_port: 1, dst_port: 2, proto: 6, _pad: [0; 3] };
    let kb = CtKey { vni: 9, src_ip: [10, 0, 0, 9], dst_ip: [10, 0, 0, 8], src_port: 9, dst_port: 8, proto: 6, _pad: [0; 3] };
    a.conntrack_insert(ka, CtEntry::default());
    assert!(a.conntrack_get(&ka).is_some());
    assert!(b.conntrack_get(&ka).is_none(), "A's flow must not appear in B (shared-nothing)");
    b.conntrack_insert(kb, CtEntry::default());
    assert!(b.conntrack_get(&kb).is_some());
    assert!(a.conntrack_get(&kb).is_none());
```
(Match `CtKey`/`CtEntry` field layout to `flowplane-common` — read it; use the same construction style the file already uses. Import `Maps` if needed for `conntrack_*`.) Run to FAIL (`DpdkMaps::new(0)` twice → `rte_hash_create` name collision → the 2nd `expect` panics).

- [ ] **Step 2: Make hash names unique per instance** — in `flowplane/nfkit/src/dpdk_maps.rs`, add at the top:
```rust
use std::sync::atomic::{AtomicU32, Ordering};
static NEXT_INSTANCE: AtomicU32 = AtomicU32::new(0);
```
Rewrite `DpdkMaps::new` to suffix every hash name with a fresh instance id (keep names short for `RTE_HASH_NAMESIZE`=32):
```rust
    pub fn new(socket_id: i32) -> Result<Self, HashError> {
        let n = NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            local: None,
            dhcp_config: None,
            conntrack: DpdkHash::new(&format!("dm_ct_{n}"), CAP_CT, socket_id)?,
            underlay: DpdkHash::new(&format!("dm_ul_{n}"), CAP_STD, socket_id)?,
            fw_meta: DpdkHash::new(&format!("dm_fm_{n}"), CAP_STD, socket_id)?,
            fw_rules: DpdkHash::new(&format!("dm_fr_{n}"), CAP_STD, socket_id)?,
            lb: DpdkHash::new(&format!("dm_lb_{n}"), CAP_STD, socket_id)?,
            maglev: DpdkHash::new(&format!("dm_mg_{n}"), CAP_STD, socket_id)?,
            nat: DpdkHash::new(&format!("dm_nat_{n}"), CAP_STD, socket_id)?,
            nat_ips: DpdkHash::new(&format!("dm_ni_{n}"), CAP_STD, socket_id)?,
            route4: DpdkHash::new(&format!("dm_r4_{n}"), CAP_STD, socket_id)?,
            route6: DpdkHash::new(&format!("dm_r6_{n}"), CAP_STD, socket_id)?,
            dhcp_meta: DpdkHash::new(&format!("dm_dm_{n}"), CAP_STD, socket_id)?,
            meter: DpdkHash::new(&format!("dm_mt_{n}"), CAP_STD, socket_id)?,
        })
    }
```
Run: `cargo test -p nfkit --test dpdk_maps -- --test-threads=1` → PASS. clippy `-p nfkit --all-targets` + fmt clean.

- [ ] **Step 3: Commit**
```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/nfkit/src/dpdk_maps.rs flowplane/nfkit/tests/dpdk_maps.rs
git commit -m "feat(nfkit): per-lcore-instantiable DpdkMaps (unique rte_hash names via AtomicU32)"
```

---

## Task 2: Multi-lcore datapath test (per-lcore DpdkMaps, in-process batches)

**Files:** Create `flowplane/nfkit/tests/multilcore_datapath.rs`.

- [ ] **Step 1: Write the test** — model the fixture on `parity_uplink.rs` (copy `inner_frame`/`encap_to`/`allow_meta`/`allow_rule` + the consts). Structure:
```rust
//! Shared-nothing per-lcore state: N worker lcores each run `process_uplink` over their OWN DpdkMaps
//! on an in-process batch of distinct flows. Asserts (a) each worker's decapped output is byte-
//! identical to the sim, and (b) conntrack isolation — a worker's map holds ITS flows, none of the
//! others'. Runs --no-huge, -l 0-2 (2 workers). Run with --test-threads=1.
use flowplane_common::{FwMeta, FwRule, Local, UnderlayValue, /* + FW consts */};
use flowplane_core::datapath::{process_uplink, UplinkIn};
use flowplane_core::pkt::{Action, Pkt};
use flowplane_sim::{MemMaps, SimNode, VecPkt};
use nfkit::{DpdkMaps, Eal, LcoreRuntime, MbufPkt, Mempool};
use std::sync::Mutex;
// ... copy consts (VNI, TAP, GUEST_MAC, GUEST_IP, EXT_IP, HOST_UL, DST_PORT) + inner_frame/encap_to/allow_meta/allow_rule ...

const N_WORKERS: u16 = 2;
const FLOWS_PER_WORKER: u16 = 4;

// Distinct inner-src IP per (worker, flow) → distinct CT keys; same dst GUEST_IP so the one fw allow rule matches.
fn flow_src(worker: u16, flow: u16) -> [u8; 4] { [10, 9, worker as u8, (flow + 1) as u8] }

#[derive(Default)]
struct WorkerOut { outputs: Vec<Vec<u8>>, own_ct_hits: usize, foreign_ct_hits: usize }

#[test]
fn multilcore_per_lcore_state() {
    let _eal = Eal::init(["nfkit-test", "-l", "0-2", "--no-huge", "-m", "512", "--no-pci", "--file-prefix", "nfkit_mlc"]).expect("EAL");
    let pool = Mempool::new("mlc_pool", 8191, 250, 0).expect("pool");
    let results: Vec<Mutex<WorkerOut>> = (0..N_WORKERS).map(|_| Mutex::new(WorkerOut::default())).collect();

    LcoreRuntime::for_each_worker(N_WORKERS, |q| {
        // Each worker builds its OWN DpdkMaps (unique names, auto) + fw allow on TAP.
        let mut maps = DpdkMaps::new(0).expect("per-lcore DpdkMaps");
        maps.add_fw_meta(TAP, allow_meta());
        maps.add_fw_rule(TAP, 0, allow_rule(DST_PORT));
        let u = UnderlayValue { vni: VNI, tap_ifindex: TAP, guest_mac: GUEST_MAC, _pad: [0; 2] };
        let zl = Local { uplink_ifindex: 0, uplink_mac: [0; 6], gateway_mac: [0; 6], underlay_ipv6: [0; 16] };

        let mut out = WorkerOut::default();
        for f in 0..FLOWS_PER_WORKER {
            let frame = encap_to(&inner_frame(flow_src(q, f), GUEST_IP, DST_PORT), HOST_UL);
            let mut mb = pool.alloc().expect("alloc");
            mb.append(frame.len() as u16).expect("append");
            mb.data_mut().copy_from_slice(&frame);
            let mut mp = MbufPkt::new(&mut mb);
            let action = process_uplink(&mut mp, &mut maps, &UplinkIn { vni: VNI, u, outer_dst: HOST_UL, local: &zl, now: 0 });
            // Record output bytes (read via read_array loop) — do NOT assert here (worker panic aborts).
            let mut bytes = Vec::with_capacity(mp.len());
            for i in 0..mp.len() { bytes.push(mp.read_array::<1>(i).unwrap()[0]); }
            if action == Action::Redirect(TAP) { out.outputs.push(bytes); }
        }
        // Isolation snapshot: our flows present, the OTHER worker's flows absent.
        let other = (q + 1) % N_WORKERS;
        for f in 0..FLOWS_PER_WORKER {
            if ct_present(&maps, q, f) { out.own_ct_hits += 1; }
            if ct_present(&maps, other, f) { out.foreign_ct_hits += 1; }
        }
        *results[q as usize].lock().unwrap() = out;
    });

    // Assert on the MAIN thread (post-join).
    for q in 0..N_WORKERS {
        let out = results[q as usize].lock().unwrap();
        assert_eq!(out.outputs.len(), FLOWS_PER_WORKER as usize, "worker {q}: all flows delivered");
        assert_eq!(out.own_ct_hits, FLOWS_PER_WORKER as usize, "worker {q}: own flows tracked");
        assert_eq!(out.foreign_ct_hits, 0, "worker {q}: NO foreign flows (shared-nothing isolation)");
        // Byte-parity vs sim for each flow.
        for (f, got) in out.outputs.iter().enumerate() {
            let expected = sim_uplink(flow_src(q, f as u16));
            assert_eq!(*got, expected, "worker {q} flow {f}: DPDK != sim byte parity");
        }
    }
}
```
Provide the two helpers:
```rust
// Is the (worker,flow) inner 5-tuple present in `maps`' conntrack? Build the same key ct_key derives.
fn ct_present(maps: &DpdkMaps, worker: u16, flow: u16) -> bool {
    use flowplane_common::CtKey;
    let k = CtKey { vni: VNI, src_ip: flow_src(worker, flow), dst_ip: GUEST_IP, src_port: 40000, dst_port: DST_PORT, proto: 6, _pad: [0; 3] };
    flowplane_core::maps::Maps::conntrack_get(maps, &k).is_some()
}
// Sim reference output for a flow (VecPkt+MemMaps).
fn sim_uplink(src: [u8; 4]) -> Vec<u8> {
    let frame = encap_to(&inner_frame(src, GUEST_IP, DST_PORT), HOST_UL);
    let mut sim = MemMaps::default();
    sim.fw_meta.insert(TAP, allow_meta());
    sim.fw_rules.insert((TAP, 0), allow_rule(DST_PORT));
    let u = UnderlayValue { vni: VNI, tap_ifindex: TAP, guest_mac: GUEST_MAC, _pad: [0; 2] };
    let zl = Local { uplink_ifindex: 0, uplink_mac: [0; 6], gateway_mac: [0; 6], underlay_ipv6: [0; 16] };
    let mut vp = VecPkt::from_bytes(&frame);
    let a = process_uplink(&mut vp, &mut sim, &UplinkIn { vni: VNI, u, outer_dst: HOST_UL, local: &zl, now: 0 });
    assert_eq!(a, Action::Redirect(TAP));
    vp.into_bytes()
}
```
IMPORTANT verify against the real code: (1) the exact `CtKey` fields + the inner src PORT `ct_key` uses (the `inner_frame` builder sets TCP sport 40000 — confirm `ct_key` keys on that); read `flowplane-core`'s `ct_key` + `CtKey` to make `ct_present` build the identical key. (2) `DpdkMaps` exposes `add_fw_meta`/`add_fw_rule` (it does). (3) `Mempool::new` signature (see `parity_uplink.rs`). Adjust literals to match.

- [ ] **Step 2: Run → PASS** — `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test multilcore_datapath -- --test-threads=1 --nocapture'`. Expect 2 workers, byte-parity + isolation all green. clippy `-p nfkit --all-targets` + fmt clean. (If EAL rejects `-l 0-2` on a <3-core box, fall back to `-l 0-1` + `N_WORKERS=1` — but this host has 16 lcores, so `0-2` is fine.)

- [ ] **Step 3: Commit**
```bash
git add flowplane/nfkit/tests/multilcore_datapath.rs
git commit -m "test(nfkit): multi-lcore datapath — per-lcore DpdkMaps, byte-parity + conntrack isolation"
```

---

## Task 3: Symmetric-Toeplitz RSS key + symmetry test + Port wiring

**Files:** Create `flowplane/nfkit/src/rss.rs`; modify `flowplane/nfkit/src/lib.rs`, `flowplane/nfkit/src/port.rs`; create `flowplane/nfkit/tests/rss_symmetry.rs`.

- [ ] **Step 1: Write `flowplane/nfkit/src/rss.rs`**
```rust
//! Symmetric-Toeplitz RSS: a symmetric key (0x6d5a repeated) for which Toeplitz(A‖B) == Toeplitz(B‖A),
//! so both directions of a flow hash to the same queue → the same lcore. This is what makes the
//! per-lcore conntrack/nat state correct (a flow's reply lands on the lcore that created its CT).
//! `Port::configure` programs this key; the HW spreading needs a real NIC (deferred), but the KEY's
//! symmetry property is verified in software here.

/// The canonical symmetric RSS key (Woo & Park): 40 bytes of the 2-byte period `0x6d 0x5a`.
pub const SYMMETRIC_RSS_KEY: [u8; 40] = {
    let mut k = [0u8; 40];
    let mut i = 0;
    while i < 40 { k[i] = if i % 2 == 0 { 0x6d } else { 0x5a }; i += 1; }
    k
};

/// Software Toeplitz RSS hash (matches the NIC's `rte_softrss`): for each set bit of `input` (MSB
/// first), XOR in the 32-bit window of `key` starting at that bit position.
#[must_use]
pub fn toeplitz_softrss(input: &[u8], key: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for (i, &byte) in input.iter().enumerate() {
        for b in 0..8u32 {
            if byte & (0x80 >> b) != 0 {
                let bitpos = i as u32 * 8 + b;
                let mut window: u32 = 0;
                for j in 0..32u32 {
                    let kb = bitpos + j;
                    let bit = (key[(kb / 8) as usize] >> (7 - (kb % 8))) & 1;
                    window = (window << 1) | u32::from(bit);
                }
                result ^= window;
            }
        }
    }
    result
}

/// Map an RSS hash to a queue index (NIC uses the low bits of the redirection table; for our test we
/// use the modulo, which preserves the symmetry property).
#[must_use]
pub fn rss_queue(hash: u32, n_queues: u16) -> u16 {
    (hash % u32::from(n_queues.max(1))) as u16
}
```
Wire `flowplane/nfkit/src/lib.rs`: `mod rss; pub use rss::{toeplitz_softrss, rss_queue, SYMMETRIC_RSS_KEY};`. Build `cargo build -p nfkit`.

- [ ] **Step 2: Program the key in `Port::configure`** — in `flowplane/nfkit/src/port.rs`, inside the `if nq > 1 {` RSS block (after setting `rss_hf`), add:
```rust
                // Symmetric-Toeplitz key: both flow directions hash to the same queue → same lcore
                // (the per-lcore conntrack/nat model relies on this). SAFETY: the key is 'static.
                conf.rx_adv_conf.rss_conf.rss_key = crate::rss::SYMMETRIC_RSS_KEY.as_ptr() as *mut u8;
                conf.rx_adv_conf.rss_conf.rss_key_len = crate::rss::SYMMETRIC_RSS_KEY.len() as u8;
```
Build `cargo build -p nfkit` (no NIC needed to compile; the key only matters on HW). (If the bindgen field name differs, e.g. `rss_key`/`rss_key_len`, grep the generated `rte_eth_rss_conf` and match.)

- [ ] **Step 3: Write `flowplane/nfkit/tests/rss_symmetry.rs`** (no EAL needed — pure function):
```rust
//! The symmetric RSS key makes Toeplitz(fwd 5-tuple) == Toeplitz(rev 5-tuple), so a flow and its
//! reply hash to the SAME queue/lcore. Verifies the property the per-lcore state model depends on.
use nfkit::{rss_queue, toeplitz_softrss, SYMMETRIC_RSS_KEY};

// RSS input for IPv4+L4 = src_ip ‖ dst_ip ‖ src_port ‖ dst_port (network order).
fn tuple(sip: [u8; 4], dip: [u8; 4], sp: u16, dp: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    v.extend_from_slice(&sip); v.extend_from_slice(&dip);
    v.extend_from_slice(&sp.to_be_bytes()); v.extend_from_slice(&dp.to_be_bytes());
    v
}

#[test]
fn symmetric_key_pins_both_directions() {
    let cases = [
        ([10, 0, 0, 1], [203, 0, 113, 9], 40000u16, 443u16),
        ([192, 168, 1, 5], [8, 8, 8, 8], 1234, 53),
        ([10, 9, 0, 1], [10, 9, 1, 2], 22, 51000),
    ];
    for (sip, dip, sp, dp) in cases {
        let fwd = toeplitz_softrss(&tuple(sip, dip, sp, dp), &SYMMETRIC_RSS_KEY);
        let rev = toeplitz_softrss(&tuple(dip, sip, dp, sp), &SYMMETRIC_RSS_KEY);
        assert_eq!(fwd, rev, "symmetric key must hash fwd == rev for {sip:?}:{sp} <-> {dip:?}:{dp}");
        for n in [2u16, 4, 8, 16] {
            assert_eq!(rss_queue(fwd, n), rss_queue(rev, n), "same queue for n={n}");
        }
    }
    // Sanity: distinct flows generally land on different hashes (not all-equal → the hash is live).
    let a = toeplitz_softrss(&tuple([1, 1, 1, 1], [2, 2, 2, 2], 1, 2), &SYMMETRIC_RSS_KEY);
    let b = toeplitz_softrss(&tuple([9, 9, 9, 9], [8, 8, 8, 8], 7, 8), &SYMMETRIC_RSS_KEY);
    assert_ne!(a, b, "hash should differ across distinct flows");
}
```
Run: `cargo test -p nfkit --test rss_symmetry` → PASS. **If `fwd != rev`**, the key/tuple ordering is off — this is a KNOWN-GOOD construction (0x6d5a symmetric key over src‖dst‖sport‖dport); recheck the softrss bit order (MSB-first) and the key periodicity before changing anything else. Do NOT weaken the assertion.

- [ ] **Step 4: Full nfkit suite + commit** — `cargo test -p nfkit -- --test-threads=1` (all M3–M8 green). clippy `-p nfkit --all-targets` + fmt clean.
```bash
git add flowplane/nfkit/src/rss.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/src/port.rs flowplane/nfkit/tests/rss_symmetry.rs
git commit -m "feat(nfkit): symmetric-Toeplitz RSS key (Port::configure) + software symmetry test (fwd==rev)"
```

---

## Definition of Done (M8)
- `cargo test -p nfkit -- --test-threads=1`: `dpdk_maps` (coexistence), `multilcore_datapath` (byte-parity + CT isolation), `rss_symmetry` (fwd==rev), + all M3–M7 anchors pass `--no-huge`.
- `cargo test -p flowplane-sim` + the `flowplane` `anchor_*` crate still pass unchanged (M8 is nfkit-only).
- Per-lcore `DpdkMaps` instantiation works; `Port::configure` programs the symmetric key; no new `Maps` trait method.
- Default host build untouched.

## Risks / notes
- **Worker panic aborts** (M2 trampoline) — record results into the `Mutex` slot, assert on the MAIN thread after `for_each_worker` returns. Never `assert!`/`unwrap`-that-can-fail inside a worker (an alloc failure `expect` is acceptable — it's a genuine abort).
- **`ct_present` key must match `ct_key`** — read `flowplane-core`'s `ct_key` + `CtKey` layout; build the identical key (esp. the inner L4 src/dst ports the `inner_frame` TCP builder sets: sport 40000, dport `DST_PORT`).
- **rte_hash name length ≤ 32** — the short prefixes (`dm_ct_<u32>`) fit.
- **RSS symmetry** — the `rss_symmetry` test IS the verification; the 0x6d5a key + MSB-first Toeplitz over src‖dst‖sport‖dport is the standard symmetric construction.
- **`-l 0-2` on a small box** — this host has 16 lcores; if ever run elsewhere with <3, fall back to fewer workers.
