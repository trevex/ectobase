# nfkit M2 — Multi-Queue Packet-I/O Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `nfkit`'s safe, zero-cost multi-queue packet-I/O core (`Mempool`, `Mbuf`, `Port`/`RxQueue`/`TxQueue`, `LcoreRuntime`, `Backend`) and prove it with an RSS l2fwd validated on `net_pcap` (deterministic CI) and `net_af_xdp` (gated veth loopback).

**Architecture:** Run-to-completion, shared-nothing per lcore. `Mbuf` is an owned RAII handle (Drop frees; tx transfers ownership of sent mbufs to DPDK, retains un-sent). `Port` configures N rx/tx queues with RSS; `LcoreRuntime` launches a per-lcore worker via `rte_eal_remote_launch`. `Backend` selects NIC/af_xdp/pcap/tap/null by config — same datapath code everywhere. Flowplane-agnostic (no `flowplane-core`).

**Tech Stack:** Rust (rustup nightly per repo), `dpdk-sys` FFI (from M1), DPDK 25.11.2, `arrayvec` (fixed-cap burst), scapy (in devShell) for the af_xdp harness.

**Context from M1:** `dpdk-sys` exposes bindgen FNs for `rte_pktmbuf_pool_create`, `rte_mempool_*`, `rte_eth_dev_configure`/`rx_queue_setup`/`tx_queue_setup`/`dev_start`/`dev_stop`/`dev_close`/`dev_info_get`/`dev_count_avail`, `rte_eal_remote_launch`/`rte_eal_mp_wait_lcore`/`rte_lcore_*`, `rte_socket_id`; and shim FNs `nfkit_eth_rx_burst`/`tx_burst`/`nfkit_pktmbuf_alloc`/`free`. Mbuf head/tail ops are DPDK static-inline → this milestone extends the shim. Run all cargo commands inside `nix develop`. The DPDK build is cached (`~/.cache/dpdk-sys/`); Task 1 changes the driver set → one rebuild, then cached.

**Bindgen-name caveat:** DPDK enum/const names may be generated as e.g. `RTE_ETH_MQ_RX_RSS`, `RTE_ETH_RSS_IP`, `rte_eth_conf`, `rte_eth_rxconf` — if an exact name differs in the generated `bindings.rs`, grep the generated file and use the actual symbol. The plan's names are DPDK 25.11 canonical.

---

## File Structure

- `flowplane/dpdk-sys/shim.h`, `shim.c` — **add** mbuf head/tail/data shim fns.
- `flowplane/dpdk-sys/build.rs` — `DRIVERS` **+= `net/af_xdp`**.
- `flowplane/nfkit/Cargo.toml` — add `arrayvec` dep.
- `flowplane/nfkit/src/mempool.rs` — `Mempool` (RAII pktmbuf pool).
- `flowplane/nfkit/src/mbuf.rs` — `Mbuf` (owned handle), `MbufError`, `MbufBurst`, `BURST`.
- `flowplane/nfkit/src/port.rs` — `Port`, `RxQueue`, `TxQueue`, `PortError`.
- `flowplane/nfkit/src/runtime.rs` — `LcoreRuntime`.
- `flowplane/nfkit/src/backend.rs` — `Backend`, `PortSpec`.
- `flowplane/nfkit/src/lib.rs` — re-exports.
- `flowplane/nfkit/examples/l2fwd.rs` — RSS l2fwd.
- `flowplane/nfkit/tests/{mbuf.rs, l2fwd_pcap.rs, afxdp_loopback.rs}` — tests.
- `hack/dpdk/afxdp-loopback.sh` — veth+scapy harness.

---

## Task 1: Extend the dpdk-sys shim (mbuf head/tail ops) + enable af_xdp

**Files:**
- Modify: `flowplane/dpdk-sys/shim.h`, `flowplane/dpdk-sys/shim.c`, `flowplane/dpdk-sys/build.rs`
- Test: `flowplane/dpdk-sys/tests/link.rs`

- [ ] **Step 1: Add the shim declarations**

Append to `flowplane/dpdk-sys/shim.h` (before or after the existing decls):

```c
/* Mbuf data + head/tail room ops (DPDK static-inline; bindgen can't emit them). */
uint8_t *nfkit_pktmbuf_mtod(struct rte_mbuf *m);
uint16_t nfkit_pktmbuf_data_len(struct rte_mbuf *m);
uint32_t nfkit_pktmbuf_pkt_len(struct rte_mbuf *m);
uint8_t  *nfkit_pktmbuf_prepend(struct rte_mbuf *m, uint16_t len);
uint8_t  *nfkit_pktmbuf_append(struct rte_mbuf *m, uint16_t len);
uint8_t  *nfkit_pktmbuf_adj(struct rte_mbuf *m, uint16_t len);
int       nfkit_pktmbuf_trim(struct rte_mbuf *m, uint16_t len);
```

- [ ] **Step 2: Add the shim definitions**

Append to `flowplane/dpdk-sys/shim.c`:

```c
uint8_t *nfkit_pktmbuf_mtod(struct rte_mbuf *m) { return rte_pktmbuf_mtod(m, uint8_t *); }
uint16_t nfkit_pktmbuf_data_len(struct rte_mbuf *m) { return m->data_len; }
uint32_t nfkit_pktmbuf_pkt_len(struct rte_mbuf *m) { return m->pkt_len; }
uint8_t *nfkit_pktmbuf_prepend(struct rte_mbuf *m, uint16_t len) { return (uint8_t *)rte_pktmbuf_prepend(m, len); }
uint8_t *nfkit_pktmbuf_append(struct rte_mbuf *m, uint16_t len) { return (uint8_t *)rte_pktmbuf_append(m, len); }
uint8_t *nfkit_pktmbuf_adj(struct rte_mbuf *m, uint16_t len) { return (uint8_t *)rte_pktmbuf_adj(m, len); }
int nfkit_pktmbuf_trim(struct rte_mbuf *m, uint16_t len) { return rte_pktmbuf_trim(m, len); }
```

- [ ] **Step 3: Enable the af_xdp driver in the DPDK build**

In `flowplane/dpdk-sys/build.rs`, change the `DRIVERS` constant:

```rust
const DRIVERS: &str = "net/null,net/pcap,net/tap,net/af_xdp";
```

This changes the cache key, so the next build recompiles DPDK once (~2–5 min) with the af_xdp PMD, then caches. The af_xdp PMD needs libbpf + libxdp at DPDK-build time — the devShell provides `libbpf` + `xdp-tools.lib`. If meson reports the af_xdp driver as "disabled: missing dependency", the DPDK build did not see libxdp/libbpf; in that case add their pkg-config paths to the `meson setup` env in `build_dpdk_cached` (e.g. set `PKG_CONFIG_PATH` in the `run("meson", ...)` call to include the devShell's libxdp/libbpf) and note the fix. If af_xdp genuinely cannot be enabled, STOP and report BLOCKED — do not silently ship without it (M2 requires it).

- [ ] **Step 4: Extend the link test to reference the new symbols**

In `flowplane/dpdk-sys/tests/link.rs`, add references to force-resolve the new shim symbols (inside `symbols_resolve`):

```rust
    let prepend: unsafe extern "C" fn(*mut dpdk_sys::rte_mbuf, u16) -> *mut u8 =
        dpdk_sys::nfkit_pktmbuf_prepend;
    let mtod: unsafe extern "C" fn(*mut dpdk_sys::rte_mbuf) -> *mut u8 = dpdk_sys::nfkit_pktmbuf_mtod;
    assert!(!(prepend as *const ()).is_null());
    assert!(!(mtod as *const ()).is_null());
```

- [ ] **Step 5: Build + run (first run rebuilds DPDK with af_xdp)**

Run (timeout 600000 ms): `nix develop --command bash -c 'cd flowplane && cargo test -p dpdk-sys --test link'`
Expected: DPDK rebuilds once with 4 drivers, crate compiles, link test PASSES. Verify the af_xdp PMD built: `ls ~/.cache/dpdk-sys/install-*/lib | grep af_xdp` should show `librte_net_af_xdp.a`.

- [ ] **Step 6: Commit**

```bash
cd /home/nik/Development/ironcore-net-xdp
git add flowplane/dpdk-sys
git commit -m "feat(dpdk-sys): mbuf head/tail shim fns + enable net/af_xdp driver"
```

---

## Task 2: `Mempool` (RAII pktmbuf pool) + arrayvec dep

**Files:**
- Modify: `flowplane/nfkit/Cargo.toml`
- Create: `flowplane/nfkit/src/mempool.rs`
- Modify: `flowplane/nfkit/src/lib.rs`
- Test: `flowplane/nfkit/tests/mempool.rs`

- [ ] **Step 1: Add the arrayvec dependency**

In `flowplane/nfkit/Cargo.toml` `[dependencies]`, add:

```toml
arrayvec = "0.7"
```

- [ ] **Step 2: Write the failing test**

Create `flowplane/nfkit/tests/mempool.rs`:

```rust
// Mempool alloc/free accounting. Requires EAL; run with --test-threads=1.
use nfkit::{Eal, Mempool};

#[test]
fn mempool_allocates_and_frees() {
    let _eal = Eal::init([
        "nfkit-test", "-l", "0", "--no-huge", "-m", "512", "--no-pci", "--file-prefix", "nfkit_mp",
    ])
    .expect("EAL init");
    let pool = Mempool::new("t", 1023, 250, 0).expect("pool");
    let before = pool.avail_count();
    let m = pool.alloc().expect("alloc one");
    assert_eq!(pool.avail_count(), before - 1, "alloc takes one buffer");
    drop(m);
    assert_eq!(pool.avail_count(), before, "drop returns the buffer");
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test mempool -- --test-threads=1'`
Expected: FAIL to compile (`Mempool` not found).

- [ ] **Step 4: Implement `Mempool`**

Create `flowplane/nfkit/src/mempool.rs`:

```rust
//! Safe RAII wrapper over a DPDK pktmbuf mempool.
use crate::mbuf::Mbuf;
use std::ffi::CString;
use std::ptr::NonNull;

/// A pool of packet mbufs. Freed on drop. Shareable across lcores via DPDK's per-lcore cache
/// (the underlying `rte_mempool` is internally synchronized), so this is `Sync`.
pub struct Mempool {
    raw: NonNull<dpdk_sys::rte_mempool>,
}

// SAFETY: rte_mempool is internally synchronized (per-lcore caches + a shared ring); concurrent
// alloc/free from multiple lcores is the documented usage.
unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}

#[derive(Debug)]
pub struct MempoolError;

impl Mempool {
    /// Create a pktmbuf pool: `n` mbufs, `cache` per-lcore cache size, on NUMA `socket`.
    /// Mbuf dataroom is DPDK's default (`RTE_MBUF_DEFAULT_BUF_SIZE`, ~2KB) — enough for 1500 MTU
    /// + headroom; jumbo/multi-seg is out of scope for M2.
    pub fn new(name: &str, n: u32, cache: u32, socket: i32) -> Result<Mempool, MempoolError> {
        let cname = CString::new(name).map_err(|_| MempoolError)?;
        // SAFETY: name is a valid C string for the call; other args are plain scalars. The default
        // buf size constant and priv size 0 are the standard pktmbuf pool params.
        let raw = unsafe {
            dpdk_sys::rte_pktmbuf_pool_create(
                cname.as_ptr(),
                n,
                cache,
                0,
                dpdk_sys::RTE_MBUF_DEFAULT_BUF_SIZE as u16,
                socket,
            )
        };
        NonNull::new(raw).map(|raw| Mempool { raw }).ok_or(MempoolError)
    }

    /// Allocate one mbuf, or `None` if the pool is exhausted.
    pub fn alloc(&self) -> Option<Mbuf> {
        // SAFETY: self.raw is a live pool for the lifetime of &self.
        let m = unsafe { dpdk_sys::nfkit_pktmbuf_alloc(self.raw.as_ptr()) };
        NonNull::new(m).map(|p| unsafe { Mbuf::from_raw(p) })
    }

    /// Number of free buffers currently available (for tests/observability).
    pub fn avail_count(&self) -> u32 {
        // SAFETY: live pool.
        unsafe { dpdk_sys::rte_mempool_avail_count(self.raw.as_ptr()) }
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        // SAFETY: sole owner; no outstanding Mbuf references are enforced by the caller (Mbufs
        // borrow nothing from Mempool at the type level, but in practice the pool outlives its mbufs
        // in M2 usage: workers drop mbufs each iteration before the pool is dropped at shutdown).
        unsafe { dpdk_sys::rte_mempool_free(self.raw.as_ptr()) }
    }
}
```

- [ ] **Step 5: Wire into lib.rs**

In `flowplane/nfkit/src/lib.rs`, add (keep existing `Eal` exports):

```rust
mod mbuf;
mod mempool;
pub use mbuf::{Mbuf, MbufBurst, MbufError, BURST};
pub use mempool::{Mempool, MempoolError};
```

(Task 3 creates `mbuf.rs`; this task will not compile until Task 3's `Mbuf` exists. To keep Task 2 self-contained, implement Task 3's `mbuf.rs` in the same working session before running — OR temporarily add a minimal `Mbuf` stub. Recommended: do Task 2 + Task 3 back-to-back and commit Task 2's test run after Task 3 lands. If executing strictly per-task, mark Task 2 DONE_WITH_CONCERNS noting the mbuf.rs dependency and proceed to Task 3.)

- [ ] **Step 6: Commit (after Task 3 exists so it compiles)**

```bash
git add flowplane/nfkit/Cargo.toml flowplane/nfkit/src/mempool.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/tests/mempool.rs
git commit -m "feat(nfkit): Mempool RAII pktmbuf pool + arrayvec dep"
```

---

## Task 3: `Mbuf` (owned handle, data + head/tail ops)

**Files:**
- Create: `flowplane/nfkit/src/mbuf.rs`
- Test: `flowplane/nfkit/tests/mbuf.rs`

- [ ] **Step 1: Write the failing test**

Create `flowplane/nfkit/tests/mbuf.rs`:

```rust
// Mbuf data + head/tail room ops over a real DPDK mbuf. Requires EAL; --test-threads=1.
use nfkit::{Eal, Mempool};

#[test]
fn mbuf_prepend_append_write_read() {
    let _eal = Eal::init([
        "nfkit-test", "-l", "0", "--no-huge", "-m", "512", "--no-pci", "--file-prefix", "nfkit_mbuf",
    ])
    .expect("EAL init");
    let pool = Mempool::new("mb", 1023, 250, 0).expect("pool");
    let mut m = pool.alloc().expect("alloc");
    assert_eq!(m.len(), 0, "fresh mbuf is empty");

    // append 4 bytes, write a payload
    let tail = m.append(4).expect("append");
    tail.copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(m.len(), 4);
    assert_eq!(m.data(), &[1, 2, 3, 4]);

    // prepend 2 bytes (headroom), write a header
    let head = m.prepend(2).expect("prepend");
    head.copy_from_slice(&[0xaa, 0xbb]);
    assert_eq!(m.data(), &[0xaa, 0xbb, 1, 2, 3, 4]);

    // adjust (strip 2 head bytes) + trim (strip 1 tail byte)
    m.adjust(2).expect("adjust");
    m.trim(1).expect("trim");
    assert_eq!(m.data(), &[1, 2, 3]);
}

#[test]
fn mbuf_prepend_beyond_headroom_errors() {
    let _eal = Eal::init([
        "nfkit-test", "-l", "0", "--no-huge", "-m", "512", "--no-pci", "--file-prefix", "nfkit_mbuf2",
    ])
    .expect("EAL init");
    let pool = Mempool::new("mb2", 1023, 250, 0).expect("pool");
    let mut m = pool.alloc().expect("alloc");
    // default headroom is 128; prepending 5000 must fail, not corrupt memory.
    assert!(m.prepend(5000).is_err());
}
```

Note: EAL is process-global — these two tests both call `Eal::init`. Because M1's single-init guard makes only the FIRST `Eal::init` succeed per process, having two `#[test]`s that each init will make the second fail. **Put both assertions in ONE test** (or gate the second init). Merge the two above into a single `#[test] fn mbuf_ops()` that does the prepend/append/adjust/trim sequence AND the beyond-headroom error check, using ONE `Eal::init`. (This mirrors the M1 `eal_init` test's single-process constraint.)

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test mbuf -- --test-threads=1'`
Expected: FAIL to compile (`Mbuf` methods missing).

- [ ] **Step 3: Implement `Mbuf`**

Create `flowplane/nfkit/src/mbuf.rs`:

```rust
//! Safe owned handle over a DPDK `rte_mbuf`. Drop frees it. Move-only.
use arrayvec::ArrayVec;
use std::ptr::NonNull;
use std::slice;

/// Rx/Tx burst size — one cache-friendly batch.
pub const BURST: usize = 32;
/// A fixed-capacity, zero-heap-alloc batch of owned mbufs.
pub type MbufBurst = ArrayVec<Mbuf, BURST>;

#[derive(Debug)]
pub struct MbufError;

/// An owned packet buffer. Dropping frees it back to its pool. `TxQueue::tx` transfers ownership
/// of transmitted mbufs to DPDK via [`Mbuf::into_raw`]. Not `Clone`.
pub struct Mbuf {
    raw: NonNull<dpdk_sys::rte_mbuf>,
}

impl Mbuf {
    /// Take ownership of a raw mbuf. SAFETY: `raw` must be a live, singly-owned mbuf.
    pub(crate) unsafe fn from_raw(raw: NonNull<dpdk_sys::rte_mbuf>) -> Mbuf {
        Mbuf { raw }
    }
    /// Borrow the raw pointer (does not transfer ownership).
    pub(crate) fn as_raw(&self) -> *mut dpdk_sys::rte_mbuf {
        self.raw.as_ptr()
    }
    /// Give up ownership, returning the raw pointer WITHOUT freeing (caller/DPDK now owns it).
    pub(crate) fn into_raw(self) -> *mut dpdk_sys::rte_mbuf {
        let p = self.raw.as_ptr();
        std::mem::forget(self);
        p
    }

    /// Current data length (bytes).
    pub fn len(&self) -> usize {
        // SAFETY: live mbuf.
        unsafe { dpdk_sys::nfkit_pktmbuf_data_len(self.raw.as_ptr()) as usize }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read-only view of the packet data.
    pub fn data(&self) -> &[u8] {
        // SAFETY: mtod points into the mbuf's dataroom for `data_len` bytes; borrow tied to &self.
        unsafe {
            let p = dpdk_sys::nfkit_pktmbuf_mtod(self.raw.as_ptr());
            slice::from_raw_parts(p, self.len())
        }
    }
    /// Mutable view of the packet data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        // SAFETY: exclusive &mut self; mtod + data_len bound the slice.
        unsafe {
            let p = dpdk_sys::nfkit_pktmbuf_mtod(self.raw.as_ptr());
            slice::from_raw_parts_mut(p, self.len())
        }
    }

    /// Grow the head by `n` bytes (into headroom); returns the new front `n` bytes. Err if no room.
    pub fn prepend(&mut self, n: u16) -> Result<&mut [u8], MbufError> {
        // SAFETY: DPDK bounds-checks headroom and returns NULL on overflow.
        let p = unsafe { dpdk_sys::nfkit_pktmbuf_prepend(self.raw.as_ptr(), n) };
        if p.is_null() {
            return Err(MbufError);
        }
        Ok(unsafe { slice::from_raw_parts_mut(p, n as usize) })
    }
    /// Grow the tail by `n` bytes; returns the new trailing `n` bytes. Err if no room.
    pub fn append(&mut self, n: u16) -> Result<&mut [u8], MbufError> {
        // SAFETY: DPDK bounds-checks tailroom and returns NULL on overflow.
        let p = unsafe { dpdk_sys::nfkit_pktmbuf_append(self.raw.as_ptr(), n) };
        if p.is_null() {
            return Err(MbufError);
        }
        Ok(unsafe { slice::from_raw_parts_mut(p, n as usize) })
    }
    /// Strip `n` bytes from the head. Err if `n > len`.
    pub fn adjust(&mut self, n: u16) -> Result<(), MbufError> {
        // SAFETY: DPDK returns NULL if n > data_len.
        let p = unsafe { dpdk_sys::nfkit_pktmbuf_adj(self.raw.as_ptr(), n) };
        if p.is_null() {
            Err(MbufError)
        } else {
            Ok(())
        }
    }
    /// Strip `n` bytes from the tail. Err if `n > len`.
    pub fn trim(&mut self, n: u16) -> Result<(), MbufError> {
        // SAFETY: DPDK returns <0 if n > data_len.
        let rc = unsafe { dpdk_sys::nfkit_pktmbuf_trim(self.raw.as_ptr(), n) };
        if rc < 0 {
            Err(MbufError)
        } else {
            Ok(())
        }
    }
}

impl Drop for Mbuf {
    fn drop(&mut self) {
        // SAFETY: sole owner; free returns the buffer to its pool.
        unsafe { dpdk_sys::nfkit_pktmbuf_free(self.raw.as_ptr()) }
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test mbuf --test mempool -- --test-threads=1'`
Expected: mbuf + mempool tests PASS. Also run `cargo clippy -p nfkit --all-targets` clean and `cargo fmt`.

- [ ] **Step 5: Commit (this also unblocks Task 2's commit)**

```bash
git add flowplane/nfkit/src/mbuf.rs flowplane/nfkit/tests/mbuf.rs flowplane/nfkit/Cargo.toml flowplane/nfkit/src/mempool.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/tests/mempool.rs
git commit -m "feat(nfkit): owned Mbuf (RAII, data/head/tail ops) + Mempool"
```

---

## Task 4: `Port` + `RxQueue`/`TxQueue` (multi-queue RSS, burst, ownership transfer)

**Files:**
- Create: `flowplane/nfkit/src/port.rs`
- Modify: `flowplane/nfkit/src/lib.rs`
- Test: `flowplane/nfkit/tests/port.rs`

- [ ] **Step 1: Write the failing test**

Create `flowplane/nfkit/tests/port.rs`:

```rust
// Configure the net_null vdev port with 1 queue, rx an empty burst, and verify tx ownership
// transfer: sent mbufs are NOT double-freed, un-sent remain owned. --test-threads=1.
use nfkit::{Eal, Mempool, Port, MbufBurst};

#[test]
fn port_configures_and_tx_transfers_ownership() {
    let _eal = Eal::init([
        "nfkit-test", "-l", "0", "--no-huge", "-m", "512", "--no-pci",
        "--vdev", "net_null0", "--file-prefix", "nfkit_port",
    ])
    .expect("EAL init");
    let pool = Mempool::new("p", 1023, 250, 0).expect("pool");
    let port = Port::configure(0, 1, &pool).expect("configure port 0");
    let (mut rx, mut tx) = port.queue(0);

    // rx from net_null yields nothing.
    let mut burst = MbufBurst::new();
    let n = rx.rx(&mut burst);
    assert_eq!(n, 0);
    assert!(burst.is_empty());

    // tx: net_null accepts everything. Fill a burst with allocated mbufs, tx, and confirm the
    // burst is drained (ownership passed to DPDK — no leak, no double free).
    let avail_before = pool.avail_count();
    for _ in 0..4 {
        let mut m = pool.alloc().unwrap();
        m.append(64).unwrap();
        burst.push(m);
    }
    let sent = tx.tx(&mut burst);
    assert_eq!(sent, 4, "net_null accepts all");
    assert!(burst.is_empty(), "sent mbufs removed from the burst");
    // net_null frees on tx, so the pool returns to full — proves no leak and no double free.
    assert_eq!(pool.avail_count(), avail_before, "sent mbufs freed exactly once by DPDK");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test port -- --test-threads=1'`
Expected: FAIL to compile (`Port` missing).

- [ ] **Step 3: Implement `Port` + queues**

Create `flowplane/nfkit/src/port.rs`:

```rust
//! Safe ethdev port + per-lcore rx/tx queues. `Port` configures N rx/tx queues with RSS and
//! owns the device lifecycle (stop+close on drop). `RxQueue`/`TxQueue` are `!Send` handles.
use crate::mbuf::{Mbuf, MbufBurst};
use crate::mempool::Mempool;
use std::marker::PhantomData;
use std::ptr;

#[derive(Debug)]
pub struct PortError(pub i32);

/// A configured, started ethdev port. Stops + closes on drop.
pub struct Port {
    id: u16,
    n_queues: u16,
}

impl Port {
    /// Configure port `id` with `n_queues` rx+tx queues and RSS (basic hash), each rx queue fed
    /// from `pool`. Backends without HW RSS (pcap/tap/null) are configured single-queue regardless
    /// of `n_queues` if the device caps it. Starts the device.
    pub fn configure(id: u16, n_queues: u16, pool: &Mempool) -> Result<Port, PortError> {
        // SAFETY: standard ethdev bring-up sequence; all pointers point to locals live for the call.
        unsafe {
            let mut info: dpdk_sys::rte_eth_dev_info = std::mem::zeroed();
            let rc = dpdk_sys::rte_eth_dev_info_get(id, &mut info);
            if rc != 0 {
                return Err(PortError(rc));
            }
            let nq = n_queues.min(info.max_rx_queues).min(info.max_tx_queues).max(1);

            let mut conf: dpdk_sys::rte_eth_conf = std::mem::zeroed();
            if nq > 1 {
                conf.rxmode.mq_mode = dpdk_sys::rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_RSS;
                // Basic RSS over whatever the device supports (IP + TCP/UDP typically).
                conf.rx_adv_conf.rss_conf.rss_hf =
                    (dpdk_sys::RTE_ETH_RSS_IP as u64) & info.flow_type_rss_offloads;
            }
            let rc = dpdk_sys::rte_eth_dev_configure(id, nq, nq, &conf);
            if rc != 0 {
                return Err(PortError(rc));
            }
            let socket = dpdk_sys::rte_eth_dev_socket_id(id).max(0);
            for q in 0..nq {
                let rc = dpdk_sys::rte_eth_rx_queue_setup(
                    id, q, 512, socket as u32, ptr::null(), pool_raw(pool),
                );
                if rc != 0 {
                    return Err(PortError(rc));
                }
                let rc = dpdk_sys::rte_eth_tx_queue_setup(id, q, 512, socket as u32, ptr::null());
                if rc != 0 {
                    return Err(PortError(rc));
                }
            }
            let rc = dpdk_sys::rte_eth_dev_start(id);
            if rc != 0 {
                return Err(PortError(rc));
            }
            Ok(Port { id, n_queues: nq })
        }
    }

    pub fn n_queues(&self) -> u16 {
        self.n_queues
    }

    /// Build the `(RxQueue, TxQueue)` handles for queue `q`. Intended to be called ON the lcore
    /// that will service this queue (the handles are `!Send`).
    pub fn queue(&self, q: u16) -> (RxQueue, TxQueue) {
        (
            RxQueue { port: self.id, q, _ns: PhantomData },
            TxQueue { port: self.id, q, _ns: PhantomData },
        )
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        // SAFETY: sole owner; stop before close is the required teardown order.
        unsafe {
            dpdk_sys::rte_eth_dev_stop(self.id);
            dpdk_sys::rte_eth_dev_close(self.id);
        }
    }
}

// Access the raw mempool pointer without exposing it publicly.
fn pool_raw(pool: &Mempool) -> *mut dpdk_sys::rte_mempool {
    pool.as_raw()
}

/// `!Send` rx queue handle. Poll from exactly one lcore.
pub struct RxQueue {
    port: u16,
    q: u16,
    _ns: PhantomData<*const ()>,
}
/// `!Send` tx queue handle. Transmit from exactly one lcore.
pub struct TxQueue {
    port: u16,
    q: u16,
    _ns: PhantomData<*const ()>,
}

impl RxQueue {
    /// Receive up to the burst's remaining capacity; appends owned mbufs to `out`. Returns count.
    pub fn rx(&mut self, out: &mut MbufBurst) -> usize {
        let cap = out.remaining_capacity();
        if cap == 0 {
            return 0;
        }
        let mut raw: [*mut dpdk_sys::rte_mbuf; crate::mbuf::BURST] =
            [ptr::null_mut(); crate::mbuf::BURST];
        // SAFETY: raw has room for `cap` <= BURST pointers; nfkit_eth_rx_burst fills the first n.
        let n = unsafe {
            dpdk_sys::nfkit_eth_rx_burst(self.port, self.q, raw.as_mut_ptr(), cap as u16) as usize
        };
        for &p in raw.iter().take(n) {
            // SAFETY: each returned pointer is a freshly-owned mbuf from the driver.
            out.push(unsafe { Mbuf::from_raw(std::ptr::NonNull::new_unchecked(p)) });
        }
        n
    }
}

impl TxQueue {
    /// Transmit the front of `burst`. Sent mbufs are removed from `burst` and their ownership
    /// passed to DPDK (freed by the driver after transmit — NOT by us). Un-sent mbufs remain in
    /// `burst` (owned; retry or drop). Returns count sent.
    pub fn tx(&mut self, burst: &mut MbufBurst) -> usize {
        if burst.is_empty() {
            return 0;
        }
        let mut raw: [*mut dpdk_sys::rte_mbuf; crate::mbuf::BURST] =
            [ptr::null_mut(); crate::mbuf::BURST];
        for (i, m) in burst.iter().enumerate() {
            raw[i] = m.as_raw();
        }
        // SAFETY: raw[0..len] are the burst's live mbufs; the driver takes ownership of the first n.
        let sent = unsafe {
            dpdk_sys::nfkit_eth_tx_burst(self.port, self.q, raw.as_mut_ptr(), burst.len() as u16)
                as usize
        };
        // Remove the sent prefix WITHOUT running Drop (DPDK owns/frees them now).
        for m in burst.drain(..sent) {
            let _ = m.into_raw(); // forget: ownership already transferred to DPDK
        }
        sent
    }
}
```

Note: `Mempool` must expose `as_raw(&self) -> *mut rte_mempool` at `pub(crate)` visibility — add that method to `mempool.rs` (`pub(crate) fn as_raw(&self) -> *mut dpdk_sys::rte_mempool { self.raw.as_ptr() }`).

- [ ] **Step 4: Wire lib.rs + add Mempool::as_raw**

Add to `flowplane/nfkit/src/lib.rs`:
```rust
mod port;
pub use port::{Port, PortError, RxQueue, TxQueue};
```
Add `pub(crate) fn as_raw` to `Mempool` (see note above).

- [ ] **Step 5: Run to verify pass**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test port -- --test-threads=1'`
Expected: PASS. clippy + fmt clean.

- [ ] **Step 6: Commit**

```bash
git add flowplane/nfkit/src/port.rs flowplane/nfkit/src/mempool.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/tests/port.rs
git commit -m "feat(nfkit): multi-queue RSS Port + !Send Rx/TxQueue with ownership-transfer tx"
```

---

## Task 5: `LcoreRuntime` (per-lcore worker via rte_eal_remote_launch)

**Files:**
- Create: `flowplane/nfkit/src/runtime.rs`
- Modify: `flowplane/nfkit/src/lib.rs`
- Test: `flowplane/nfkit/tests/runtime.rs`

This task contains the milestone's one genuinely delicate `unsafe` (a Rust closure invoked from a C worker thread). Follow the code exactly; the SAFETY argument is spelled out.

- [ ] **Step 1: Write the failing test**

Create `flowplane/nfkit/tests/runtime.rs`:

```rust
// LcoreRuntime runs a worker closure on each worker lcore and joins. With `-l 0-1` there is one
// main lcore (0) and one worker (1). The closure records which queue indices ran. --test-threads=1.
use nfkit::{Eal, LcoreRuntime};
use std::sync::atomic::{AtomicU32, Ordering};

#[test]
fn runtime_runs_worker_on_each_lcore() {
    let _eal = Eal::init([
        "nfkit-test", "-l", "0-1", "--no-huge", "-m", "512", "--no-pci", "--file-prefix", "nfkit_rt",
    ])
    .expect("EAL init");
    let ran = AtomicU32::new(0);
    LcoreRuntime::for_each_worker(1, |queue_id| {
        // one worker lcore -> queue_id 0
        ran.fetch_add(1u32 << queue_id, Ordering::SeqCst);
    });
    assert_eq!(ran.load(Ordering::SeqCst), 1, "exactly one worker (queue 0) ran and joined");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test runtime -- --test-threads=1'`
Expected: FAIL to compile (`LcoreRuntime` missing).

- [ ] **Step 3: Implement `LcoreRuntime`**

Create `flowplane/nfkit/src/runtime.rs`:

```rust
//! Per-lcore run-to-completion launcher. `for_each_worker` runs a closure on every WORKER lcore
//! (all EAL lcores except the main one), passing a 0-based `queue_id`, and joins before returning.
use std::os::raw::c_void;

/// The trampoline the C worker thread calls. `arg` points to a `WorkerArg`.
extern "C" fn trampoline(arg: *mut c_void) -> i32 {
    // SAFETY: `arg` is a `*mut WorkerArg` we passed to rte_eal_remote_launch; it lives on the
    // launching thread's stack for the whole scope (we join before returning), and exactly one
    // worker thread reads it. We must NOT unwind across the C boundary — catch any panic and abort.
    let wa = unsafe { &*(arg as *const WorkerArg) };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (wa.func)(wa.queue_id);
    }));
    if result.is_err() {
        // A panic must not cross into C. Abort the process (a worker panic is unrecoverable here).
        eprintln!("nfkit: worker lcore {} panicked; aborting", wa.queue_id);
        std::process::abort();
    }
    0
}

struct WorkerArg<'a> {
    func: &'a (dyn Fn(u16) + Sync),
    queue_id: u16,
}

/// Launcher for per-lcore workers.
pub struct LcoreRuntime;

impl LcoreRuntime {
    /// Run `func(queue_id)` on the first `n_workers` worker lcores (0-based `queue_id`), then join
    /// all. Blocks until every launched worker returns. `func` must be `Sync` (shared across lcores).
    /// Callers pass `n_workers = port.n_queues()` so every worker owns a distinct queue (never more
    /// workers than queues — an rx/tx queue must be serviced by exactly one lcore).
    pub fn for_each_worker<F: Fn(u16) + Sync>(n_workers: u16, func: F) {
        // WorkerArgs live on THIS stack frame for the whole call; we join (mp_wait_lcore) before
        // returning, so the references stay valid for every worker.
        let dynf: &(dyn Fn(u16) + Sync) = &func;
        let mut args: Vec<WorkerArg> = Vec::new();
        let mut lcores: Vec<u32> = Vec::new();
        // SAFETY: iterate EAL worker lcores (skip main). rte_get_next_lcore(prev, skip_main=1, wrap=0).
        unsafe {
            let mut q: u16 = 0;
            let mut lc = dpdk_sys::rte_get_next_lcore(u32::MAX, 1, 0);
            while lc < dpdk_sys::RTE_MAX_LCORE && q < n_workers {
                lcores.push(lc);
                args.push(WorkerArg { func: dynf, queue_id: q });
                q += 1;
                lc = dpdk_sys::rte_get_next_lcore(lc, 1, 0);
            }
            // Launch each worker with a stable pointer to its arg (args is fully built — no realloc).
            for (i, &lc) in lcores.iter().enumerate() {
                let ptr = &args[i] as *const WorkerArg as *mut c_void;
                let rc = dpdk_sys::rte_eal_remote_launch(Some(trampoline), ptr, lc);
                assert_eq!(rc, 0, "rte_eal_remote_launch failed for lcore {lc}");
            }
            // Join ALL workers before args/func go out of scope.
            dpdk_sys::rte_eal_mp_wait_lcore();
        }
    }
}

/// Count of EAL worker lcores (all lcores except the main one). Use to size the queue request.
pub fn worker_lcore_count() -> u16 {
    let mut n = 0u16;
    // SAFETY: read-only lcore enumeration after EAL init.
    unsafe {
        let mut lc = dpdk_sys::rte_get_next_lcore(u32::MAX, 1, 0);
        while lc < dpdk_sys::RTE_MAX_LCORE {
            n += 1;
            lc = dpdk_sys::rte_get_next_lcore(lc, 1, 0);
        }
    }
    n
}
```

Notes for the implementer:
- The exact bindgen signature of `rte_eal_remote_launch` may be `Option<unsafe extern "C" fn(*mut c_void) -> i32>` for the callback — pass `Some(trampoline)`. If bindgen typed the callback arg differently, match it.
- `rte_get_next_lcore` / `RTE_MAX_LCORE` / `rte_eal_mp_wait_lcore` are the standard names; if bindgen differs, grep `bindings.rs`.
- Do NOT let `args` reallocate after taking pointers — it is fully built before the launch loop (correct above).

- [ ] **Step 4: Wire lib.rs**

Add to `flowplane/nfkit/src/lib.rs`:
```rust
mod runtime;
pub use runtime::{worker_lcore_count, LcoreRuntime};
```

- [ ] **Step 5: Run to verify pass**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test runtime -- --test-threads=1'`
Expected: PASS (worker on lcore 1 runs + joins). clippy + fmt clean.

- [ ] **Step 6: Commit**

```bash
git add flowplane/nfkit/src/runtime.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/tests/runtime.rs
git commit -m "feat(nfkit): LcoreRuntime — per-lcore worker launch via rte_eal_remote_launch"
```

---

## Task 6: `Backend` + `PortSpec` (write-once-run-anywhere)

**Files:**
- Create: `flowplane/nfkit/src/backend.rs`
- Modify: `flowplane/nfkit/src/lib.rs`
- Test: `flowplane/nfkit/tests/backend.rs`

- [ ] **Step 1: Write the failing test**

Create `flowplane/nfkit/tests/backend.rs`:

```rust
use nfkit::Backend;

#[test]
fn backend_builds_eal_and_vdev_args() {
    // pcap backend -> --no-huge + a net_pcap vdev arg
    let b = Backend::Pcap { rx: "in.pcap".into(), tx: "out.pcap".into() };
    let eal = b.eal_args("nfkit");
    assert!(eal.iter().any(|a| a == "--no-huge"));
    assert!(eal.iter().any(|a| a.starts_with("net_pcap")), "vdev arg present: {eal:?}");
    // null backend -> --no-huge + net_null vdev
    let n = Backend::Null.eal_args("nfkit");
    assert!(n.iter().any(|a| a == "net_null0"));
    // af_xdp backend -> NO --no-huge (needs hugepages), iface in the vdev
    let a = Backend::AfXdp { iface: "vv0".into(), queues: 1 };
    let ae = a.eal_args("nfkit");
    assert!(!ae.iter().any(|x| x == "--no-huge"));
    assert!(ae.iter().any(|x| x.contains("iface=vv0")));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test backend'`
Expected: FAIL to compile (`Backend` missing).

- [ ] **Step 3: Implement `Backend`**

Create `flowplane/nfkit/src/backend.rs`:

```rust
//! Backend selection: the same datapath runs on any of these by producing the right EAL args.
//! `--vdev` args make the port appear as ethdev port 0 regardless of backend.

/// Which DPDK port backing to run on.
pub enum Backend {
    /// A real NIC by PCI address (multi-queue/RSS on real HW).
    Nic { pci: String },
    /// AF_XDP on a kernel netdev (needs hugepages + CAP_NET_ADMIN).
    AfXdp { iface: String, queues: u16 },
    /// pcap replay/record (functional/CI; no hugepages).
    Pcap { rx: String, tx: String },
    /// Kernel TAP.
    Tap { name: String },
    /// Null sink/source.
    Null,
}

impl Backend {
    /// Build the full EAL argv (argv[0] = `prog`). Includes `--no-huge` for software backends and
    /// the `--vdev` for vdev backends. Port 0 is always the configured backend.
    pub fn eal_args(&self, prog: &str) -> Vec<String> {
        let mut v = vec![prog.to_string(), "-l".into(), "0-3".into()];
        match self {
            Backend::Nic { pci } => {
                v.push("-a".into());
                v.push(pci.clone());
            }
            Backend::AfXdp { iface, queues } => {
                v.push("--vdev".into());
                v.push(format!("net_af_xdp0,iface={iface},start_queue=0,queue_count={queues}"));
            }
            Backend::Pcap { rx, tx } => {
                v.push("--no-huge".into());
                v.push("-m".into());
                v.push("512".into());
                v.push("--no-pci".into());
                v.push("--vdev".into());
                v.push(format!("net_pcap0,rx_pcap={rx},tx_pcap={tx}"));
            }
            Backend::Tap { name } => {
                v.push("--no-huge".into());
                v.push("-m".into());
                v.push("512".into());
                v.push("--no-pci".into());
                v.push("--vdev".into());
                v.push(format!("net_tap0,iface={name}"));
            }
            Backend::Null => {
                v.push("--no-huge".into());
                v.push("-m".into());
                v.push("512".into());
                v.push("--no-pci".into());
                v.push("--vdev".into());
                v.push("net_null0".into());
            }
        }
        v
    }
}
```

Note: the pcap test asserts a token `starts_with("net_pcap")` — the vdev value is `net_pcap0,rx_pcap=...`, which satisfies it. The Null test asserts the exact token `net_null0`, present above.

- [ ] **Step 4: Wire lib.rs + run**

Add to `flowplane/nfkit/src/lib.rs`:
```rust
mod backend;
pub use backend::Backend;
```
Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test backend'`
Expected: PASS. (No EAL needed — pure arg building.)

- [ ] **Step 5: Commit**

```bash
git add flowplane/nfkit/src/backend.rs flowplane/nfkit/src/lib.rs flowplane/nfkit/tests/backend.rs
git commit -m "feat(nfkit): Backend enum → EAL/vdev args (write-once-run-anywhere)"
```

---

## Task 7: l2fwd example

**Files:**
- Create: `flowplane/nfkit/examples/l2fwd.rs`

- [ ] **Step 1: Write the example**

Create `flowplane/nfkit/examples/l2fwd.rs`:

```rust
//! RSS l2fwd: rx a burst, swap src/dst MAC, tx it back. Runs the LcoreRuntime across all worker
//! lcores, each on its own RSS-fed queue. Backend is chosen by argv.
//!   cargo run -p nfkit --example l2fwd -- pcap in.pcap out.pcap
//!   cargo run -p nfkit --example l2fwd -- afxdp vv0
//!   cargo run -p nfkit --example l2fwd -- null
use nfkit::{Backend, Eal, LcoreRuntime, Mempool, MbufBurst, Port};
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let backend = match a.first().map(String::as_str) {
        Some("pcap") => Backend::Pcap { rx: a[1].clone(), tx: a[2].clone() },
        Some("afxdp") => Backend::AfXdp { iface: a[1].clone(), queues: 1 },
        Some("tap") => Backend::Tap { name: a[1].clone() },
        _ => Backend::Null,
    };
    // pcap replays a finite file then rx returns 0 forever — stop after an idle streak.
    let is_pcap = matches!(backend, Backend::Pcap { .. });

    let _eal = Eal::init(backend.eal_args("nfkit-l2fwd")).expect("EAL init");
    let pool = Mempool::new("l2fwd", 8191, 250, 0).expect("pool");
    // Request one queue per worker lcore; the device may cap it (pcap/tap/null -> 1). Then run
    // exactly port.n_queues() workers so each owns a distinct queue.
    let requested = nfkit::worker_lcore_count().max(1);
    let port = Port::configure(0, requested, &pool).expect("configure port 0");
    let nq = port.n_queues();

    LcoreRuntime::for_each_worker(nq, |queue_id| {
        let (mut rx, mut tx) = port.queue(queue_id);
        let mut burst = MbufBurst::new();
        let mut idle = 0u32;
        while !STOP.load(Ordering::Relaxed) {
            burst.clear();
            let n = rx.rx(&mut burst);
            if n == 0 {
                idle += 1;
                if is_pcap && idle > 1000 {
                    break; // pcap drained
                }
                continue;
            }
            idle = 0;
            for m in burst.iter_mut() {
                if m.len() >= 12 {
                    let d = m.data_mut();
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&d[0..6]);
                    d.copy_within(6..12, 0); // dst = old src
                    d[6..12].copy_from_slice(&mac); // src = old dst
                }
            }
            let mut off = 0;
            while off < burst.len() {
                let sent = tx.tx(&mut burst);
                if sent == 0 {
                    break; // ring full; drop remainder (M2 simplicity)
                }
                off += sent;
            }
        }
    });
    println!("l2fwd done");
}
```

The example uses only `nfkit`'s public API (incl. `nfkit::worker_lcore_count()` from Task 5) — it never touches `dpdk_sys` directly.

- [ ] **Step 2: Build the example**

Run: `nix develop --command bash -c 'cd flowplane && cargo build -p nfkit --example l2fwd'`
Expected: compiles. clippy + fmt clean.

- [ ] **Step 3: Smoke-run on null**

Run: `nix develop --command bash -c 'cd flowplane && timeout 3 cargo run -p nfkit --example l2fwd -- null; true'`
Expected: EAL boots, workers spin, no crash (Ctrl-C/timeout ends it). This is a smoke check, not an assertion.

- [ ] **Step 4: Commit**

```bash
git add flowplane/nfkit/examples/l2fwd.rs
git commit -m "feat(nfkit): RSS l2fwd example (per-lcore rx/swap-mac/tx)"
```

---

## Task 8: Deterministic pcap l2fwd test (the CI DoD)

**Files:**
- Create: `flowplane/nfkit/tests/l2fwd_pcap.rs`
- Create: `flowplane/nfkit/tests/data/gen_pcap.py` (helper to make the input pcap) OR generate inline.

- [ ] **Step 1: Generate a deterministic input pcap fixture**

Create `flowplane/nfkit/tests/data/l2fwd_in.pcap` by running (scapy is in the devShell):

Run: `nix develop --command bash -c 'python3 - <<PY
from scapy.all import Ether, IP, UDP, wrpcap
pkts=[Ether(src="11:11:11:11:11:11",dst="22:22:22:22:22:22")/IP(src="10.0.0.1",dst="10.0.0.2")/UDP()/b"hello" for _ in range(4)]
wrpcap("flowplane/nfkit/tests/data/l2fwd_in.pcap", pkts)
print("wrote", len(pkts))
PY'`
Expected: `wrote 4`. Commit this fixture.

- [ ] **Step 2: Write the test**

Create `flowplane/nfkit/tests/l2fwd_pcap.rs`:

```rust
// Deterministic DoD: run the l2fwd example on net_pcap over a fixture, assert every output frame
// has src/dst MAC swapped vs the input. Uses the compiled example binary via `cargo run`.
use std::process::Command;

#[test]
fn l2fwd_pcap_swaps_macs() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let input = format!("{dir}/tests/data/l2fwd_in.pcap");
    let out = format!("{dir}/tests/data/l2fwd_out.pcap");
    let _ = std::fs::remove_file(&out);

    // Run the example under the nix shell EAL, pcap backend. `cargo run` finds the example.
    let status = Command::new("cargo")
        .args(["run", "-p", "nfkit", "--example", "l2fwd", "--", "pcap", &input, &out])
        .current_dir(format!("{dir}/.."))
        .status()
        .expect("run l2fwd");
    assert!(status.success());

    // Verify with scapy: each out frame's dst==in src and src==in dst.
    let py = format!(
        r#"from scapy.all import rdpcap
i=rdpcap("{input}"); o=rdpcap("{out}")
assert len(o)==len(i)==4, (len(i),len(o))
for a,b in zip(i,o):
    assert b.dst==a.src and b.src==a.dst, (a.summary(),b.summary())
print("OK")"#
    );
    let s = Command::new("python3").arg("-c").arg(py).status().expect("scapy verify");
    assert!(s.success(), "MAC-swap verification failed");
}
```

Note: this test shells out to `cargo run` + `python3`, so it must itself run inside `nix develop`. It is an integration test; keep it in `tests/` and it will run under `cargo test -p nfkit` when invoked inside the shell. If nested `cargo run` inside `cargo test` is problematic (target-dir lock), instead build the example once (`cargo build --example l2fwd`) and invoke the built binary path `target/debug/examples/l2fwd` directly — do that if the nested invocation deadlocks.

- [ ] **Step 3: Run**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test l2fwd_pcap -- --test-threads=1'`
Expected: PASS (`OK`, MACs swapped on all 4 frames).

- [ ] **Step 4: Commit**

```bash
git add flowplane/nfkit/tests/l2fwd_pcap.rs flowplane/nfkit/tests/data/l2fwd_in.pcap
git commit -m "test(nfkit): deterministic net_pcap l2fwd MAC-swap DoD"
```

---

## Task 9: Gated af_xdp veth loopback (privileged e2e)

**Files:**
- Create: `hack/dpdk/afxdp-loopback.sh`
- Create: `flowplane/nfkit/tests/afxdp_loopback.rs`

- [ ] **Step 1: Write the loopback harness script**

Create `hack/dpdk/afxdp-loopback.sh` (executable):

```bash
#!/usr/bin/env bash
# af_xdp veth loopback e2e for the nfkit l2fwd example. Requires root + reserved hugepages.
# Exits 77 (skip) if prerequisites are missing; 0 on success; non-zero on failure.
set -euo pipefail

need_skip() { echo "SKIP: $1" >&2; exit 77; }
[ "$(id -u)" -eq 0 ] || need_skip "not root (veth + af_xdp need CAP_NET_ADMIN)"
[ "$(awk '/HugePages_Total/{print $2}' /proc/meminfo)" -gt 0 ] || need_skip "no hugepages reserved (sudo sysctl vm.nr_hugepages=1024)"

VV0=nfkitvv0; VV1=nfkitvv1
cleanup() { ip link del "$VV0" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
ip link add "$VV0" type veth peer name "$VV1"
ip link set "$VV0" up; ip link set "$VV1" up

BIN="${L2FWD_BIN:?set L2FWD_BIN to the built example path}"
# Run l2fwd on af_xdp bound to VV0 in the background.
"$BIN" afxdp "$VV0" &
L2FWD=$!
sleep 2

# Send one frame into VV1; it arrives on VV0 for DPDK; l2fwd swaps MAC + tx back out VV0 -> VV1.
python3 - "$VV1" <<'PY'
import sys, time
from scapy.all import Ether, IP, UDP, sendp, sniff, AsyncSniffer
iface=sys.argv[1]
snf=AsyncSniffer(iface=iface, count=1, timeout=5,
                 lfilter=lambda p: p.haslayer(Ether) and p[Ether].src=="22:22:22:22:22:22")
snf.start(); time.sleep(0.3)
sendp(Ether(src="11:11:11:11:11:11",dst="22:22:22:22:22:22")/IP(dst="10.0.0.2")/UDP()/b"x", iface=iface, verbose=0)
res=snf.stop()
assert res and len(res)==1, "did not receive the MAC-swapped frame back"
print("LOOPBACK OK")
PY
RC=$?
kill "$L2FWD" 2>/dev/null || true
exit $RC
```

- [ ] **Step 2: Write the gated test**

Create `flowplane/nfkit/tests/afxdp_loopback.rs`:

```rust
// Drives hack/dpdk/afxdp-loopback.sh. SKIPS (passes) when unprivileged / no hugepages / af_xdp
// absent (script exits 77). Runs the real e2e in a privileged job.
use std::process::Command;

#[test]
fn afxdp_veth_loopback() {
    let root = format!("{}/..", env!("CARGO_MANIFEST_DIR")); // repo root
    // Build the example first so the script can exec it.
    let build = Command::new("cargo")
        .args(["build", "-p", "nfkit", "--example", "l2fwd"])
        .current_dir(&root)
        .status()
        .expect("build example");
    assert!(build.success());
    let bin = format!("{root}/target/debug/examples/l2fwd");

    let status = Command::new("bash")
        .arg(format!("{root}/hack/dpdk/afxdp-loopback.sh"))
        .env("L2FWD_BIN", &bin)
        .current_dir(&root)
        .status()
        .expect("run loopback script");
    match status.code() {
        Some(0) => {}                       // e2e passed
        Some(77) => eprintln!("afxdp loopback skipped (unprivileged / no hugepages)"),
        other => panic!("afxdp loopback failed: exit {other:?}"),
    }
}
```

- [ ] **Step 3: Run (will SKIP on this dev host — unprivileged / 0 hugepages)**

Run: `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit --test afxdp_loopback -- --nocapture'`
Expected: prints "afxdp loopback skipped ..." and PASSES (exit 77 path). To actually exercise it: `sudo sysctl -w vm.nr_hugepages=1024` and run the script as root with `L2FWD_BIN` set (document this; do not require root in the default test run).

- [ ] **Step 4: Add a Makefile target for the privileged run (optional convenience)**

Add to `Makefile`:
```makefile
.PHONY: dpdk-afxdp-loopback
dpdk-afxdp-loopback: ## Run the af_xdp veth loopback e2e (needs sudo + hugepages)
	cargo build -p nfkit --example l2fwd
	sudo L2FWD_BIN=$(PWD)/target/debug/examples/l2fwd hack/dpdk/afxdp-loopback.sh
```

- [ ] **Step 5: Commit**

```bash
git add hack/dpdk/afxdp-loopback.sh flowplane/nfkit/tests/afxdp_loopback.rs Makefile
git commit -m "test(nfkit): gated af_xdp veth loopback e2e (skips unprivileged) + make target"
```

---

## Definition of Done (M2)

- `nix develop --command bash -c 'cd flowplane && cargo test -p nfkit -- --test-threads=1'` passes: mempool, mbuf, port, runtime, backend, and `l2fwd_pcap` (MAC-swap on net_pcap, `--no-huge`), with `afxdp_loopback` cleanly skipping when unprivileged.
- `cargo run -p nfkit --example l2fwd -- null` boots EAL + workers without crashing.
- `dpdk-sys` builds DPDK with the `net/af_xdp` PMD; cache still hits after the one rebuild.
- Default host build + `flowplane-sim` tests untouched (nfkit/dpdk-sys opt-in).
- With `sudo sysctl vm.nr_hugepages=1024`, `make dpdk-afxdp-loopback` forwards a real frame end-to-end over veth.

**Next milestone (M3, separate plan):** `MbufPkt: Pkt` + `DpdkMaps: Maps` → compose `flowplane-core` on the uplink; byte-parity vs the sim via `net_pcap` (the Phase-2 datapath gate).
