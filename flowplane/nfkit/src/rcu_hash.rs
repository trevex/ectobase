//! `RcuHash<K, V>`: a lock-free-reader (`RW_CONCURRENCY_LF`) + QSBR-RCU typed hash whose VALUE is
//! stored inside the `rte_hash`'s own per-key data pointer, NOT in a Rust-side slab.
//!
//! WHY A DISTINCT TYPE FROM `DpdkHash`: `DpdkHash<K,V>` keeps values in a companion
//! `Vec<Option<V>>` slab indexed by the position `rte_hash_add_key` returns. That is perfectly fine
//! for the SINGLE-THREADED per-lcore `DpdkMaps` (no concurrency), but DPDK's LF+RCU + QSBR only
//! protects the C-side KEY table — it does NOT protect a Rust-side value slab. A concurrent reader
//! of `DpdkHash::new_lf_rcu` could therefore (a) read a torn multi-word `V` mid-write, or (b)
//! use-after-free if the `Vec` reallocated on growth. `RcuHash` fixes this by storing the value
//! where DPDK's RCU lifetime rules DO apply: the per-key `pdata` pointer.
//!
//! MECHANISM (verified against DPDK 25.11 `rte_cuckoo_hash.c`):
//!  * `insert(k, v)`: `p = Box::into_raw(Box::new(v)) as *mut c_void; rte_hash_add_key_data(h, k, p)`.
//!    The store to `pdata` is a `memory_order_release` atomic exchange (`search_and_update`), so a
//!    lock-free reader doing `rte_hash_lookup_data` (acquire) never observes a half-published box.
//!  * `get(k)`: `rte_hash_lookup_data(h, k, &mut data)`; on hit, copy the whole `V` OUT of the box
//!    (`V: Copy`). The box stays alive for the read because reclamation is RCU-deferred.
//!  * RECLAMATION — both cases handled by rte_hash itself once `free_key_data_func` is configured:
//!     - OVERWRITE (`add_key_data` on an existing key): `search_and_update` release-exchanges the
//!       new pointer in and calls `__rte_hash_rcu_auto_free_old_data(h, old)` → the OLD box is
//!       enqueued on the QSBR defer queue and freed via `free_key_data_func` only after a grace
//!       period. (rte_hash.h: "If RCU is configured with a free_key_data_func callback, the old
//!       data is automatically deferred-freed via RCU.")
//!     - DELETE (`rte_hash_del_key`): the removed key's `pdata` is likewise handed to
//!       `free_key_data_func` after a grace period via `__hash_rcu_qsbr_free_resource`.
//!
//!    So there is NO need for a manual `rte_rcu_qsbr_synchronize`-before-free: wiring
//!    `free_key_data_func = drop(Box::from_raw(V))` makes overwrite AND delete fully RCU-safe.
//!
//! SINGLE-WRITER MODEL: no `MULTI_WRITER_ADD`. `insert`/`remove` take `&mut self`; the datapath
//! lcores hold only `&self` and call `get`/`for_each`.
//!
//! ALL-ZERO KEY CONSTRAINT: DPDK's cuckoo hash reserves an internal dummy key-store slot at index 0
//! and uses `0` for both `EMPTY_SLOT` and `NULL_SIGNATURE` (buckets are memset to zero). A key whose
//! bytes are ALL ZERO aliases that dummy slot in `search_and_update`, so — with RCU value auto-free
//! configured — inserting an all-zero key spuriously frees the dummy slot's data pointer and
//! double-frees. This was reproduced directly (key `0` double-frees; key `55` is clean, matching
//! DPDK's own `test_hash_rcu_qsbr_replace_auto_free`). Therefore `RcuHash` callers MUST NOT use an
//! all-zero key. `SharedConfigMaps` keys (VNI/IP tuples, interface ids, …) are never all-zero in
//! practice; if a map could legitimately key on all-zero bytes, offset it by a non-zero base or
//! reserve that key. `insert` debug-asserts the key is non-zero to catch violations early.

use std::ffi::CString;
use std::marker::PhantomData;
use std::os::raw::c_void;
use std::ptr::NonNull;

pub use crate::dpdk_hash::HashError;

/// `free_key_data_func` trampoline: rte_hash calls this (after a grace period) with the value
/// pointer that must be reclaimed — for both the overwrite (old data) and delete cases. We reclaim
/// the `Box<V>` we leaked in `insert`.
///
/// SAFETY: `key_data` is exactly a pointer we produced via `Box::<V>::into_raw` in `insert`, and
/// rte_hash guarantees no reader can still dereference it (grace period elapsed) before this runs.
/// `p` (the configured `key_data_ptr`) is unused/NULL. Boxing back and dropping runs `V`'s
/// destructor and frees the allocation exactly once.
unsafe extern "C" fn free_value<V>(_p: *mut c_void, key_data: *mut c_void) {
    if !key_data.is_null() {
        drop(Box::from_raw(key_data.cast::<V>()));
    }
}

pub struct RcuHash<K: Copy, V: Copy> {
    raw: NonNull<dpdk_sys::rte_hash>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K: Copy, V: Copy> RcuHash<K, V> {
    /// Create a lock-free-reader (`RW_CONCURRENCY_LF`) hash with QSBR RCU attached to `qsbr`, storing
    /// each value inside the rte_hash data pointer (RCU-covered lifetime). Single-writer model.
    ///
    /// # Errors
    /// Returns `HashError` if the name is invalid, `rte_hash_create` fails, or
    /// `rte_hash_rcu_qsbr_add` fails to attach the QSBR variable.
    ///
    /// # Safety
    /// `qsbr` must point to an initialized `rte_rcu_qsbr` that outlives the returned hash.
    pub unsafe fn new_lf_rcu(
        name: &str,
        entries: u32,
        socket_id: i32,
        qsbr: *mut dpdk_sys::rte_rcu_qsbr,
    ) -> Result<Self, HashError> {
        let cname = CString::new(name).map_err(|_| HashError)?;
        let mut params: dpdk_sys::rte_hash_parameters = std::mem::zeroed();
        params.name = cname.as_ptr();
        params.entries = entries;
        params.key_len = std::mem::size_of::<K>() as u32;
        params.socket_id = socket_id;
        params.extra_flag = dpdk_sys::RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF as u8;
        // SAFETY: params fully initialized; name lives for the call. hash_func=NULL -> DPDK default.
        let raw = dpdk_sys::rte_hash_create(&params);
        let raw = NonNull::new(raw).ok_or(HashError)?;

        // RCU config: DQ mode (mode=0), default dq_size, and — crucially — a free_key_data_func so
        // rte_hash auto-reclaims BOTH overwritten (old) values and deleted values after a grace
        // period. key_data_ptr stays NULL (our free fn ignores it).
        let mut cfg: dpdk_sys::rte_hash_rcu_config = std::mem::zeroed();
        cfg.v = qsbr;
        cfg.free_key_data_func = Some(free_value::<V>);
        // rte_hash_rcu_qsbr_add: 0 on success, 1 on error (rte_errno set).
        let rc = dpdk_sys::rte_hash_rcu_qsbr_add(raw.as_ptr(), &mut cfg);
        if rc != 0 {
            dpdk_sys::rte_hash_free(raw.as_ptr());
            return Err(HashError);
        }
        Ok(Self {
            raw,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    /// Insert (or overwrite) `k` -> `v`. Returns `false` if the table is full (`-ENOSPC`); the value
    /// is then NOT stored and the box we allocated is reclaimed immediately (no leak). On overwrite
    /// of an existing key, rte_hash RCU-defers the OLD value box's free (grace period), so a
    /// concurrent lock-free reader still holding the old pointer never sees freed memory.
    pub fn insert(&mut self, k: &K, v: V) -> bool {
        // All-zero keys alias DPDK's reserved dummy slot 0 and double-free under RCU auto-free (see
        // module doc). Catch violations in debug builds; release builds trust the caller.
        debug_assert!(
            {
                // SAFETY: k points to size_of::<K>() readable bytes (K: Copy POD).
                let bytes =
                    unsafe { std::slice::from_raw_parts((k as *const K).cast::<u8>(), size_of::<K>()) };
                bytes.iter().any(|&b| b != 0)
            },
            "RcuHash: all-zero key aliases DPDK's reserved dummy slot; offset keys by a non-zero base"
        );
        let boxed = Box::into_raw(Box::new(v)).cast::<c_void>();
        // SAFETY: k points to size_of::<K>() == key_len bytes; the hash copies the key. `boxed` is a
        // freshly-leaked Box<V>; on success rte_hash owns its reclamation via free_key_data_func.
        let rc = unsafe {
            dpdk_sys::rte_hash_add_key_data(
                self.raw.as_ptr(),
                (k as *const K).cast::<c_void>(),
                boxed,
            )
        };
        if rc == 0 {
            true
        } else {
            // Not stored (table full / invalid). Reclaim the box we just leaked to avoid a leak.
            // SAFETY: `boxed` was produced by Box::into_raw above and was NOT handed to the table.
            unsafe { drop(Box::from_raw(boxed.cast::<V>())) };
            false
        }
    }

    /// Look up `k`, copying the whole value OUT of its RCU-protected box (`V: Copy`). Lock-free and
    /// safe to call concurrently with the single writer's `insert`/`remove`.
    #[must_use]
    pub fn get(&self, k: &K) -> Option<V> {
        let mut data: *mut c_void = std::ptr::null_mut();
        // SAFETY: k points to key_len bytes; read-only lookup. `data` is a valid out-param.
        let rc = unsafe {
            dpdk_sys::rte_hash_lookup_data(
                self.raw.as_ptr(),
                (k as *const K).cast::<c_void>(),
                &mut data,
            )
        };
        if rc >= 0 && !data.is_null() {
            // SAFETY: on a hit, `data` is the release-published `pdata` pointer to a live `Box<V>`
            // whose reclamation is RCU-deferred past this read (the caller reports quiescence AFTER
            // dropping the returned copy). `V: Copy` → a full bytewise copy-out; we never retain the
            // pointer.
            Some(unsafe { *data.cast::<V>() })
        } else {
            None
        }
    }

    /// Delete `k`. Returns `true` if present and removed. rte_hash RCU-defers both the key-slot
    /// recycle AND the value box free (via `free_key_data_func`) until every registered reader has
    /// passed a grace period, so it is safe against concurrent lock-free readers.
    pub fn remove(&mut self, k: &K) -> bool {
        // SAFETY: k points to key_len bytes; rte_hash_del_key reads the key and, with
        // RW_CONCURRENCY_LF + internal RCU, is safe against concurrent lock-free readers.
        let pos = unsafe {
            dpdk_sys::rte_hash_del_key(self.raw.as_ptr(), (k as *const K).cast::<c_void>())
        };
        pos >= 0
    }

    /// Number of live entries, via `rte_hash_count`. Observability only. NOTE: with RCU, deleted
    /// keys can still count until their slot is reclaimed (lazily, after a grace period).
    #[must_use]
    pub fn count(&self) -> usize {
        // SAFETY: `self.raw` is a valid rte_hash handle; read-only count.
        let n = unsafe { dpdk_sys::rte_hash_count(self.raw.as_ptr()) };
        if n < 0 {
            0
        } else {
            n as usize
        }
    }

    /// Visit every live `(key, value)` entry. Order is unspecified. The value comes from the stored
    /// data pointer (RCU box). Copies `K` out per entry so the closure cannot hold a live in-table
    /// key borrow. Intended for control-plane use (snapshotting) — not the lock-free reader path.
    pub fn for_each(&self, mut f: impl FnMut(&K, &V)) {
        let mut next: u32 = 0;
        let mut key_ptr: *const c_void = std::ptr::null();
        let mut data_ptr: *mut c_void = std::ptr::null_mut();
        loop {
            // SAFETY: valid handle; out-params valid. Returns entry position (>=0) or negative at
            // end/on error. We only deref on pos >= 0.
            let pos = unsafe {
                dpdk_sys::rte_hash_iterate(
                    self.raw.as_ptr(),
                    &mut key_ptr,
                    &mut data_ptr,
                    &mut next,
                )
            };
            if pos < 0 {
                break;
            }
            if data_ptr.is_null() {
                continue;
            }
            // SAFETY: on a successful step, `key_ptr` points to key_len == size_of::<K>() bytes and
            // `data_ptr` to the live value box. `K`/`V` are Copy POD; we read bytewise copies.
            let k: K = unsafe { std::ptr::read(key_ptr.cast::<K>()) };
            let v: V = unsafe { *data_ptr.cast::<V>() };
            f(&k, &v);
        }
    }
}

impl<K: Copy, V: Copy> Drop for RcuHash<K, V> {
    fn drop(&mut self) {
        // rte_hash_free does NOT invoke free_key_data_func on entries that are still LIVE at free
        // time (verified in DPDK 25.11 rte_cuckoo_hash.c: it only rte_free()s the key store). It
        // DOES flush pending DEFERRED frees (overwrite/delete boxes) via rte_rcu_qsbr_dq_delete →
        // dq_reclaim(~0). So we must reclaim the currently-live value boxes ourselves here, then let
        // rte_hash_free drain the defer queue and free the table. Drop has exclusive ownership (no
        // concurrent reader/writer), so a plain iterate-and-free is sound.
        let mut next: u32 = 0;
        let mut key_ptr: *const c_void = std::ptr::null();
        let mut data_ptr: *mut c_void = std::ptr::null_mut();
        loop {
            // SAFETY: valid handle; out-params valid; only reclaim on pos >= 0.
            let pos = unsafe {
                dpdk_sys::rte_hash_iterate(
                    self.raw.as_ptr(),
                    &mut key_ptr,
                    &mut data_ptr,
                    &mut next,
                )
            };
            if pos < 0 {
                break;
            }
            if !data_ptr.is_null() {
                // SAFETY: each live entry's data pointer is a Box<V> we leaked in `insert` and never
                // handed to the defer queue (it is still live). Exclusive access in Drop.
                unsafe { drop(Box::from_raw(data_ptr.cast::<V>())) };
            }
        }
        // SAFETY: sole owner. Frees the table and flushes any still-pending deferred value-box frees
        // via the DQ delete path.
        unsafe { dpdk_sys::rte_hash_free(self.raw.as_ptr()) }
    }
}
