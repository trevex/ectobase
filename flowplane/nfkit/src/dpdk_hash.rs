//! Safe typed wrapper over a DPDK `rte_hash`. Key = the raw bytes of `K` (K must be `#[repr(C)]` POD,
//! no padding — key_len = size_of::<K>()). Values live in a companion slab indexed by the stable
//! position `rte_hash_add_key` returns. Any hash function is fine — correctness is the exact
//! key->value mapping, not the hash values.
use std::ffi::CString;
use std::marker::PhantomData;
use std::os::raw::c_void;
use std::ptr::NonNull;

#[derive(Debug)]
pub struct HashError;

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rte_hash operation failed")
    }
}

impl std::error::Error for HashError {}

pub struct DpdkHash<K: Copy, V: Copy> {
    raw: NonNull<dpdk_sys::rte_hash>,
    slab: Vec<Option<V>>,
    _k: PhantomData<K>,
}

impl<K: Copy, V: Copy> DpdkHash<K, V> {
    /// # Errors
    /// Returns `HashError` if `rte_hash_create` fails (name clash / OOM).
    pub fn new(name: &str, entries: u32, socket_id: i32) -> Result<Self, HashError> {
        let cname = CString::new(name).map_err(|_| HashError)?;
        let mut params: dpdk_sys::rte_hash_parameters = unsafe { std::mem::zeroed() };
        params.name = cname.as_ptr();
        params.entries = entries;
        params.key_len = std::mem::size_of::<K>() as u32;
        params.socket_id = socket_id;
        // SAFETY: params fully initialized (zeroed then set); name lives for the call. hash_func=NULL
        // -> DPDK default.
        let raw = unsafe { dpdk_sys::rte_hash_create(&params) };
        let raw = NonNull::new(raw).ok_or(HashError)?;
        Ok(Self {
            raw,
            slab: vec![None; entries as usize],
            _k: PhantomData,
        })
    }

    /// Insert (or overwrite) key -> value. Returns `false` if the table is full
    /// (`rte_hash_add_key` < 0); the value is then NOT stored. Deterministic: the value slab grows
    /// on demand to fit whatever position `rte_hash` returns, so it can never index out of range
    /// regardless of capacity alignment or the number of writers.
    pub fn insert(&mut self, k: &K, v: V) -> bool {
        // SAFETY: k points to size_of::<K>() == key_len bytes; the hash copies the key.
        // rte_hash_add_key takes *const rte_hash and *const c_void (read-only access).
        let pos = unsafe {
            dpdk_sys::rte_hash_add_key(self.raw.as_ptr(), (k as *const K).cast::<c_void>())
        };
        if pos < 0 {
            return false; // table full (-ENOSPC) — observable to the caller
        }
        let idx = pos as usize;
        if idx >= self.slab.len() {
            self.slab.resize(idx + 1, None); // grow to fit; V: Copy, no pointers into slab
        }
        self.slab[idx] = Some(v);
        true
    }

    /// Number of live entries, via `rte_hash_count`. Observability only.
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

    /// Visit every live `(key, value)` entry. Order is unspecified (rte_hash iteration order is not
    /// defined). The value comes from the companion `slab` (rte_hash stores only keys); it is indexed
    /// by the position `rte_hash_iterate` returns. Copies `K` out per entry (`Copy` POD) so the
    /// closure cannot hold a borrow of the live in-table key pointer.
    pub fn for_each(&self, mut f: impl FnMut(&K, &V)) {
        let mut next: u32 = 0;
        let mut key_ptr: *const c_void = std::ptr::null();
        let mut data_ptr: *mut c_void = std::ptr::null_mut();
        loop {
            // SAFETY: `self.raw` is a valid rte_hash handle; `key_ptr`/`data_ptr`/`next` are valid
            // out-params. `rte_hash_iterate` returns the entry position (>=0) or a negative errno
            // (-ENOENT at end, -EINVAL on bad args). We only deref `key_ptr` when pos >= 0.
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
            // SAFETY: on a successful iteration step, `key_ptr` points to the stored key, which is
            // exactly key_len == size_of::<K>() bytes and valid until the next table mutation. `K`
            // is `Copy` POD, so we read a bytewise copy; the closure then never holds the live
            // pointer's borrow.
            let k: K = unsafe { std::ptr::read(key_ptr.cast::<K>()) };
            if let Some(Some(v)) = self.slab.get(pos as usize) {
                f(&k, v);
            }
        }
    }

    #[must_use]
    pub fn get(&self, k: &K) -> Option<V> {
        // SAFETY: k points to key_len bytes; read-only lookup.
        let pos = unsafe {
            dpdk_sys::rte_hash_lookup(self.raw.as_ptr(), (k as *const K).cast::<c_void>())
        };
        if pos >= 0 {
            self.slab.get(pos as usize).copied().flatten()
        } else {
            None
        }
    }
}

impl<K: Copy, V: Copy> Drop for DpdkHash<K, V> {
    fn drop(&mut self) {
        // SAFETY: sole owner; frees the hash.
        unsafe { dpdk_sys::rte_hash_free(self.raw.as_ptr()) }
    }
}
