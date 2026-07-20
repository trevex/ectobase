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

    pub fn insert(&mut self, k: &K, v: V) {
        // SAFETY: k points to size_of::<K>() == key_len bytes; the hash copies the key.
        // rte_hash_add_key takes *const rte_hash and *const c_void (read-only access).
        let pos = unsafe {
            dpdk_sys::rte_hash_add_key(self.raw.as_ptr(), (k as *const K).cast::<c_void>())
        };
        if pos >= 0 {
            self.slab[pos as usize] = Some(v);
        }
    }

    #[must_use]
    pub fn get(&self, k: &K) -> Option<V> {
        // SAFETY: k points to key_len bytes; read-only lookup.
        let pos = unsafe {
            dpdk_sys::rte_hash_lookup(self.raw.as_ptr(), (k as *const K).cast::<c_void>())
        };
        if pos >= 0 {
            self.slab[pos as usize]
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
