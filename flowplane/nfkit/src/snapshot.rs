//! Serialize/restore a [`DpdkMaps`] conntrack+NAT snapshot for a blue-green hitless DPDK upgrade:
//! the OLD binary exports its per-lcore flow state, the NEW binary restores it into a fresh
//! `DpdkMaps` so established flows survive the swap.
//!
//! # Scope
//! Only the FLOW tables are snapshotted: `conntrack`, `nat`, and `nat_ips`. The config maps
//! (routes / fw / lb / maglev / underlay / dhcp / meter) are re-derived from the control plane on
//! the new instance and are deliberately NOT carried across. In particular the `meter` map holds
//! transient EDT pacing cursors that are pointless to hand off.
//!
//! # Format (host-endian, same-arch/host handoff — a LOCAL upgrade, not a wire format)
//! ```text
//! MAGIC (b"NFKS", 4 bytes) ++ VERSION (u16 LE) ++
//!   conntrack: u32 count ++ count × (CtKey bytes ++ CtEntry bytes)
//!   nat:       u32 count ++ count × (NatKey bytes ++ NatValue bytes)
//!   nat_ips:   u32 count ++ count × (NatIpKey bytes ++ u8 value byte)
//! ```
//! The blob is VERSIONED: [`restore_maps`] REFUSES a magic/version mismatch (returns an error and
//! lets the caller fall back to accepting flow loss) rather than corrupting the new instance's
//! state. Every read in `restore_maps` is bounds-checked — a truncated or garbage blob returns
//! `Err`, never panics or reads out of bounds.
//!
//! The POD types (`CtKey`/`CtEntry`/`NatKey`/`NatValue`/`NatIpKey`) are all `#[repr(C)] Copy`, so
//! an entry is serialized as an exact `size_of::<T>()` byte copy and deserialized the same way.
//! Because both directions run on the same architecture and host, endianness and padding are
//! consistent by construction.

use crate::dpdk_maps::NatIpKey;
use crate::DpdkMaps;
use flowplane_common::{CtEntry, CtKey, NatKey, NatValue};
use flowplane_core::maps::Maps;
use std::mem::size_of;

/// Magic marking a nfkit snapshot blob ("NFKit Snapshot").
const MAGIC: [u8; 4] = *b"NFKS";
/// On-disk format version. Bump on any layout change to the tables or the framing.
const VERSION: u16 = 1;

/// A snapshot could not be restored. Held reason is a static string for cheap logging.
#[derive(Debug, PartialEq, Eq)]
pub struct SnapshotError(pub &'static str);

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "snapshot restore failed: {}", self.0)
    }
}

impl std::error::Error for SnapshotError {}

/// Per-table counts of entries restored — asserted against the source in the round-trip test.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct RestoreStats {
    pub conntrack: usize,
    pub nat: usize,
    pub nat_ips: usize,
}

// ── POD ↔ bytes helpers ──────────────────────────────────────────────────────

/// Append the raw bytes of a `#[repr(C)] Copy` POD value to `out`.
fn push_pod<T: Copy>(out: &mut Vec<u8>, v: &T) {
    // SAFETY: `T` is `#[repr(C)] Copy` POD (all call sites pass CtKey/CtEntry/NatKey/NatValue/
    // NatIpKey/u8). Reading its `size_of::<T>()` bytes as a `&[u8]` is a plain byte view of a live,
    // aligned value; we only read and immediately copy into `out`.
    let bytes = unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) };
    out.extend_from_slice(bytes);
}

/// Read a `#[repr(C)] Copy` POD value out of `buf` at `off`, advancing `off`. Bounds-checked:
/// returns `Err` (never panics / reads OOB) if fewer than `size_of::<T>()` bytes remain.
fn read_pod<T: Copy>(buf: &[u8], off: &mut usize) -> Result<T, SnapshotError> {
    let end = off
        .checked_add(size_of::<T>())
        .ok_or(SnapshotError("length overflow"))?;
    let slice = buf
        .get(*off..end)
        .ok_or(SnapshotError("truncated: entry body"))?;
    // SAFETY: `slice` is exactly `size_of::<T>()` bytes (checked above). `read_unaligned` copies
    // those bytes into a `T` with no alignment requirement on the source. `T` is `#[repr(C)] Copy`
    // POD, so every bit pattern of that length is a valid value (no invariants to violate).
    let v = unsafe { std::ptr::read_unaligned(slice.as_ptr().cast::<T>()) };
    *off = end;
    Ok(v)
}

/// Read a bounds-checked `u32` little-endian count.
fn read_count(buf: &[u8], off: &mut usize) -> Result<usize, SnapshotError> {
    let end = off.checked_add(4).ok_or(SnapshotError("length overflow"))?;
    let slice = buf
        .get(*off..end)
        .ok_or(SnapshotError("truncated: table count"))?;
    let n = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
    *off = end;
    Ok(n as usize)
}

// ── serialize ────────────────────────────────────────────────────────────────

/// Serialize the FLOW tables (conntrack + nat + nat_ips) of `maps` into a versioned blob.
#[must_use]
pub fn serialize_maps(maps: &DpdkMaps) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());

    // conntrack
    let mut ct: Vec<(CtKey, CtEntry)> = Vec::new();
    maps.conntrack_for_each(|k, v| ct.push((*k, *v)));
    out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
    for (k, v) in &ct {
        push_pod(&mut out, k);
        push_pod(&mut out, v);
    }

    // nat
    let mut nat: Vec<(NatKey, NatValue)> = Vec::new();
    maps.nat_for_each(|k, v| nat.push((*k, *v)));
    out.extend_from_slice(&(nat.len() as u32).to_le_bytes());
    for (k, v) in &nat {
        push_pod(&mut out, k);
        push_pod(&mut out, v);
    }

    // nat_ips
    let mut nat_ips: Vec<(NatIpKey, u8)> = Vec::new();
    maps.nat_ips_for_each(|k, v| nat_ips.push((*k, *v)));
    out.extend_from_slice(&(nat_ips.len() as u32).to_le_bytes());
    for (k, v) in &nat_ips {
        push_pod(&mut out, k);
        push_pod(&mut out, v);
    }

    out
}

// ── restore ──────────────────────────────────────────────────────────────────

/// Restore a blob produced by [`serialize_maps`] into a FRESH `DpdkMaps`, re-inserting every flow
/// entry via the existing setters. Refuses a magic/version mismatch and bounds-checks every read.
///
/// # Errors
/// - `SnapshotError("bad magic")` / `SnapshotError("unsupported version")` on header mismatch.
/// - A `truncated: …` error if the blob ends mid-header, mid-count, or mid-entry.
pub fn restore_maps(maps: &mut DpdkMaps, blob: &[u8]) -> Result<RestoreStats, SnapshotError> {
    // header — the magic occupies bytes 0..4, so parsing resumes at offset 4.
    let magic = blob.get(0..4).ok_or(SnapshotError("truncated: magic"))?;
    if magic != MAGIC {
        return Err(SnapshotError("bad magic"));
    }
    let mut off = 4usize;
    let ver = read_pod::<u16>(blob, &mut off).map_err(|_| SnapshotError("truncated: version"))?;
    if ver != VERSION {
        return Err(SnapshotError("unsupported version"));
    }

    // conntrack
    let ct_n = read_count(blob, &mut off)?;
    for _ in 0..ct_n {
        let k = read_pod::<CtKey>(blob, &mut off)?;
        let v = read_pod::<CtEntry>(blob, &mut off)?;
        maps.conntrack_insert(k, v);
    }

    // nat
    let nat_n = read_count(blob, &mut off)?;
    for _ in 0..nat_n {
        let k = read_pod::<NatKey>(blob, &mut off)?;
        let v = read_pod::<NatValue>(blob, &mut off)?;
        maps.add_nat(k, v);
    }

    // nat_ips
    let ni_n = read_count(blob, &mut off)?;
    for _ in 0..ni_n {
        let k = read_pod::<NatIpKey>(blob, &mut off)?;
        // Consume the dummy value byte (bounds-checked) even though add_nat_ip re-derives it.
        let _v = read_pod::<u8>(blob, &mut off)?;
        maps.add_nat_ip(k.vni, k.ipv4);
    }

    Ok(RestoreStats {
        conntrack: ct_n,
        nat: nat_n,
        nat_ips: ni_n,
    })
}
