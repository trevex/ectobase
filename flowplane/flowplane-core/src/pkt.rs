//! Packet access abstraction. eBPF impl uses raw ptr + manual bounds checks (verifier-safe);
//! native impl uses a Vec. Typed access is FIXED-SIZE (const-generic N) so the eBPF impl stays
//! verifier-friendly — no runtime-length slices cross the trait boundary.

/// What the glue should do with the packet after core returns.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Action {
    Pass,
    Drop,
    /// Redirect out this ifindex (plain `bpf_redirect`).
    Redirect(u32),
    /// Redirect to the netns PEER of this ifindex (`bpf_redirect_peer`): inject at the peer's ingress
    /// in the pod netns in the same softirq, skipping the primary's xmit + host-stack re-entry. Only
    /// valid for a veth/netkit device (a `peer_capable` local-delivery target); the sim treats it as a
    /// plain delivery to the ifindex (the peer hop is a kernel-datapath detail it doesn't model).
    RedirectPeer(u32),
}

#[allow(clippy::len_without_is_empty)]
pub trait Pkt {
    /// Current frame length in bytes.
    fn len(&self) -> usize;
    /// Logical (wire) length of the packet in bytes.
    ///
    /// On skb-backed contexts this is `skb->len`, which may exceed the linear head
    /// (`data_end - data`). On XDP and linear buffers it equals the head length. The encap
    /// header writer uses this (not `len()`) so a non-linear skb gets a correct outer payload
    /// length.
    fn logical_len(&self) -> usize;
    /// Copy `N` bytes at `off`, bounds-checked. None if out of range.
    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]>;
    /// Overwrite `src.len()` bytes at `off`, bounds-checked. false if out of range.
    fn write_bytes(&mut self, off: usize, src: &[u8]) -> bool;

    /// Overwrite a FIXED `N` bytes at `off`, bounds-checked. false if out of range.
    ///
    /// This is the write-side dual of [`read_array`](Pkt::read_array): passing the length as a const
    /// generic (rather than a runtime slice via [`write_bytes`](Pkt::write_bytes)) lets the eBPF impl
    /// lower each write to a single fixed-width store instead of a byte loop — materially smaller
    /// bytecode on the hot path (keeps large in-place rewriters like SNAT inside the XDP verifier's
    /// single-function budget). The default delegates to `write_bytes` for impls that don't override.
    #[inline(always)]
    fn write_array<const N: usize>(&mut self, off: usize, src: &[u8; N]) -> bool {
        self.write_bytes(off, src)
    }
    /// Prepend `delta` bytes of headroom (encap). Models bpf_xdp_adjust_head(-delta).
    fn grow_head(&mut self, delta: usize) -> bool;
    /// Remove `delta` bytes from the front (decap). Models bpf_xdp_adjust_head(+delta).
    fn shrink_head(&mut self, delta: usize) -> bool;

    /// Resize the frame to exactly `new_len` bytes at the tail (grow or shrink). Models
    /// `bpf_xdp_adjust_tail` / `bpf_skb_change_tail` — the DHCPv4 responder grows the frame to a
    /// constant `REPLY_LEN` before writing the fixed-layout reply. The eBPF `RawPkt` impl does NOT
    /// resize itself (the XDP/tc glue resizes with the native primitive, then wraps the grown frame
    /// in a fresh `RawPkt`); only owning buffers (`VecPkt`) implement this. The default is a no-op
    /// returning false so non-resizable impls stay usable for callers that never resize.
    #[inline(always)]
    fn set_tail(&mut self, _new_len: usize) -> bool {
        false
    }

    #[inline(always)]
    fn read_u16_be(&self, off: usize) -> Option<u16> {
        self.read_array::<2>(off).map(u16::from_be_bytes)
    }
    #[inline(always)]
    fn read_u8(&self, off: usize) -> Option<u8> {
        self.read_array::<1>(off).map(|b| b[0])
    }
}
