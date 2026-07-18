use flowplane_core::pkt::Pkt;

pub struct VecPkt {
    buf: Vec<u8>,
    logical_len: usize,
}

impl VecPkt {
    pub fn from_bytes(b: &[u8]) -> Self {
        Self {
            buf: b.to_vec(),
            logical_len: b.len(),
        }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
    /// Override the logical (wire) length to simulate a non-linear skb whose true length
    /// exceeds the linear buffer. Used to exercise the encap inner-length path.
    pub fn set_logical_len(&mut self, n: usize) {
        self.logical_len = n;
    }
}

impl Pkt for VecPkt {
    fn len(&self) -> usize {
        self.buf.len()
    }
    fn logical_len(&self) -> usize {
        self.logical_len
    }
    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        let end = off.checked_add(N)?;
        if end > self.buf.len() {
            return None;
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[off..end]);
        Some(out)
    }
    fn write_bytes(&mut self, off: usize, src: &[u8]) -> bool {
        let end = match off.checked_add(src.len()) {
            Some(e) => e,
            None => return false,
        };
        if end > self.buf.len() {
            return false;
        }
        self.buf[off..end].copy_from_slice(src);
        true
    }
    fn grow_head(&mut self, delta: usize) -> bool {
        let mut prefix = vec![0u8; delta];
        prefix.extend_from_slice(&self.buf);
        self.buf = prefix;
        self.logical_len += delta;
        true
    }
    fn shrink_head(&mut self, delta: usize) -> bool {
        if delta > self.buf.len() {
            return false;
        }
        self.buf.drain(0..delta);
        self.logical_len -= delta;
        true
    }
    fn set_tail(&mut self, new_len: usize) -> bool {
        // Grow (zero-fill) or shrink the linear buffer at the tail, mirroring bpf_xdp_adjust_tail /
        // bpf_skb_change_tail's absolute-length resize.
        self.buf.resize(new_len, 0);
        self.logical_len = new_len;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip() {
        let mut p = VecPkt::from_bytes(&[0u8; 32]);
        assert!(p.write_bytes(4, &[0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(p.read_array::<4>(4), Some([0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(p.read_u16_be(4), Some(0xdead));
        assert_eq!(p.read_array::<4>(30), None); // out of range
    }

    #[test]
    fn grow_then_shrink_head() {
        let mut p = VecPkt::from_bytes(&[1, 2, 3, 4]);
        assert!(p.grow_head(2));
        assert_eq!(p.len(), 6);
        assert!(p.write_bytes(0, &[9, 9]));
        assert!(p.shrink_head(2));
        assert_eq!(p.len(), 4);
        assert_eq!(p.read_array::<4>(0), Some([1, 2, 3, 4]));
    }

    #[test]
    fn logical_len_defaults_to_buf_and_tracks_resize() {
        let mut p = VecPkt::from_bytes(&[0u8; 20]);
        assert_eq!(p.logical_len(), 20);
        assert!(p.grow_head(14));
        assert_eq!(p.logical_len(), 34); // tracks grow
        assert!(p.shrink_head(14));
        assert_eq!(p.logical_len(), 20); // tracks shrink
        p.set_logical_len(1500); // simulate non-linear skb
        assert_eq!(p.logical_len(), 1500);
        assert_eq!(p.len(), 20); // linear buffer unchanged
    }
}
