//! DSR Geneve-option encode/decode: the VIP identity the edge dispatches to the backend so the
//! backend can reverse-SNAT the guest reply src -> VIP. Payload of the Geneve DSR TLV. Layout
//! frozen by the B1 spike (verifier-accepted on the collect_md device).

use flowplane_common::DsrOpt;

/// Total buffer = 4-byte Geneve option header + 20-byte DsrOpt payload.
pub const DSR_OPT_BUF_LEN: usize = 24;

// Geneve option identity (private class/type) — the exact bytes the B1 spike round-tripped.
const OPT_CLASS: u16 = 0x0108;
const OPT_TYPE: u8 = 0x01;
const OPT_LEN_WORDS: u8 = 5; // 20-byte payload / 4

/// Serialize a DsrOpt into the Geneve option buffer (header + payload).
pub fn encode(opt: &DsrOpt) -> [u8; DSR_OPT_BUF_LEN] {
    let mut b = [0u8; DSR_OPT_BUF_LEN];
    b[0..2].copy_from_slice(&OPT_CLASS.to_be_bytes());
    b[2] = OPT_TYPE;
    b[3] = OPT_LEN_WORDS;
    b[4] = opt.family;
    b[5] = 0;
    b[6..8].copy_from_slice(&opt.port.to_be_bytes());
    b[8..24].copy_from_slice(&opt.vip);
    b
}

/// Parse a DsrOpt out of a Geneve option buffer. None if the class/type don't match.
pub fn decode(b: &[u8; DSR_OPT_BUF_LEN]) -> Option<DsrOpt> {
    let class = u16::from_be_bytes([b[0], b[1]]);
    if class != OPT_CLASS || b[2] != OPT_TYPE {
        return None;
    }
    let mut vip = [0u8; 16];
    vip.copy_from_slice(&b[8..24]);
    Some(DsrOpt {
        family: b[4],
        _pad: 0,
        port: u16::from_be_bytes([b[6], b[7]]),
        vip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsr_opt_round_trip_v6() {
        let opt = DsrOpt {
            family: 1,
            _pad: 0,
            port: 443,
            vip: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        assert_eq!(decode(&encode(&opt)), Some(opt));
    }

    #[test]
    fn dsr_opt_round_trip_v4() {
        let opt = DsrOpt {
            family: 0,
            _pad: 0,
            port: 80,
            vip: [203, 0, 113, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(decode(&encode(&opt)), Some(opt));
    }

    #[test]
    fn decode_rejects_foreign_option() {
        let mut b = encode(&DsrOpt {
            family: 0,
            _pad: 0,
            port: 80,
            vip: [1; 16],
        });
        b[0] = 0xFF; // wrong class
        assert_eq!(decode(&b), None);
    }

    #[test]
    fn buf_len_matches_ebpf_wrapper() {
        // Must equal the eBPF wrapper's DSR_OPT_BUF_LEN (flowplane_ebpf::tunnel::DSR_OPT_BUF_LEN = 24).
        assert_eq!(DSR_OPT_BUF_LEN, 24);
    }
}
