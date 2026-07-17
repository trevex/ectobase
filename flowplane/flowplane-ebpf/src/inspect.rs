use aya_ebpf::{bindings::xdp_action, helpers::bpf_xdp_load_bytes, programs::XdpContext};

use crate::maps::INSPECT;

pub fn try_inspect(ctx: &XdpContext) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = (data_end - data) as u32;

    if let Some(entry) = INSPECT.get_ptr_mut(0) {
        unsafe {
            (*entry).len = pkt_len;
            (*entry).seen = (*entry).seen.wrapping_add(1);

            // Zero-fill so bytes beyond the actual packet stay 0.
            (*entry).bytes = [0u8; 32];

            // Ask for a fixed 32 bytes. bpf_xdp_load_bytes does its own bounds
            // check: if the packet is shorter than 32 bytes it returns an error
            // and leaves our zeroed buffer intact — no verifier issue with a
            // variable length.
            let buf_ptr = (*entry).bytes.as_mut_ptr() as *mut core::ffi::c_void;
            let _ = bpf_xdp_load_bytes(ctx.ctx, 0, buf_ptr, 32);
        }
    }

    xdp_action::XDP_PASS
}
