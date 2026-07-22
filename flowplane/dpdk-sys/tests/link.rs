// Assigning each function item to a typed fn-pointer forces the linker to resolve the
// symbol at link time (the shim symbol + the DPDK EAL entry point). We don't call them.
#[test]
fn symbols_resolve() {
    let rx: unsafe extern "C" fn(u16, u16, *mut *mut dpdk_sys::rte_mbuf, u16) -> u16 =
        dpdk_sys::nfkit_eth_rx_burst;
    let init: unsafe extern "C" fn(
        std::os::raw::c_int,
        *mut *mut std::os::raw::c_char,
    ) -> std::os::raw::c_int = dpdk_sys::rte_eal_init;
    let prepend: unsafe extern "C" fn(*mut dpdk_sys::rte_mbuf, u16) -> *mut u8 =
        dpdk_sys::nfkit_pktmbuf_prepend;
    let mtod: unsafe extern "C" fn(*mut dpdk_sys::rte_mbuf) -> *mut u8 =
        dpdk_sys::nfkit_pktmbuf_mtod;
    // fn pointers are never null in Rust, so we just check that the symbols bound.
    let _ = rx;
    let _ = init;
    let _ = prepend;
    let _ = mtod;
}
