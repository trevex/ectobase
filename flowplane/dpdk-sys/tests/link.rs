// Compiling + linking this test proves the DPDK static libs + the shim resolve. We take
// function-pointer values to force the linker to resolve the symbols.
// rte_eal_init itself is exercised by nfkit (Task 5).
#[test]
fn symbols_resolve() {
    // Binding the function to a typed fn-pointer forces the linker to pull in the symbol.
    // Use addr_of on the fn-ptr to get a raw pointer we can check is non-null.
    let rx: unsafe extern "C" fn(u16, u16, *mut *mut dpdk_sys::rte_mbuf, u16) -> u16 =
        dpdk_sys::nfkit_eth_rx_burst;
    let init: unsafe extern "C" fn(
        std::os::raw::c_int,
        *mut *mut std::os::raw::c_char,
    ) -> std::os::raw::c_int = dpdk_sys::rte_eal_init;
    // fn pointers are never null in Rust, so we just check that the symbol bound.
    let _ = rx;
    let _ = init;
}
