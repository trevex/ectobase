/// Virtual gateway MAC the datapath answers ARP with (and uses as inner-eth src on delivery).
/// Single-sourced in `flowplane_common::proto` so eBPF, core, and sim share the exact same value.
pub use flowplane_common::proto::GW_MAC;
