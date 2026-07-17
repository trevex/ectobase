/// Coarse datapath failure reason for the eBPF hot path. Verifier-friendly: `Copy`, no alloc,
/// no panic. Carried in `Result<_, DpErr>` in place of the old `Result<_, ()>`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DpErr {
    /// A bounds/length check failed (packet too short, offset out of range).
    Bounds,
    /// Header parse/lookup produced an unexpected shape.
    Parse,
    /// The packet/protocol shape is not handled by this path.
    Unsupported,
    /// No route/entry resolved for the destination.
    NoRoute,
}
