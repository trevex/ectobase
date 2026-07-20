//! nfkit — a safe, zero-cost DPDK network-function substrate.
mod eal;
mod mbuf;
mod mempool;
mod port;
mod runtime;
pub use eal::{Eal, EalError};
pub use mbuf::{Mbuf, MbufBurst, MbufError, BURST};
pub use mempool::{Mempool, MempoolError};
pub use port::{Port, PortError, RxQueue, TxQueue};
pub use runtime::{worker_lcore_count, LcoreRuntime};
