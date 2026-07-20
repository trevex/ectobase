//! nfkit — a safe, zero-cost DPDK network-function substrate.
mod backend;
mod dpdk_hash;
mod eal;
mod mbuf;
mod mempool;
mod port;
mod runtime;
pub use backend::Backend;
pub use dpdk_hash::{DpdkHash, HashError};
pub use eal::{Eal, EalError};
pub use mbuf::{Mbuf, MbufBurst, MbufError, BURST};
pub use mempool::{Mempool, MempoolError};
pub use port::{Port, PortError, RxQueue, TxQueue};
pub use runtime::{worker_lcore_count, LcoreRuntime};
