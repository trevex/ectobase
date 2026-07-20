//! nfkit — a safe, zero-cost DPDK network-function substrate.
mod eal;
mod mbuf;
mod mempool;
mod port;
pub use eal::{Eal, EalError};
pub use mbuf::{Mbuf, MbufBurst, MbufError, BURST};
pub use mempool::{Mempool, MempoolError};
pub use port::{Port, PortError, RxQueue, TxQueue};
