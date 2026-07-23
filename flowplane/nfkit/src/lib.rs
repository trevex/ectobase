//! nfkit — a safe, zero-cost DPDK network-function substrate.
mod backend;
mod dpdk_hash;
mod dpdk_maps;
mod eal;
mod edt;
mod flow;
mod mbuf;
mod mbuf_pkt;
mod mempool;
mod port;
mod rcu_hash;
mod rss;
mod runtime;
mod snapshot;
pub use backend::Backend;
pub use dpdk_hash::{DpdkHash, HashError};
pub use dpdk_maps::{DpdkMaps, NatIpKey};
pub use eal::{Eal, EalError};
pub use edt::{monotonic_ns, EdtPacer};
pub use flow::{
    create as flow_create, ingress_attr, offload_mode, probe_raw_flow_offload,
    validate as flow_validate, FlowError, FlowRule, Match5Drop, OffloadMode, RawDecap, RawEncap,
};
pub use mbuf::{Mbuf, MbufBurst, MbufError, BURST};
pub use mbuf_pkt::MbufPkt;
pub use mempool::{Mempool, MempoolError};
pub use port::{Port, PortError, RxQueue, TxQueue};
pub use rcu_hash::RcuHash;
pub use rss::{rss_queue, toeplitz_softrss, SYMMETRIC_RSS_KEY};
pub use runtime::{worker_lcore_count, LcoreRuntime};
pub use snapshot::{restore_maps, serialize_maps, RestoreStats, SnapshotError};
