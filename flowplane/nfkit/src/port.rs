//! Safe ethdev port + per-lcore rx/tx queues. `Port` configures N rx/tx queues with RSS and owns
//! the device lifecycle (stop+close on drop). `RxQueue`/`TxQueue` are `!Send` handles — service a
//! queue from exactly one lcore.
use crate::mbuf::{Mbuf, MbufBurst, BURST};
use crate::mempool::Mempool;
use std::marker::PhantomData;
use std::ptr;

#[derive(Debug)]
pub struct PortError(pub i32);

impl std::fmt::Display for PortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ethdev bring-up failed (rc={}; check rte_errno)", self.0)
    }
}

impl std::error::Error for PortError {}

/// A configured, started ethdev port. Stops + closes on drop.
pub struct Port {
    id: u16,
    n_queues: u16,
}

impl Port {
    /// Configure port `id` with up to `n_queues` rx+tx queues and RSS (basic IP hash), each rx
    /// queue fed from `pool`. Devices that cap queues (pcap/tap/null -> 1) reduce `n_queues`
    /// accordingly. Starts the device.
    ///
    /// # Errors
    /// Returns `PortError(rc)` if any ethdev bring-up call fails.
    pub fn configure(id: u16, n_queues: u16, pool: &Mempool) -> Result<Port, PortError> {
        // SAFETY: standard ethdev bring-up; all pointers reference locals live for the call.
        unsafe {
            let mut info: dpdk_sys::rte_eth_dev_info = std::mem::zeroed();
            let rc = dpdk_sys::rte_eth_dev_info_get(id, &mut info);
            if rc != 0 {
                return Err(PortError(rc));
            }
            let nq = n_queues
                .min(info.max_rx_queues)
                .min(info.max_tx_queues)
                .max(1);

            let mut conf: dpdk_sys::rte_eth_conf = std::mem::zeroed();
            if nq > 1 {
                conf.rxmode.mq_mode = dpdk_sys::rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_RSS;
                // RTE_ETH_RSS_IP is a C macro (not bindgen-visible); retrieved via shim.
                // Intersect with device's supported offloads so drivers that don't support
                // IP hash don't reject the configure call.
                conf.rx_adv_conf.rss_conf.rss_hf =
                    dpdk_sys::nfkit_rss_ip_hf() & info.flow_type_rss_offloads;
            }
            let rc = dpdk_sys::rte_eth_dev_configure(id, nq, nq, &conf);
            if rc != 0 {
                return Err(PortError(rc));
            }
            // rte_eth_dev_socket_id returns -1 on error; clamp to 0 (SOCKET_ID_ANY semantics).
            let socket = dpdk_sys::rte_eth_dev_socket_id(id).max(0) as u32;
            for q in 0..nq {
                let rc = dpdk_sys::rte_eth_rx_queue_setup(
                    id,
                    q,
                    512,
                    socket,
                    ptr::null(),
                    pool.as_raw(),
                );
                if rc != 0 {
                    return Err(PortError(rc));
                }
                let rc = dpdk_sys::rte_eth_tx_queue_setup(id, q, 512, socket, ptr::null());
                if rc != 0 {
                    return Err(PortError(rc));
                }
            }
            let rc = dpdk_sys::rte_eth_dev_start(id);
            if rc != 0 {
                return Err(PortError(rc));
            }
            Ok(Port { id, n_queues: nq })
        }
    }

    #[must_use]
    pub fn n_queues(&self) -> u16 {
        self.n_queues
    }

    /// Build the `(RxQueue, TxQueue)` handles for queue `q`. Call ON the lcore that services it
    /// (the handles are `!Send`).
    #[must_use]
    pub fn queue(&self, q: u16) -> (RxQueue, TxQueue) {
        debug_assert!(
            q < self.n_queues,
            "queue index {q} out of range (n_queues={})",
            self.n_queues
        );
        (
            RxQueue {
                port: self.id,
                q,
                _ns: PhantomData,
            },
            TxQueue {
                port: self.id,
                q,
                _ns: PhantomData,
            },
        )
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        // SAFETY: sole owner; stop before close is the required teardown order.
        unsafe {
            dpdk_sys::rte_eth_dev_stop(self.id);
            dpdk_sys::rte_eth_dev_close(self.id);
        }
    }
}

/// `!Send` rx queue handle. Poll from exactly one lcore.
pub struct RxQueue {
    port: u16,
    q: u16,
    _ns: PhantomData<*const ()>,
}

/// `!Send` tx queue handle. Transmit from exactly one lcore.
pub struct TxQueue {
    port: u16,
    q: u16,
    _ns: PhantomData<*const ()>,
}

impl RxQueue {
    /// Receive up to `out`'s remaining capacity; appends owned mbufs to `out`. Returns count.
    #[inline]
    pub fn rx(&mut self, out: &mut MbufBurst) -> usize {
        let cap = out.remaining_capacity();
        if cap == 0 {
            return 0;
        }
        let mut raw: [*mut dpdk_sys::rte_mbuf; BURST] = [ptr::null_mut(); BURST];
        // SAFETY: raw has room for cap <= BURST ptrs; the driver fills the first n with
        // freshly-owned mbufs. We convert each into an `Mbuf` (which will free it on drop).
        let n = unsafe {
            dpdk_sys::nfkit_eth_rx_burst(self.port, self.q, raw.as_mut_ptr(), cap as u16) as usize
        };
        for &p in raw.iter().take(n) {
            // SAFETY: nfkit_eth_rx_burst fills exactly raw[0..n] with independent, valid,
            // non-null mbuf pointers (DPDK ethdev rx_burst contract), so new_unchecked +
            // taking ownership is sound.
            out.push(unsafe { Mbuf::from_raw(std::ptr::NonNull::new_unchecked(p)) });
        }
        n
    }
}

impl TxQueue {
    /// Transmit the front of `burst`. Sent mbufs are removed and their ownership passed to DPDK
    /// (freed by the driver after transmit — NOT by us). Un-sent mbufs remain in `burst`. Returns
    /// count sent.
    #[inline]
    pub fn tx(&mut self, burst: &mut MbufBurst) -> usize {
        if burst.is_empty() {
            return 0;
        }
        let mut raw: [*mut dpdk_sys::rte_mbuf; BURST] = [ptr::null_mut(); BURST];
        for (i, m) in burst.iter().enumerate() {
            raw[i] = m.as_raw();
        }
        // SAFETY: raw[0..len] are the burst's live mbufs. The driver takes ownership of the
        // first `sent` of them (frees them after transmit); we must NOT drop those.
        let sent = unsafe {
            dpdk_sys::nfkit_eth_tx_burst(self.port, self.q, raw.as_mut_ptr(), burst.len() as u16)
                as usize
        };
        // Remove the sent prefix WITHOUT running Drop (DPDK owns/frees them now).
        for m in burst.drain(..sent) {
            let _ = m.into_raw();
        }
        sent
    }
}
