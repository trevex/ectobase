#pragma once
#include <stdint.h>
struct rte_mbuf;
struct rte_mempool;
/* Non-inline wrappers for DPDK's static-inline fast path (bindgen can't emit inline fns). */
uint16_t nfkit_eth_rx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb);
uint16_t nfkit_eth_tx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb);
struct rte_mbuf *nfkit_pktmbuf_alloc(struct rte_mempool *mp);
void nfkit_pktmbuf_free(struct rte_mbuf *m);
