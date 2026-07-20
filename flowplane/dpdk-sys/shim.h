#pragma once
#include <stdint.h>
struct rte_mbuf;
struct rte_mempool;
/* Non-inline wrappers for DPDK's static-inline fast path (bindgen can't emit inline fns). */
uint16_t nfkit_eth_rx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb);
uint16_t nfkit_eth_tx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb);
struct rte_mbuf *nfkit_pktmbuf_alloc(struct rte_mempool *mp);
void nfkit_pktmbuf_free(struct rte_mbuf *m);

/* Mbuf data + head/tail room ops (DPDK static-inline; bindgen can't emit them). */
uint8_t *nfkit_pktmbuf_mtod(struct rte_mbuf *m);
uint16_t nfkit_pktmbuf_data_len(struct rte_mbuf *m);
uint32_t nfkit_pktmbuf_pkt_len(struct rte_mbuf *m);
uint8_t  *nfkit_pktmbuf_prepend(struct rte_mbuf *m, uint16_t len);
uint8_t  *nfkit_pktmbuf_append(struct rte_mbuf *m, uint16_t len);
uint8_t  *nfkit_pktmbuf_adj(struct rte_mbuf *m, uint16_t len);
int       nfkit_pktmbuf_trim(struct rte_mbuf *m, uint16_t len);
