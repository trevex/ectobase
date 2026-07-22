#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "shim.h"

uint16_t nfkit_eth_rx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb) {
    return rte_eth_rx_burst(port, qid, pkts, nb);
}
uint16_t nfkit_eth_tx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb) {
    return rte_eth_tx_burst(port, qid, pkts, nb);
}
struct rte_mbuf *nfkit_pktmbuf_alloc(struct rte_mempool *mp) { return rte_pktmbuf_alloc(mp); }
void nfkit_pktmbuf_free(struct rte_mbuf *m) { rte_pktmbuf_free(m); }

uint8_t *nfkit_pktmbuf_mtod(struct rte_mbuf *m) { return rte_pktmbuf_mtod(m, uint8_t *); }
uint16_t nfkit_pktmbuf_data_len(struct rte_mbuf *m) { return m->data_len; }
uint32_t nfkit_pktmbuf_pkt_len(struct rte_mbuf *m) { return m->pkt_len; }
uint8_t *nfkit_pktmbuf_prepend(struct rte_mbuf *m, uint16_t len) { return (uint8_t *)rte_pktmbuf_prepend(m, len); }
uint8_t *nfkit_pktmbuf_append(struct rte_mbuf *m, uint16_t len) { return (uint8_t *)rte_pktmbuf_append(m, len); }
uint8_t *nfkit_pktmbuf_adj(struct rte_mbuf *m, uint16_t len) { return (uint8_t *)rte_pktmbuf_adj(m, len); }
int nfkit_pktmbuf_trim(struct rte_mbuf *m, uint16_t len) { return rte_pktmbuf_trim(m, len); }
uint64_t nfkit_rss_ip_hf(void) { return (uint64_t)RTE_ETH_RSS_IP; }
