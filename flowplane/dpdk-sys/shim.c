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
