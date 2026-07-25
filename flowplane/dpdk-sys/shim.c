#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_rcu_qsbr.h>
#include <rte_ring.h>
#include <rte_errno.h>
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

size_t nfkit_rcu_qsbr_get_memsize(uint32_t m) { return rte_rcu_qsbr_get_memsize(m); }
int    nfkit_rcu_qsbr_init(struct rte_rcu_qsbr *v, uint32_t m) { return rte_rcu_qsbr_init(v, m); }
int    nfkit_rcu_qsbr_thread_register(struct rte_rcu_qsbr *v, unsigned int t) { return rte_rcu_qsbr_thread_register(v, t); }
void   nfkit_rcu_qsbr_thread_online(struct rte_rcu_qsbr *v, unsigned int t) { rte_rcu_qsbr_thread_online(v, t); }
void   nfkit_rcu_qsbr_quiescent(struct rte_rcu_qsbr *v, unsigned int t) { rte_rcu_qsbr_quiescent(v, t); }

int nfkit_rte_errno(void) { return rte_errno; }
struct rte_ring *nfkit_ring_create_scdeq(const char *name, unsigned count, int socket_id) {
    return rte_ring_create(name, count, socket_id, RING_F_SC_DEQ); /* MP enqueue (default), SC dequeue */
}
unsigned nfkit_ring_mp_enqueue_bulk(struct rte_ring *r, void **objs, unsigned n) {
    return rte_ring_mp_enqueue_bulk(r, objs, n, NULL); /* all-or-nothing: returns n on success, 0 if it won't all fit */
}
unsigned nfkit_ring_sc_dequeue_burst(struct rte_ring *r, void **objs, unsigned n) {
    return rte_ring_sc_dequeue_burst(r, objs, n, NULL); /* up-to-n: returns however many were available */
}
