#pragma once
#include <stdint.h>
#include <stddef.h>
struct rte_mbuf;
struct rte_mempool;
struct rte_rcu_qsbr;
struct rte_ring;
/* Non-inline wrappers for DPDK's static-inline fast path (bindgen can't emit inline fns). */
uint16_t nfkit_eth_rx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb);
uint16_t nfkit_eth_tx_burst(uint16_t port, uint16_t qid, struct rte_mbuf **pkts, uint16_t nb);
/* Returns the RTE_ETH_RSS_IP composite hash-function bitmask (C macro; not bindgen-visible). */
uint64_t nfkit_rss_ip_hf(void);
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

/* RCU/QSBR ops (DPDK static-inline; bindgen can't emit them) — real symbols for Rust. */
size_t nfkit_rcu_qsbr_get_memsize(uint32_t max_threads);
int    nfkit_rcu_qsbr_init(struct rte_rcu_qsbr *v, uint32_t max_threads);
int    nfkit_rcu_qsbr_thread_register(struct rte_rcu_qsbr *v, unsigned int thread_id);
void   nfkit_rcu_qsbr_thread_online(struct rte_rcu_qsbr *v, unsigned int thread_id);
void   nfkit_rcu_qsbr_quiescent(struct rte_rcu_qsbr *v, unsigned int thread_id);

/* Inter-lcore rte_ring: MP enqueue / SC dequeue. Create wraps RING_F_SC_DEQ (a C macro, not
 * bindgen-visible). The bulk/burst ops are DPDK static-inline; expose them as real symbols. */
int nfkit_rte_errno(void); /* read the per-lcore rte_errno (a C macro; not bindgen-visible) */
struct rte_ring *nfkit_ring_create_scdeq(const char *name, unsigned count, int socket_id);
unsigned nfkit_ring_mp_enqueue_bulk(struct rte_ring *r, void **objs, unsigned n);
unsigned nfkit_ring_sc_dequeue_burst(struct rte_ring *r, void **objs, unsigned n);
