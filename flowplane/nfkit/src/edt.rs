//! Software Earliest-Departure-Time (EDT) pacer for DPDK backends without hardware pacing
//! (af_xdp / net_tap / net_pcap). `process_guest_tx` returns `Some(edt_tstamp)` on the metered
//! encap arm; a backend with HW-EDT sets the NIC tx-timestamp, but a software backend must hold the
//! mbuf until its departure time. `EdtPacer` is that hold-and-release calendar queue.
//!
//! INTEGRATION SEAM (guest-egress poll loop, wired in the perf phase — not built here):
//!   match out.edt_tstamp { Some(edt) => pacer.enqueue(mbuf, edt), None => tx_now(mbuf) }
//!   for mbuf in pacer.drain_due(monotonic_ns()) { tx_now(mbuf) }
//! CLOCK DOMAIN: `edt_tstamp` is CLOCK_MONOTONIC ns (the eBPF path uses bpf_ktime_get_ns); the loop
//! must feed `now` from the SAME domain — see `monotonic_ns`. The pacer itself is unit-agnostic.
//!
//! Structure: a min-heap ordered by (edt, seq). A hashed timing-wheel is the O(1)-per-op swap for
//! line-rate pacing — a possible future optimization; the heap is correct and simple.
use crate::Mbuf;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

struct Scheduled {
    edt: u64,
    seq: u64,
    mbuf: Mbuf,
}
impl PartialEq for Scheduled {
    fn eq(&self, o: &Self) -> bool {
        self.edt == o.edt && self.seq == o.seq
    }
}
impl Eq for Scheduled {}
impl Ord for Scheduled {
    // Reverse so BinaryHeap (a max-heap) yields the EARLIEST (edt, seq) first.
    fn cmp(&self, o: &Self) -> Ordering {
        (o.edt, o.seq).cmp(&(self.edt, self.seq))
    }
}
impl PartialOrd for Scheduled {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

/// Holds mbufs stamped with a departure time and releases them in time order.
#[derive(Default)]
pub struct EdtPacer {
    heap: BinaryHeap<Scheduled>,
    seq: u64,
}

impl EdtPacer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
    /// Queue `mbuf` to depart at `edt` (monotonic ns). FIFO among equal `edt`.
    pub fn enqueue(&mut self, mbuf: Mbuf, edt: u64) {
        let seq = self.seq;
        self.seq += 1;
        self.heap.push(Scheduled { edt, seq, mbuf });
    }
    /// The earliest queued departure time, if any (for the loop's poll/sleep budget).
    #[must_use]
    pub fn next_departure(&self) -> Option<u64> {
        self.heap.peek().map(|s| s.edt)
    }
    /// Append every mbuf whose `edt <= now` into `out`, in (edt, seq) order. Zero-alloc variant for
    /// the hot pacing loop: the caller reuses one buffer across polls (nothing is cleared — mbufs
    /// are appended after any existing contents).
    pub fn drain_due_into(&mut self, now: u64, out: &mut Vec<Mbuf>) {
        while let Some(top) = self.heap.peek() {
            if top.edt <= now {
                out.push(self.heap.pop().unwrap().mbuf);
            } else {
                break;
            }
        }
    }

    /// Remove and return every mbuf whose `edt <= now`, in (edt, seq) order. Convenience wrapper
    /// over [`drain_due_into`](Self::drain_due_into) that allocates a fresh `Vec`.
    pub fn drain_due(&mut self, now: u64) -> Vec<Mbuf> {
        let mut out = Vec::new();
        self.drain_due_into(now, &mut out);
        out
    }
}

/// CLOCK_MONOTONIC nanoseconds — the domain `edt_tstamp` is expressed in. Used by the live loop as
/// `now`. (Not exercised by the unit tests, which pass a synthetic `now`.)
#[must_use]
pub fn monotonic_ns() -> u64 {
    // SAFETY: clock_gettime with a valid clock id + out-param.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}
