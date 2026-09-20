package reflector

import (
	"log"
	"sync"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// maxPendingDeltas bounds how many live updates a session may have queued and not yet taken by
// the drain. A consumer that far behind cannot catch up message by message: further deltas are
// dropped (and logged) and it converges on its next reconnect, whose snapshot is always whole.
// Snapshots don't count.
const maxPendingDeltas = 1024

// sessionQueue is a session's outbound queue, drained onto the gRPC stream by one goroutine (a
// stream allows one Send at a time). It never blocks the caller — the RIB fans out under its
// lock — and hands messages out in the order they were queued. A snapshot is queued whole,
// always: its size is bounded by the RIB, and a replay missing records or its marker can neither
// be pruned against nor ever report converged. Only live deltas are dropped, past
// maxPendingDeltas.
//
// maxPendingDeltas is not the queue's real memory bound: snapshots are not capped. What bounds
// them is that a session gets at most one replay per thing it holds — the global feed once, and
// each VNI once, since a Subscribe for a VNI the session already holds no longer replays — so a
// consumer that never drains holds about one copy of the RIB, not an unbounded pile. The global
// replay is shared between every session on the feed (see RIB.globalSnapshotLocked), so it costs
// one pointer per record here rather than a message; the messages themselves stay alive in the
// RIB's cache until the next global mutation, which is the part the drain's incremental nil-ing
// cannot reclaim. A client that alternates Unsubscribe/Subscribe without reading can still grow
// the queue; bounding that needs a cap keyed to the RIB's size, and an authenticated peer doing it
// deliberately is a different problem from the accidental case this covers.
type sessionQueue struct {
	id   string
	wake chan struct{} // capacity 1: something was queued, or the queue closed

	mu       sync.Mutex
	pending  []*pb.ServerMsg
	deltas   int    // live deltas in pending
	dropping bool   // a drop episode is in progress; take() ends it so the next one logs too
	dropped  uint64 // live deltas refused since the session started
	closed   bool
}

func newSessionQueue(id string) *sessionQueue {
	return &sessionQueue{id: id, wake: make(chan struct{}, 1)}
}

func (q *sessionQueue) ID() string { return q.id }

// Send queues one live delta, or drops it if maxPendingDeltas are already waiting.
func (q *sessionQueue) Send(m *pb.ServerMsg) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	if q.deltas >= maxPendingDeltas {
		if !q.dropping {
			q.dropping = true
			log.Printf("reflector: session %s fell behind; dropping live updates while it catches up — its view is stale until it reconnects", q.id)
		}
		q.dropped++
		return
	}
	q.pending = append(q.pending, m)
	q.deltas++
	q.notify()
}

// SendSnapshot queues a whole replay — its records and the marker that closes it — in order.
func (q *sessionQueue) SendSnapshot(ms []*pb.ServerMsg) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.pending = append(q.pending, ms...)
	q.notify()
}

// take waits until something is queued and returns all of it, oldest first. After close it
// returns what was queued before the close, then ok == false.
func (q *sessionQueue) take() (batch []*pb.ServerMsg, ok bool) {
	for {
		q.mu.Lock()
		if len(q.pending) > 0 {
			batch, q.pending, q.deltas = q.pending, nil, 0
			q.dropping = false // the cap just freed: a further drop is a new episode, and logs again
			q.mu.Unlock()
			return batch, true
		}
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return nil, false
		}
		<-q.wake
	}
}

// close stops queueing; take still hands out what was already queued. Idempotent.
func (q *sessionQueue) close() {
	q.mu.Lock()
	first := !q.closed
	q.closed = true
	dropped := q.dropped
	q.mu.Unlock()
	if first && dropped > 0 {
		log.Printf("reflector: session %s ended having dropped %d live updates", q.id, dropped)
	}
	q.notify()
}

// notify wakes the drain without blocking; one pending wake-up is enough, since take drains
// everything queued each time it runs.
func (q *sessionQueue) notify() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}
