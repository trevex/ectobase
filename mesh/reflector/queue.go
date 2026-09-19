package reflector

import (
	"log"
	"sync"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// maxPendingDeltas bounds how many live updates a session may have queued and unsent. A consumer
// that far behind cannot catch up message by message: further deltas are dropped (and logged) and
// it converges on its next reconnect, whose snapshot is always whole. Snapshots don't count.
const maxPendingDeltas = 1024

// sessionQueue is a session's outbound queue, drained onto the gRPC stream by one goroutine (a
// stream allows one Send at a time). It never blocks the caller — the RIB fans out under its
// lock — and hands messages out in the order they were queued. A snapshot is queued whole,
// always: its size is bounded by the RIB, and a replay missing records or its marker can neither
// be pruned against nor ever report converged. Only live deltas are dropped, past
// maxPendingDeltas.
type sessionQueue struct {
	id   string
	wake chan struct{} // capacity 1: something was queued, or the queue closed

	mu      sync.Mutex
	pending []*pb.ServerMsg
	deltas  int    // live deltas in pending
	dropped uint64 // live deltas refused since the session started
	closed  bool
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
		if q.dropped == 0 {
			log.Printf("reflector: session %s is %d live updates behind; dropping updates until it reconnects", q.id, q.deltas)
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
