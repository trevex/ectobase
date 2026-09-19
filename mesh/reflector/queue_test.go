package reflector

import (
	"fmt"
	"testing"
	"time"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// msg is a distinguishable message: a route update whose prefix encodes i.
func msg(i int) *pb.ServerMsg {
	return routeUpdate(routeKey{vni: 1, prefix: fmt.Sprintf("10.%d.%d.%d/32", i>>16&0xff, i>>8&0xff, i&0xff)},
		nil, pb.RouteOp_ROUTE_OP_ADD, false)
}

func prefixes(ms []*pb.ServerMsg) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.GetRouteUpdate().GetPrefix()
	}
	return out
}

func wantOrder(t *testing.T, got []*pb.ServerMsg, want []*pb.ServerMsg) {
	t.Helper()
	g, w := prefixes(got), prefixes(want)
	if len(g) != len(w) {
		t.Fatalf("got %d messages, want %d", len(g), len(w))
	}
	for i := range w {
		if g[i] != w[i] {
			t.Fatalf("message %d: got %s, want %s", i, g[i], w[i])
		}
	}
}

// A snapshot is queued whole, in order, however large: it is bounded by the RIB, and a replay
// missing records or its marker can neither be pruned against nor ever report converged.
func TestQueueKeepsAWholeSnapshotInOrder(t *testing.T) {
	q := newSessionQueue("n")
	snap := make([]*pb.ServerMsg, 10*maxPendingDeltas)
	for i := range snap {
		snap[i] = msg(i)
	}
	q.SendSnapshot(snap)
	got, ok := q.take()
	if !ok {
		t.Fatal("take on a non-empty queue reported closed")
	}
	wantOrder(t, got, snap)
}

// Live deltas are the only thing a queue drops, and only once maxPendingDeltas are waiting.
func TestQueueDropsOnlyDeltasPastTheCap(t *testing.T) {
	q := newSessionQueue("n")
	var want []*pb.ServerMsg
	for i := 0; i < maxPendingDeltas+10; i++ {
		m := msg(i)
		q.Send(m)
		if i < maxPendingDeltas {
			want = append(want, m)
		}
	}
	// A snapshot queued while the deltas are at the cap is still queued whole.
	snap := []*pb.ServerMsg{msg(900001), msg(900002)}
	q.SendSnapshot(snap)
	want = append(want, snap...)
	got, _ := q.take()
	wantOrder(t, got, want)
}

// A big snapshot does not count against the delta cap: the delta right behind it is queued.
func TestQueueSnapshotsDoNotCountAgainstTheDeltaCap(t *testing.T) {
	q := newSessionQueue("n")
	snap := make([]*pb.ServerMsg, 5*maxPendingDeltas)
	for i := range snap {
		snap[i] = msg(i)
	}
	q.SendSnapshot(snap)
	d := msg(800000)
	q.Send(d)
	got, _ := q.take()
	wantOrder(t, got, append(snap, d))
}

// Taking what is queued frees the cap: a consumer that catches up gets deltas again.
func TestQueueTakeFreesTheDeltaCap(t *testing.T) {
	q := newSessionQueue("n")
	for i := 0; i < maxPendingDeltas; i++ {
		q.Send(msg(i))
	}
	if got, _ := q.take(); len(got) != maxPendingDeltas {
		t.Fatalf("took %d, want %d", len(got), maxPendingDeltas)
	}
	d := msg(700000)
	q.Send(d)
	got, _ := q.take()
	wantOrder(t, got, []*pb.ServerMsg{d})
}

// After close the drain still gets what was queued, then learns the queue is done; later sends
// are ignored.
func TestQueueFlushesThenEndsAfterClose(t *testing.T) {
	q := newSessionQueue("n")
	a, b := msg(1), msg(2)
	q.Send(a)
	q.SendSnapshot([]*pb.ServerMsg{b})
	q.close()
	q.Send(msg(3))
	q.SendSnapshot([]*pb.ServerMsg{msg(4)})
	got, ok := q.take()
	if !ok {
		t.Fatal("take reported closed before handing out what was queued")
	}
	wantOrder(t, got, []*pb.ServerMsg{a, b})
	if got, ok := q.take(); ok || len(got) != 0 {
		t.Fatalf("take after the flush: got %d messages, ok=%v; want none, ok=false", len(got), ok)
	}
	q.close() // idempotent
}

// take waits for work instead of spinning or returning empty.
func TestQueueTakeWaitsForWork(t *testing.T) {
	q := newSessionQueue("n")
	done := make(chan []*pb.ServerMsg)
	go func() {
		got, _ := q.take()
		done <- got
	}()
	select {
	case got := <-done:
		t.Fatalf("take returned %d messages from an empty queue", len(got))
	case <-time.After(50 * time.Millisecond):
	}
	m := msg(1)
	q.Send(m)
	select {
	case got := <-done:
		wantOrder(t, got, []*pb.ServerMsg{m})
	case <-time.After(2 * time.Second):
		t.Fatal("take did not wake up for a queued message")
	}
}

// close wakes a drain that is waiting on an empty queue.
func TestQueueCloseWakesAWaitingTake(t *testing.T) {
	q := newSessionQueue("n")
	done := make(chan bool)
	go func() {
		_, ok := q.take()
		done <- ok
	}()
	time.Sleep(20 * time.Millisecond)
	q.close()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("take on a closed, empty queue reported ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not wake the waiting take")
	}
}
