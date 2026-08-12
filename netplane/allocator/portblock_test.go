// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package allocator

import "testing"

func TestDeterministicDisjointBlocks(t *testing.T) {
	a := New([]string{"203.0.113.10"}, 1024) // usable ports 1024..65535 => 63 blocks per IP
	b1, ok1 := a.Assign("10.0.0.5")
	b2, ok2 := a.Assign("10.0.0.6")
	if !ok1 || !ok2 {
		t.Fatalf("assign failed: ok1=%v ok2=%v", ok1, ok2)
	}
	if b1.PublicIP != "203.0.113.10" || b1.PortMax-b1.PortMin+1 != 1024 {
		t.Fatalf("block1 %+v", b1)
	}
	if b1.PortMin == b2.PortMin { // disjoint
		t.Fatalf("blocks overlap: %+v %+v", b1, b2)
	}
	if got, _ := a.Assign("10.0.0.5"); got != b1 { // stable for an existing source
		t.Fatalf("reassign changed block: %+v vs %+v", got, b1)
	}
}

// TestExhaustionReturnsNotOK: once every block across every public IP is taken, a new source is
// refused (ok=false) rather than handed a colliding fallback block — two distinct sources sharing a
// (public IP, port range) would overlap their SNAT tuples and corrupt datapath conntrack.
func TestExhaustionReturnsNotOK(t *testing.T) {
	a := New([]string{"203.0.113.10"}, 21000) // (65535-1024+1)/21000 = 3 blocks
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		b, ok := a.Assign(ipN(i))
		if !ok {
			t.Fatalf("assign %d should succeed within capacity", i)
		}
		key := b.PublicIP + ":" + itoa(int(b.PortMin))
		if seen[key] {
			t.Fatalf("duplicate block handed out: %+v", b)
		}
		seen[key] = true
	}
	if _, ok := a.Assign("10.9.9.9"); ok {
		t.Fatal("assign past capacity must return ok=false, not a colliding block")
	}
}

func TestExhaustionSpillsToNextIP(t *testing.T) {
	a := New([]string{"203.0.113.10", "203.0.113.11"}, 1024)
	seen := map[string]bool{}
	for i := 0; i < 70; i++ { // >63 forces the second IP
		b, ok := a.Assign(ipN(i))
		if !ok {
			t.Fatalf("assign %d should succeed within capacity", i)
		}
		seen[b.PublicIP] = true
	}
	if !seen["203.0.113.11"] {
		t.Fatal("did not spill to the second public IP")
	}
}

// TestPreassignKeepsExistingBlockWhenLowerSourceInserted is the drain-safety regression: inserting a
// source that sorts BEFORE an existing one must NOT move the existing source's block (the old
// positional scheme shifted it, re-NATing live flows).
func TestPreassignKeepsExistingBlockWhenLowerSourceInserted(t *testing.T) {
	// Reconcile 1: only 10.0.0.5 exists → gets the first block.
	a1 := New([]string{"203.0.113.10"}, 1024)
	b5, _ := a1.Assign("10.0.0.5")

	// Reconcile 2: 10.0.0.1 (sorts first) is added. Seed the persisted block for 10.0.0.5, then
	// assign in sorted order (10.0.0.1, 10.0.0.5).
	a2 := New([]string{"203.0.113.10"}, 1024)
	a2.Preassign("10.0.0.5", b5)
	newB, _ := a2.Assign("10.0.0.1")
	keptB, _ := a2.Assign("10.0.0.5")

	if keptB != b5 {
		t.Fatalf("existing source's block moved: was %+v now %+v", b5, keptB)
	}
	if newB.PortMin == b5.PortMin {
		t.Fatalf("new source overlaps the existing block: %+v vs %+v", newB, b5)
	}
}

// TestPreassignInvalidBlockReallocates: a persisted block whose IP left the pool is dropped and the
// source is reassigned within the current pool.
func TestPreassignInvalidBlockReallocates(t *testing.T) {
	a := New([]string{"203.0.113.20"}, 1024)
	a.Preassign("10.0.0.5", Block{PublicIP: "203.0.113.99", PortMin: 1024, PortMax: 2047}) // IP not in pool
	b, _ := a.Assign("10.0.0.5")
	if b.PublicIP != "203.0.113.20" {
		t.Fatalf("invalid preassign must reallocate within the pool: %+v", b)
	}
}

func ipN(i int) string { return "10.1." + itoa(i/256) + "." + itoa(i%256) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
