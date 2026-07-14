// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package allocator

import "testing"

func TestDeterministicDisjointBlocks(t *testing.T) {
	a := New([]string{"203.0.113.10"}, 1024) // usable ports 1024..65535 => 63 blocks per IP
	b1 := a.Assign("10.0.0.5")
	b2 := a.Assign("10.0.0.6")
	if b1.PublicIP != "203.0.113.10" || b1.PortMax-b1.PortMin+1 != 1024 {
		t.Fatalf("block1 %+v", b1)
	}
	if b1.PortMin == b2.PortMin { // disjoint
		t.Fatalf("blocks overlap: %+v %+v", b1, b2)
	}
	if got := a.Assign("10.0.0.5"); got != b1 { // stable for an existing source
		t.Fatalf("reassign changed block: %+v vs %+v", got, b1)
	}
}

func TestExhaustionSpillsToNextIP(t *testing.T) {
	a := New([]string{"203.0.113.10", "203.0.113.11"}, 1024)
	seen := map[string]bool{}
	for i := 0; i < 70; i++ { // >63 forces the second IP
		b := a.Assign(ipN(i))
		seen[b.PublicIP] = true
	}
	if !seen["203.0.113.11"] {
		t.Fatal("did not spill to the second public IP")
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
