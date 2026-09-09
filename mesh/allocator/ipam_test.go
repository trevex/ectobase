// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package allocator

import (
	"net/netip"
	"testing"
)

func TestReservedFor(t *testing.T) {
	got := ReservedFor(netip.MustParsePrefix("10.0.1.0/24"))
	want := map[netip.Addr]bool{
		netip.MustParseAddr("10.0.1.0"):   true,
		netip.MustParseAddr("10.0.1.255"): true,
	}
	if len(got) != len(want) {
		t.Fatalf("v4 reserved = %v, want %v", got, want)
	}
	for _, a := range got {
		if !want[a] {
			t.Fatalf("unexpected reserved v4 addr %v", a)
		}
	}
	got6 := ReservedFor(netip.MustParsePrefix("fd00:1::/64"))
	if len(got6) != 1 || got6[0] != netip.MustParseAddr("fd00:1::") {
		t.Fatalf("v6 reserved = %v, want [fd00:1::]", got6)
	}
}
