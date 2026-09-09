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

func used(addrs ...string) map[netip.Addr]struct{} {
	m := make(map[netip.Addr]struct{}, len(addrs))
	for _, s := range addrs {
		m[netip.MustParseAddr(s)] = struct{}{}
	}
	return m
}

func TestLowestFree(t *testing.T) {
	p := netip.MustParsePrefix("10.0.1.0/24")
	res := ReservedFor(p)
	got, ok := LowestFree(p, used(), res)
	if !ok || got != netip.MustParseAddr("10.0.1.1") {
		t.Fatalf("first = %v,%v want 10.0.1.1", got, ok)
	}
	got, ok = LowestFree(p, used("10.0.1.1", "10.0.1.2"), res)
	if !ok || got != netip.MustParseAddr("10.0.1.3") {
		t.Fatalf("gap = %v,%v want 10.0.1.3", got, ok)
	}
	tiny := netip.MustParsePrefix("192.168.0.0/30")
	_, ok = LowestFree(tiny, used("192.168.0.1", "192.168.0.2"), ReservedFor(tiny))
	if ok {
		t.Fatalf("expected exhaustion on full /30")
	}
}

func TestLowestFreeV6(t *testing.T) {
	p := netip.MustParsePrefix("fd00:1::/64")
	got, ok := LowestFree(p, used(), ReservedFor(p))
	if !ok || got != netip.MustParseAddr("fd00:1::1") {
		t.Fatalf("v6 first = %v,%v want fd00:1::1", got, ok)
	}
}
