// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package allocator (this file) implements a pure, in-memory IP address
// allocator over a netip.Prefix: reserved-address computation, lowest-free
// selection, and prefix-membership checks. It holds no state of its own —
// callers own the `used` set — so it composes with any persistence layer.
package allocator

import "net/netip"

// ReservedFor returns addresses that must never be handed out for prefix:
// the network and broadcast addresses for IPv4; the all-zeroes subnet-router
// anycast host for IPv6.
func ReservedFor(prefix netip.Prefix) []netip.Addr {
	p := prefix.Masked()
	network := p.Addr()
	if network.Is4() {
		return []netip.Addr{network, lastAddr(p)}
	}
	return []netip.Addr{network}
}

// lastAddr returns the highest address in an IPv4 prefix (broadcast).
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	host := 32 - p.Bits()
	if host >= 32 {
		v = ^uint32(0)
	} else if host > 0 {
		v |= (uint32(1) << host) - 1
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// LowestFree returns the numerically lowest address in prefix that is neither
// in used nor reserved. ok=false when the prefix is exhausted. It walks from
// the network address and returns at the first gap, so cost is O(len(used)+
// len(reserved)) regardless of prefix size.
func LowestFree(prefix netip.Prefix, used map[netip.Addr]struct{}, reserved []netip.Addr) (netip.Addr, bool) {
	skip := make(map[netip.Addr]struct{}, len(used)+len(reserved))
	for a := range used {
		skip[a] = struct{}{}
	}
	for _, a := range reserved {
		skip[a] = struct{}{}
	}
	p := prefix.Masked()
	for addr := p.Addr(); p.Contains(addr); addr = addr.Next() {
		if _, taken := skip[addr]; !taken {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// InPrefix reports whether addr is a member of prefix (same family and range).
func InPrefix(prefix netip.Prefix, addr netip.Addr) bool {
	if prefix.Addr().Is4() != addr.Is4() {
		return false
	}
	return prefix.Contains(addr)
}
