// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import "net/netip"

// underlayPrefix returns the /64 network of a node's underlay IPv6 address (the Tier-2
// fence coordinate), or "" if the input is not a genuine IPv6 address (a v4 or v4-mapped
// hostIP, or garbage) — such a node is simply not fence-eligible.
func underlayPrefix(underlay string) string {
	addr, err := netip.ParseAddr(underlay)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return ""
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}
