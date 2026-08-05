// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

func TestUnderlayPrefix(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"2001:db8:0:1::a", "2001:db8:0:1::/64"},
		{"2001:db8:0:1::", "2001:db8:0:1::/64"},
		{"fd00:db8:0:9::1", "fd00:db8:0:9::/64"},
		{"10.0.0.1", ""},           // IPv4 -> not fence-eligible
		{"::ffff:10.0.0.1", ""},    // v4-mapped -> not a real v6 underlay
		{"not-an-ip", ""},          // garbage
		{"", ""},                   // empty
	}
	for _, c := range cases {
		if got := underlayPrefix(c.in); got != c.want {
			t.Errorf("underlayPrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
