// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package allocator (this file) implements a pure, deterministic MAC address
// allocator. Like the IP allocator it holds no state of its own — the caller
// owns the `used` set — so it composes with any persistence layer.
package allocator

import (
	"encoding/binary"
	"hash/fnv"
	"net"
)

// laaUnicast is the top octet of a locally-administered, unicast MAC: bit 1
// (locally administered) set, bit 0 (multicast) clear. It matches the agent's
// mac_for fallback convention (flowplane attach/naming.rs) so both the control
// plane and the datapath mint MACs from the same private, collision-free space.
const laaUnicast = 0x02

// DeriveMAC returns a deterministic locally-administered unicast MAC for seed,
// perturbed by attempt so callers can step past a collision. The low 40 bits
// come from an FNV-1a hash of (seed, attempt); the top octet is fixed to 0x02.
// The same (seed, attempt) always yields the same MAC, which is what makes a
// NIC's address stable across reconciles.
func DeriveMAC(seed string, attempt int) net.HardwareAddr {
	h := fnv.New64a()
	_, _ = h.Write([]byte(seed))
	var tail [9]byte
	tail[0] = 0 // separator so seed and attempt can't blend
	binary.BigEndian.PutUint64(tail[1:], uint64(attempt))
	_, _ = h.Write(tail[:])
	sum := h.Sum64()
	return net.HardwareAddr{
		laaUnicast,
		byte(sum >> 32), byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum),
	}
}

// LowestFreeMAC derives a MAC for seed, stepping attempt until the result is not
// in used, and returns it in canonical lowercase colon form. ok=false only when
// maxMACAttempts consecutive derivations all collide — astronomically unlikely
// for a 40-bit space, but bounded so a pathological used-set can't spin forever.
// Keys of used must be canonical net.HardwareAddr.String() form.
func LowestFreeMAC(seed string, used map[string]struct{}) (string, bool) {
	const maxMACAttempts = 1 << 12
	for attempt := 0; attempt < maxMACAttempts; attempt++ {
		m := DeriveMAC(seed, attempt).String()
		if _, taken := used[m]; !taken {
			return m, true
		}
	}
	return "", false
}
