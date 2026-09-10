// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package allocator

import (
	"net"
	"testing"
)

func TestDeriveMACIsLocallyAdministeredUnicast(t *testing.T) {
	m := DeriveMAC("some-uid", 0)
	if len(m) != 6 {
		t.Fatalf("len = %d want 6", len(m))
	}
	// bit 0 (multicast) must be clear, bit 1 (locally administered) must be set.
	if m[0]&0x01 != 0 {
		t.Fatalf("multicast bit set in %s", m)
	}
	if m[0]&0x02 == 0 {
		t.Fatalf("locally-administered bit clear in %s", m)
	}
	if _, err := net.ParseMAC(m.String()); err != nil {
		t.Fatalf("not a parseable MAC %q: %v", m.String(), err)
	}
}

func TestDeriveMACIsDeterministic(t *testing.T) {
	a0, a0again := DeriveMAC("uid-a", 0).String(), DeriveMAC("uid-a", 0).String()
	if a0 != a0again {
		t.Fatal("same seed/attempt produced different MACs")
	}
	if b0 := DeriveMAC("uid-b", 0).String(); a0 == b0 {
		t.Fatal("distinct seeds collided (should be vanishingly unlikely)")
	}
	if a1 := DeriveMAC("uid-a", 1).String(); a0 == a1 {
		t.Fatal("attempt perturbation had no effect")
	}
}

func TestLowestFreeMACStepsPastCollisions(t *testing.T) {
	seed := "uid-x"
	first := DeriveMAC(seed, 0).String()
	// Occupy the attempt-0 MAC; allocator must return the attempt-1 MAC.
	got, ok := LowestFreeMAC(seed, map[string]struct{}{first: {}})
	if !ok {
		t.Fatal("unexpected exhaustion")
	}
	if got == first {
		t.Fatalf("returned the taken MAC %s", got)
	}
	if want := DeriveMAC(seed, 1).String(); got != want {
		t.Fatalf("got %s want %s (attempt 1)", got, want)
	}
}

func TestLowestFreeMACFreeReturnsAttemptZero(t *testing.T) {
	seed := "uid-y"
	got, ok := LowestFreeMAC(seed, map[string]struct{}{})
	if !ok || got != DeriveMAC(seed, 0).String() {
		t.Fatalf("got %s,%v want attempt-0 MAC", got, ok)
	}
}
