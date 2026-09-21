// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
)

// prepareForCreater and prepareForUpdater mirror the apiserver-kit strategy hooks without importing
// the kit: this module is apimachinery-only by invariant (see api/apicheck).
type prepareForCreater interface {
	PrepareForCreate(context.Context)
}

type prepareForUpdater interface {
	PrepareForUpdate(context.Context, runtime.Object)
}

// allKinds is every kind this group serves. A kind missing from here is a kind whose generation
// silently never moves, so the list is deliberately exhaustive rather than representative.
func allKinds() []runtime.Object {
	return []runtime.Object{
		&FirewallPolicy{}, &FloatingIP{}, &IPAllocation{}, &IPPool{}, &LoadBalancer{},
		&NATGateway{}, &NetworkInterface{}, &Subnet{}, &VPC{}, &VPCPeering{},
	}
}

// Generation is set per type, so a new kind can be added without it and nothing would complain —
// until a controller's observedGeneration check silently latches on it in production, which no
// envtest would catch (envtest serves these as CRDs, which do increment generation).
func TestEveryKindImplementsTheGenerationHooks(t *testing.T) {
	for _, obj := range allKinds() {
		if _, ok := obj.(prepareForCreater); !ok {
			t.Errorf("%T does not implement PrepareForCreate: its generation would stay 0 forever", obj)
		}
		if _, ok := obj.(prepareForUpdater); !ok {
			t.Errorf("%T does not implement PrepareForUpdate: its generation would never advance", obj)
		}
	}
}

func TestPrepareForCreateStartsAtGenerationOne(t *testing.T) {
	for _, obj := range allKinds() {
		c, ok := obj.(prepareForCreater)
		if !ok {
			continue // reported by TestEveryKindImplementsTheGenerationHooks
		}
		c.PrepareForCreate(context.Background())
		m, err := meta.Accessor(obj)
		if err != nil {
			t.Fatalf("%T: %v", obj, err)
		}
		if m.GetGeneration() != 1 {
			t.Errorf("%T: generation = %d after create, want 1", obj, m.GetGeneration())
		}
	}
}

func TestPrepareForUpdateAdvancesOnlyOnASpecChange(t *testing.T) {
	// LoadBalancer stands in for the shape every kind shares: the hook is generated from one
	// template, and TestEveryKindImplementsTheGenerationHooks proves each kind has it.
	stored := &LoadBalancer{}
	stored.Generation = 7
	stored.Spec.IP = "192.0.2.1"

	t.Run("spec changed", func(t *testing.T) {
		// BeforeUpdate has already copied the stored generation onto the incoming object.
		in := &LoadBalancer{}
		in.Generation = 7
		in.Spec.IP = "192.0.2.2"
		in.PrepareForUpdate(context.Background(), stored)
		if in.Generation != 8 {
			t.Fatalf("generation = %d, want 8", in.Generation)
		}
	})

	t.Run("metadata only", func(t *testing.T) {
		in := &LoadBalancer{}
		in.Generation = 7
		in.Spec.IP = "192.0.2.1"
		in.Labels = map[string]string{"team": "net"}
		in.PrepareForUpdate(context.Background(), stored)
		if in.Generation != 7 {
			t.Fatalf("generation = %d after a label-only edit, want 7 — a metadata edit must not "+
				"make every controller re-reconcile", in.Generation)
		}
	})

	t.Run("mismatched old type is left alone", func(t *testing.T) {
		in := &LoadBalancer{}
		in.Generation = 7
		in.PrepareForUpdate(context.Background(), &Subnet{})
		if in.Generation != 7 {
			t.Fatalf("generation = %d, want 7", in.Generation)
		}
	})
}

func TestNextGeneration(t *testing.T) {
	if got := nextGeneration(4, true); got != 5 {
		t.Errorf("nextGeneration(4, true) = %d, want 5", got)
	}
	if got := nextGeneration(4, false); got != 4 {
		t.Errorf("nextGeneration(4, false) = %d, want 4", got)
	}
}
