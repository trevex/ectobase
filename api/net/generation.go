// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

// Generation semantics for this group are implemented per type, in each kind's *_rest.go, via the
// PrepareForCreate / PrepareForUpdate hooks the apiserver strategy calls.
//
// They have to be, because nothing upstream does it for us. `rest.BeforeCreate` sets no generation
// at all, and `rest.BeforeUpdate` only copies the stored value onto the incoming object so a client
// cannot forge it — the increment is left to each resource's own strategy, which is exactly what
// upstream Kubernetes resources do. The kit's DefaultStrategy is generic over runtime.Object and
// cannot know which field is a given resource's "spec", so it does not do it either.
//
// Without these hooks every object in this group stays at generation 0 for its whole life, which
// is quietly destructive: it makes every `status.observedGeneration == metadata.generation`
// comparison trivially true, so a controller's idempotence short-circuit latches after the first
// reconcile and the resource is never reconciled for a spec edit again. That is not hypothetical —
// it is why a LoadBalancer could not be moved between pools, and it is invisible to envtest, which
// serves these kinds as CRDs and therefore *does* increment generation.
//
// The ordering this relies on: BeforeUpdate copies the stored generation onto the incoming object
// BEFORE calling PrepareForUpdate, and does so before persisting, so a bump in the hook is what
// lands. Status updates never reach PrepareForUpdate — the status subresource installs a strategy
// that calls only its own override — so a status write cannot bump the generation.
//
// INTERIM: apiserver-kit is gaining an opt-in GenerationTracker interface (branch
// feat/generation-semantics) that does this generically, at which point each type here collapses
// to a single SpecChanged method and these two hooks go away. Until ectobase can build against
// that kit — it is on k8s v0.37 and this module is on v0.36 — the hooks live here.

// nextGeneration returns the generation an updated object should carry: one past the stored value
// when the spec changed, and the stored value untouched otherwise. Metadata-only edits (a label, an
// annotation) must not move it, or every controller watching the resource re-reconciles for nothing.
func nextGeneration(stored int64, specChanged bool) int64 {
	if specChanged {
		return stored + 1
	}

	return stored
}
