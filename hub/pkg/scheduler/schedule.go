// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package scheduler binds unbound VirtualMachines to a ClusterPool. The pure
// Schedule function does the placement decision (Ready + selector + resource
// fit + spread); the Reconciler does the I/O.
package scheduler

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/hub/pkg/clusterpool"
)

// Schedule picks a ClusterPool for vm: Ready + PoolSelector match + resource fit
// (allocated[r]+request[r] <= Allocatable[r] for every requested r). Among fitting
// pools it returns the one with the highest minimum free fraction across the
// requested resources (spread), tie-broken by lowest name. ok=false + reason if none.
func Schedule(vm *computev1.VirtualMachine, pools []platformv1.ClusterPool, allocated map[string]corev1.ResourceList) (string, string, bool) {
	req := vm.Spec.Resources.Requests
	var sel labels.Selector
	if vm.Spec.PoolSelector != nil {
		s, err := metav1.LabelSelectorAsSelector(vm.Spec.PoolSelector)
		if err != nil {
			return "", fmt.Sprintf("invalid poolSelector: %v", err), false
		}
		sel = s
	}
	type cand struct {
		name  string
		score float64
	}
	var cands []cand
	for i := range pools {
		p := &pools[i]
		if p.Status.Phase != clusterpool.PhaseReady {
			continue
		}
		if sel != nil && !sel.Matches(labels.Set(p.Labels)) {
			continue
		}
		score, ok := fitScore(req, p.Status.Allocatable, allocated[p.Name])
		if !ok {
			continue
		}
		cands = append(cands, cand{p.Name, score})
	}
	if len(cands) == 0 {
		return "", "no Ready pool fits the request", false
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].name < cands[j].name
	})
	return cands[0].name, "", true
}

// fitScore returns (minFreeFraction, fits). A requested resource the pool doesn't
// advertise => does not fit. A VM with no requests fits any pool and scores 1.
func fitScore(req, allocatable, used corev1.ResourceList) (float64, bool) {
	minFree := 1.0
	for name, q := range req {
		capq, ok := allocatable[name]
		if !ok {
			return 0, false
		}
		u := used[name] // zero value if absent
		need := u.DeepCopy()
		need.Add(q)
		if need.Cmp(capq) > 0 {
			return 0, false
		}
		capv, needv := capq.AsApproximateFloat64(), need.AsApproximateFloat64()
		free := 1.0
		if capv > 0 {
			free = (capv - needv) / capv
		}
		if free < minFree {
			minFree = free
		}
	}
	return minFree, true
}

// ScheduleAntiAffine is Schedule plus anti-affinity: pools already holding the vm's
// AntiAffinity.Group (per occupancy: poolName -> set of groups) are avoided. It first
// tries non-violating fitting pools; if none, it falls back to any fitting pool and
// reports violated=true (availability wins). occupancy may be nil.
func ScheduleAntiAffine(vm *computev1.VirtualMachine, pools []platformv1.ClusterPool, allocated map[string]corev1.ResourceList, occupancy map[string]map[string]bool) (string, string, bool, bool) {
	group := ""
	if vm.Spec.AntiAffinity != nil {
		group = vm.Spec.AntiAffinity.Group
	}
	if group == "" {
		name, reason, ok := Schedule(vm, pools, allocated)
		return name, reason, false, ok
	}
	// First pass: pools NOT already holding the group.
	var clean []platformv1.ClusterPool
	for i := range pools {
		if occupancy[pools[i].Name][group] {
			continue
		}
		clean = append(clean, pools[i])
	}
	if name, reason, ok := Schedule(vm, clean, allocated); ok {
		return name, reason, false, true
	}
	// Fallback: any fitting pool, accept the violation.
	name, reason, ok := Schedule(vm, pools, allocated)
	return name, reason, ok, ok // violated == ok (a placement here is a violation)
}

// Placement is one VM's ScheduleBatch outcome.
type Placement struct {
	Pool     string
	Violated bool
	OK       bool
	Reason   string
}

// ScheduleBatch places a batch of VMs against the pools, accumulating committed
// resources (so N VMs don't over-commit one target) and anti-affinity occupancy
// (so a batch doesn't co-locate a Group it just placed). Order follows the input.
func ScheduleBatch(vms []*computev1.VirtualMachine, pools []platformv1.ClusterPool) []Placement {
	allocated := map[string]corev1.ResourceList{}
	occupancy := map[string]map[string]bool{}
	out := make([]Placement, len(vms))
	for i, vm := range vms {
		name, reason, violated, ok := ScheduleAntiAffine(vm, pools, allocated, occupancy)
		out[i] = Placement{Pool: name, Violated: violated, OK: ok, Reason: reason}
		if !ok {
			continue
		}
		// Commit this VM's requests against the chosen pool.
		cur := allocated[name]
		if cur == nil {
			cur = corev1.ResourceList{}
		}
		for r, q := range vm.Spec.Resources.Requests {
			c := cur[r]
			c.Add(q)
			cur[r] = c
		}
		allocated[name] = cur
		// Record anti-affinity occupancy.
		if vm.Spec.AntiAffinity != nil && vm.Spec.AntiAffinity.Group != "" {
			if occupancy[name] == nil {
				occupancy[name] = map[string]bool{}
			}
			occupancy[name][vm.Spec.AntiAffinity.Group] = true
		}
	}
	return out
}
