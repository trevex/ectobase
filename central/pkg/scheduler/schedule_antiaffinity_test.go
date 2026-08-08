// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package scheduler

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/central/pkg/clusterpool"
)

func readyPool(name string, cpu int64) platformv1.ClusterPool {
	return platformv1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: platformv1.ClusterPoolStatus{
			Phase:       clusterpool.PhaseReady,
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: *resource.NewQuantity(cpu, resource.DecimalSI)},
		},
	}
}

func vmWith(group string, cpu int64) *computev1.VirtualMachine {
	vm := &computev1.VirtualMachine{}
	vm.Spec.Resources.Requests = corev1.ResourceList{corev1.ResourceCPU: *resource.NewQuantity(cpu, resource.DecimalSI)}
	if group != "" {
		vm.Spec.AntiAffinity = &computev1.VMAntiAffinity{Group: group}
	}
	return vm
}

func TestSchedule_AntiAffinity_AvoidsCoLocation(t *testing.T) {
	pools := []platformv1.ClusterPool{readyPool("A", 8), readyPool("B", 8)}
	occ := map[string]map[string]bool{"A": {"web": true}}
	name, _, violated, ok := ScheduleAntiAffine(vmWith("web", 1), pools, nil, occ)
	if !ok || name != "B" || violated {
		t.Fatalf("want B non-violating, got name=%q violated=%v ok=%v", name, violated, ok)
	}
}

func TestSchedule_AntiAffinity_AvailabilityWinsWithViolation(t *testing.T) {
	pools := []platformv1.ClusterPool{readyPool("A", 8)} // only A, already holds web
	occ := map[string]map[string]bool{"A": {"web": true}}
	name, _, violated, ok := ScheduleAntiAffine(vmWith("web", 1), pools, nil, occ)
	if !ok || name != "A" || !violated {
		t.Fatalf("want A placed with violation, got name=%q violated=%v ok=%v", name, violated, ok)
	}
}

func TestScheduleBatch_NoOverCommit(t *testing.T) {
	pools := []platformv1.ClusterPool{readyPool("A", 2)} // fits exactly two 1-CPU VMs
	vms := []*computev1.VirtualMachine{vmWith("", 1), vmWith("", 1), vmWith("", 1)}
	res := ScheduleBatch(vms, pools)
	if res[0].Pool != "A" || res[1].Pool != "A" {
		t.Fatalf("first two should fit A: %+v", res)
	}
	if res[2].OK {
		t.Fatalf("third must not fit (capacity 2): %+v", res[2])
	}
}
