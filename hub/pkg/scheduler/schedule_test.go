package scheduler

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/hub/pkg/clusterpool"
)

func pool(name, phase, cpu string, labels map[string]string) platformv1.ClusterPool {
	return platformv1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Status:     platformv1.ClusterPoolStatus{Phase: phase, Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpu)}},
	}
}
func vmReq(cpu string) *computev1.VirtualMachine {
	return &computev1.VirtualMachine{Spec: computev1.VirtualMachineSpec{Resources: corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpu)}}}}
}

func TestSchedule(t *testing.T) {
	ready := clusterpool.PhaseReady
	pools := []platformv1.ClusterPool{pool("a", ready, "4", nil), pool("b", ready, "8", nil), pool("c", "Unknown", "16", nil)}

	// fits both a,b; b has more free -> b wins (spread by most-free).
	got, _, ok := Schedule(vmReq("2"), pools, map[string]corev1.ResourceList{})
	if !ok || got != "b" {
		t.Fatalf("want b, got %q ok=%v", got, ok)
	}

	// b already loaded to 7/8 -> a (free 4) beats b (free 1).
	got, _, ok = Schedule(vmReq("2"), pools, map[string]corev1.ResourceList{"b": {corev1.ResourceCPU: resource.MustParse("7")}})
	if !ok || got != "a" {
		t.Fatalf("want a, got %q", got)
	}

	// request exceeds all Ready capacity -> unschedulable.
	if _, _, ok := Schedule(vmReq("100"), pools, nil); ok {
		t.Fatalf("want unschedulable")
	}

	// gpu request but no pool advertises gpu -> unschedulable.
	gpu := &computev1.VirtualMachine{Spec: computev1.VirtualMachineSpec{Resources: corev1.ResourceRequirements{
		Requests: corev1.ResourceList{"nvidia.com/gpu": resource.MustParse("1")}}}}
	if _, _, ok := Schedule(gpu, pools, nil); ok {
		t.Fatalf("want unschedulable (no gpu)")
	}

	// Unknown pool c never chosen even though it has the most CPU.
	got, _, _ = Schedule(vmReq("2"), pools, nil)
	if got == "c" {
		t.Fatalf("must not pick Unknown pool")
	}

	// PoolSelector filters to labeled pools.
	labeled := []platformv1.ClusterPool{pool("a", ready, "4", map[string]string{"tier": "gold"}), pool("b", ready, "8", nil)}
	sel := vmReq("1")
	sel.Spec.PoolSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "gold"}}
	got, _, ok = Schedule(sel, labeled, nil)
	if !ok || got != "a" {
		t.Fatalf("selector: want a, got %q", got)
	}
}

// TestScheduleWorkload_Container exercises the generalized resource-based entry
// point with a Container-style request (no PoolSelector). It must place onto the
// most-free Ready pool, respect allocated capacity, and share capacity honestly.
func TestScheduleWorkload_Container(t *testing.T) {
	ready := clusterpool.PhaseReady
	pools := []platformv1.ClusterPool{pool("a", ready, "4", nil), pool("b", ready, "8", nil)}

	req := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")}

	// nil selector fits both; b has more free -> b wins (spread by most-free).
	got, _, ok := ScheduleWorkload(req, nil, pools, map[string]corev1.ResourceList{})
	if !ok || got != "b" {
		t.Fatalf("container: want b, got %q ok=%v", got, ok)
	}

	// b already loaded (a VM occupies 7/8) -> a (free 4) beats b (free 1),
	// proving the container respects capacity another workload already consumed.
	got, _, ok = ScheduleWorkload(req, nil, pools, map[string]corev1.ResourceList{"b": {corev1.ResourceCPU: resource.MustParse("7")}})
	if !ok || got != "a" {
		t.Fatalf("container shared-capacity: want a, got %q", got)
	}

	// request exceeds all Ready capacity -> unschedulable.
	big := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100")}
	if _, _, ok := ScheduleWorkload(big, nil, pools, nil); ok {
		t.Fatalf("container: want unschedulable")
	}
}
