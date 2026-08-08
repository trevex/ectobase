package scheduler

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/central/pkg/clusterpool"
)

func pool(name, phase, cpu string, labels map[string]string) platformv1.ClusterPool {
	return platformv1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Status:     platformv1.ClusterPoolStatus{Phase: phase, Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpu)}},
	}
}
func vmReq(cpu string) *netv1.VirtualMachine {
	return &netv1.VirtualMachine{Spec: netv1.VirtualMachineSpec{Resources: corev1.ResourceRequirements{
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
	gpu := &netv1.VirtualMachine{Spec: netv1.VirtualMachineSpec{Resources: corev1.ResourceRequirements{
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
