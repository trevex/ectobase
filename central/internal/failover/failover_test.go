package failover

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	netinstall "github.com/trevex/ectobase/central/apis/net/install"
	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

type fakeFencer struct{ err error }

func (f fakeFencer) FenceStorage(context.Context, *netv1.VirtualMachine) error { return f.err }
func (f fakeFencer) FenceNetwork(context.Context, *netv1.VirtualMachine) error { return f.err }

// splitFencer confirms storage but denies network — exercises the SECOND fence guard.
type splitFencer struct{ networkErr error }

func (splitFencer) FenceStorage(context.Context, *netv1.VirtualMachine) error   { return nil }
func (f splitFencer) FenceNetwork(context.Context, *netv1.VirtualMachine) error { return f.networkErr }

func scheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := platforminstall.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := netinstall.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func lostPool(name string) *platformv1.ClusterPool {
	old := metav1.NewMicroTime(time.Now().Add(-1 * time.Hour))
	return &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: platformv1.ClusterPoolStatus{Phase: "Unknown", Lease: &platformv1.ClusterPoolLease{RenewTime: &old}}}
}
func reqFor(name string) ctrl.Request { return ctrl.Request{NamespacedName: types.NamespacedName{Name: name}} }

func TestFailover_ConfirmedRebind(t *testing.T) {
	s := scheme(t)
	lost, healthy := lostPool("c1"), &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c2"}, Status: platformv1.ClusterPoolStatus{Phase: "Ready"}}
	vm := &netv1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm1"}, Spec: netv1.VirtualMachineSpec{ClusterName: "c1"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(lost, healthy, vm).WithStatusSubresource(vm, lost, healthy).Build()

	r := &Reconciler{Client: c, Fencer: fakeFencer{nil}, FailoverThreshold: time.Minute}
	if _, err := r.Reconcile(context.Background(), reqFor("c1")); err != nil {
		t.Fatal(err)
	}

	got := &netv1.VirtualMachine{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "vm1"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.ClusterName != "c2" {
		t.Fatalf("want rebound to c2, got %q", got.Spec.ClusterName)
	}
}

func TestFailover_FenceDenied_StaysAndBlocks(t *testing.T) {
	s := scheme(t)
	lost := lostPool("c1")
	vm := &netv1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm1"}, Spec: netv1.VirtualMachineSpec{ClusterName: "c1"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(lost, vm).WithStatusSubresource(vm, lost).Build()

	r := &Reconciler{Client: c, Fencer: fakeFencer{errors.New("no ceph")}, FailoverThreshold: time.Minute}
	if _, err := r.Reconcile(context.Background(), reqFor("c1")); err != nil {
		t.Fatal(err)
	}

	got := &netv1.VirtualMachine{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "vm1"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.ClusterName != "c1" {
		t.Fatalf("must NOT rebind when fence unconfirmed, got %q", got.Spec.ClusterName)
	}
	blocked := false
	for _, cond := range got.Status.Conditions {
		if cond.Type == "FailoverBlocked" && cond.Status == metav1.ConditionTrue {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("want FailoverBlocked condition")
	}
}

// The SECOND fence guard: storage confirms but network is denied → must NOT rebind
// (a half-fenced instance could still hold the network identity).
func TestFailover_NetworkFenceDenied_StaysAndBlocks(t *testing.T) {
	s := scheme(t)
	lost, healthy := lostPool("c1"), &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c2"}, Status: platformv1.ClusterPoolStatus{Phase: "Ready"}}
	vm := &netv1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm1"}, Spec: netv1.VirtualMachineSpec{ClusterName: "c1"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(lost, healthy, vm).WithStatusSubresource(vm, lost, healthy).Build()

	r := &Reconciler{Client: c, Fencer: splitFencer{networkErr: errors.New("no overlay withdrawal")}, FailoverThreshold: time.Minute}
	if _, err := r.Reconcile(context.Background(), reqFor("c1")); err != nil {
		t.Fatal(err)
	}

	got := &netv1.VirtualMachine{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "vm1"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.ClusterName != "c1" {
		t.Fatalf("must NOT rebind when only storage fence confirmed, got %q", got.Spec.ClusterName)
	}
	blocked := false
	for _, cond := range got.Status.Conditions {
		if cond.Type == "FailoverBlocked" && cond.Status == metav1.ConditionTrue {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("want FailoverBlocked condition on network-fence denial")
	}
}
