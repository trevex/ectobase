// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package failover

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
)

// A fenced /64 is released once its broker reports it drained — no VMI left there. That is not the
// same as no ROUTE left there: the recovered node's agent withdraws a moved VM's /32 only after the
// CNI DEL and its next tick, and a node whose kubelet died under a running agent never does. A
// release that lands first re-advertises the moved VM's address from the stale source alongside
// the pool it now runs on, and nodes that program the first nexthop send its traffic to the stale
// one. So release also waits until the reflector holds, from that /64, no address of anything
// placed on another pool.

const (
	sourceNet  = "2001:db8:0:1::/64"
	sourceNode = "pool-a-node-1"
	sourceNH   = "2001:db8:0:1::a"
	movedIP    = "10.0.0.5"
	movedKey   = "10.0.0.5/32"
)

// fakeRoutes answers AnnouncedFrom from a fixed table of what each prefix still announces (every
// holding by sourceNode via sourceNH), and records every question, so a test can assert what was
// (and was not) asked.
type fakeRoutes struct {
	held  map[string][]RouteKey
	err   error
	asked [][]RouteKey
}

func (f *fakeRoutes) AnnouncedFrom(_ context.Context, prefix string, keys []RouteKey) ([]RouteHolding, error) {
	f.asked = append(f.asked, append([]RouteKey(nil), keys...))
	if f.err != nil {
		return nil, f.err
	}
	var out []RouteHolding
	for _, k := range keys {
		for _, h := range f.held[prefix] {
			if h == k {
				out = append(out, RouteHolding{Key: k, Origin: sourceNode, Nexthop: sourceNH})
			}
		}
	}
	return out, nil
}

func (f *fakeRoutes) askedAbout(k RouteKey) bool {
	for _, q := range f.asked {
		for _, a := range q {
			if a == k {
				return true
			}
		}
	}
	return false
}

// releaseCountingFencer confirms everything and counts releases.
type releaseCountingFencer struct{ released []string }

func (*releaseCountingFencer) Fence(context.Context, string) error { return nil }
func (f *releaseCountingFencer) Release(_ context.Context, p string) error {
	f.released = append(f.released, p)
	return nil
}

// recoveredPool is pool A after a failover: back Ready, its one /64 still fenced, and its broker
// reporting that /64 drained.
func recoveredPool() *platformv1.ClusterPool {
	pool := readyPoolObj("A")
	pool.Status.FencedPrefixes = []string{sourceNet}
	pool.Status.NodeDrain = []platformv1.NodeDrainStatus{{Prefix: sourceNet, Drained: true}}
	return pool
}

// movedVM is vm1 as failover leaves it: rebound to pool, and marked FailedOver.
func movedVM(pool string) *computev1.VirtualMachine {
	vm := vmOn("vm1", pool)
	vm.Namespace = "default"
	vm.Spec.InterfaceRefs = []computev1.LocalObjectReference{{Name: "nic1"}}
	meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "FailoverBlocked", Status: metav1.ConditionFalse, Reason: "FailedOver", Message: "failed over to " + pool})
	meta.SetStatusCondition(&vm.Status.Conditions, metav1.Condition{Type: "Scheduled", Status: metav1.ConditionTrue, Reason: "FailedOver", Message: "bound to " + pool})
	return vm
}

// nicTwin is the CompiledNIC compiled for default/<nic> into pool's namespace.
func nicTwin(pool, nic string, vni int32, ips ...string) *compiledv1.CompiledNIC {
	return &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: validate.PoolNamespace(pool), Name: "default-" + nic,
			Annotations: map[string]string{
				compiledv1.SourceNamespaceAnnotation: "default",
				compiledv1.SourceNameAnnotation:      nic,
			},
		},
		Spec: compiledv1.CompiledNICSpec{ClusterName: pool, VNI: vni, OverlayIPs: ips},
	}
}

func newRecoveredReconciler(t *testing.T, routes RouteHolder, pool *platformv1.ClusterPool, objs ...client.Object) (*Reconciler, client.Client, *releaseCountingFencer) {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithObjects(append(objs, pool, readyPoolObj("B"))...).WithStatusSubresource(pool).Build()
	nf := &releaseCountingFencer{}
	return &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: nf, Routes: routes, FailoverThreshold: time.Minute}, c, nf
}

func reconcileRecovered(t *testing.T, routes RouteHolder, objs ...client.Object) (*platformv1.ClusterPool, *releaseCountingFencer, time.Duration) {
	t.Helper()
	r, c, nf := newRecoveredReconciler(t, routes, recoveredPool(), objs...)
	res, err := r.Reconcile(context.Background(), req("A"))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &platformv1.ClusterPool{}
	if err := c.Get(context.Background(), key("A"), got); err != nil {
		t.Fatal(err)
	}
	return got, nf, res.RequeueAfter
}

func stillFenced(pool *platformv1.ClusterPool) bool {
	for _, p := range pool.Status.FencedPrefixes {
		if p == sourceNet {
			return true
		}
	}
	return false
}

func TestReleaseDrained_HoldsWhileSourceAnnouncesMovedVM(t *testing.T) {
	routes := &fakeRoutes{held: map[string][]RouteKey{sourceNet: {{VNI: 100, Prefix: movedKey}}}}
	pool, nf, requeue := reconcileRecovered(t, routes, movedVM("B"), nicTwin("B", "nic1", 100, movedIP))

	if !stillFenced(pool) || len(nf.released) != 0 {
		t.Fatalf("a drained /64 that still announces a moved VM's address must stay fenced; fenced=%v released=%v",
			pool.Status.FencedPrefixes, nf.released)
	}
	c := meta.FindStatusCondition(pool.Status.Conditions, ConditionFenceReleaseBlocked)
	if c == nil || c.Status != metav1.ConditionTrue || c.Reason != "RoutesStillAnnounced" {
		t.Fatalf("want FenceReleaseBlocked=True/RoutesStillAnnounced, got %+v", c)
	}
	// The operator has to find the node: name the route, the node and nexthop announcing it, and
	// the NIC (and the pool it now runs on) it belongs to.
	for _, want := range []string{movedKey, sourceNode, sourceNH, "default/nic1", "pool B"} {
		if !strings.Contains(c.Message, want) {
			t.Fatalf("condition message must name %q, got %q", want, c.Message)
		}
	}
	if requeue <= 0 || requeue > routeRecheck {
		t.Fatalf("a held release must be rechecked soon (<= %v), not after the failover threshold; got %v", routeRecheck, requeue)
	}
}

func TestReleaseDrained_ReleasesOnceSourceWithdraws(t *testing.T) {
	routes := &fakeRoutes{} // the source has withdrawn: nothing held anywhere
	pool := recoveredPool()
	meta.SetStatusCondition(&pool.Status.Conditions, metav1.Condition{Type: ConditionFenceReleaseBlocked, Status: metav1.ConditionTrue, Reason: "RoutesStillAnnounced", Message: "earlier"})
	r, c, nf := newRecoveredReconciler(t, routes, pool, movedVM("B"), nicTwin("B", "nic1", 100, movedIP))
	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatal(err)
	}
	got := &platformv1.ClusterPool{}
	_ = c.Get(context.Background(), key("A"), got)
	if stillFenced(got) || len(nf.released) != 1 {
		t.Fatalf("with the moved VM's route withdrawn the /64 must be released; fenced=%v released=%v", got.Status.FencedPrefixes, nf.released)
	}
	if !routes.askedAbout(RouteKey{VNI: 100, Prefix: movedKey}) {
		t.Fatalf("the reflector must have been asked about the moved VM's address, asked %v", routes.asked)
	}
	if cond := meta.FindStatusCondition(got.Status.Conditions, ConditionFenceReleaseBlocked); cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("a release no longer blocked must say so, got %+v", cond)
	}
}

// Fail closed: a release that cannot be shown safe does not happen.
func TestReleaseDrained_HoldsWhenTheReflectorCannotBeAsked(t *testing.T) {
	for name, routes := range map[string]RouteHolder{
		"query error":         &fakeRoutes{err: errors.New("reflector unreachable")},
		"no reflector at all": DenyFencer{},
		"nil holder":          nil,
	} {
		t.Run(name, func(t *testing.T) {
			pool, nf, _ := reconcileRecovered(t, routes, movedVM("B"), nicTwin("B", "nic1", 100, movedIP))
			if !stillFenced(pool) || len(nf.released) != 0 {
				t.Fatalf("an unanswered route check must hold the fence; fenced=%v released=%v", pool.Status.FencedPrefixes, nf.released)
			}
			c := meta.FindStatusCondition(pool.Status.Conditions, ConditionFenceReleaseBlocked)
			if c == nil || c.Status != metav1.ConditionTrue || c.Reason != "RouteCheckFailed" {
				t.Fatalf("want FenceReleaseBlocked/RouteCheckFailed, got %+v", c)
			}
		})
	}
}

// The recovered pool keeps announcing what it legitimately serves — an E/W LB anycast address is
// shared with other pools by design — and none of that may hold its fence. Only overlay addresses
// are asked about.
func TestReleaseDrained_SharedLBAddressDoesNotBlock(t *testing.T) {
	lbKey := RouteKey{VNI: 100, Prefix: "10.9.9.9/32"}
	routes := &fakeRoutes{held: map[string][]RouteKey{sourceNet: {lbKey}}}
	twin := nicTwin("B", "nic1", 100, movedIP)
	twin.Spec.LB = []compiledv1.CompiledLB{{IP: "10.9.9.9"}} // the moved VM is itself an LB backend
	pool, nf, _ := reconcileRecovered(t, routes, movedVM("B"), twin)

	if stillFenced(pool) || len(nf.released) != 1 {
		t.Fatalf("an LB address the recovered pool announces must not hold its fence; fenced=%v", pool.Status.FencedPrefixes)
	}
	if routes.askedAbout(lbKey) {
		t.Fatalf("an LB address is no workload's overlay address and must not be asked about, asked %v", routes.asked)
	}
}

// Anything placed on another pool is waited on, however it got there. A workload placed elsewhere
// is announced from the recovering pool's /64 legitimately only while a move off that pool is in
// flight, which is exactly what the release must wait out. The gate reads placement (where the
// NIC's twin is compiled), not history: failover's own marks are lost or never written on real
// paths, and a planned move off a lost pool has none.
func TestReleaseDrained_AnythingPlacedElsewhereBlocks(t *testing.T) {
	lostMark := movedVM("B") // failed over, but a 409 or a crash lost the FailedOver status write
	lostMark.Status.Conditions = []metav1.Condition{{Type: "Scheduled", Status: metav1.ConditionTrue, Reason: "Bound", Message: "bound to B", LastTransitionTime: metav1.Now()}}
	plannedMove := vmOn("vm1", "C") // the user moved it A->C while A was lost: no failover marks at all
	plannedMove.Namespace = "default"
	plannedMove.Spec.InterfaceRefs = []computev1.LocalObjectReference{{Name: "nic1"}}
	ctr := &computev1.Container{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ctr1"},
		Spec: computev1.ContainerSpec{ClusterName: "B", InterfaceRefs: []computev1.LocalObjectReference{{Name: "nic1"}}}}

	for name, tc := range map[string]struct {
		pool     string
		workload client.Object
	}{
		"failed over, FailedOver mark lost": {"B", lostMark},
		"planned move off the lost pool":    {"C", plannedMove},
		"never failed over":                 {"B", vmOn("vm2", "B")},
		"container":                         {"B", ctr},
	} {
		t.Run(name, func(t *testing.T) {
			routes := &fakeRoutes{held: map[string][]RouteKey{sourceNet: {{VNI: 100, Prefix: movedKey}}}}
			pool, nf, _ := reconcileRecovered(t, routes, tc.workload, nicTwin(tc.pool, "nic1", 100, movedIP))
			if !stillFenced(pool) || len(nf.released) != 0 {
				t.Fatalf("an address placed on %s still announced from A's /64 must hold A's fence; fenced=%v",
					tc.pool, pool.Status.FencedPrefixes)
			}
		})
	}
}

// What is placed on the recovering pool itself belongs there: its routes from that /64 are the
// ones the release is meant to bring back.
func TestReleaseDrained_OwnPlacementsDoNotBlock(t *testing.T) {
	routes := &fakeRoutes{held: map[string][]RouteKey{sourceNet: {{VNI: 100, Prefix: "10.0.0.7/32"}}}}
	movedBack := movedVM("A") // failed over at some point, bound to A now
	pool, nf, _ := reconcileRecovered(t, routes, movedBack, nicTwin("A", "nic1", 100, "10.0.0.7"))
	if stillFenced(pool) || len(nf.released) != 1 {
		t.Fatalf("an address placed on the recovering pool must not hold its fence; fenced=%v", pool.Status.FencedPrefixes)
	}
	if len(routes.asked) != 0 {
		t.Fatalf("with nothing placed elsewhere there is nothing to ask the reflector, asked %v", routes.asked)
	}
}

// A key is (VNI, host prefix): the moved VM's address in its own VPC, v6 as a /128.
func TestReleaseDrained_AsksAboutEachAddressInItsVNI(t *testing.T) {
	routes := &fakeRoutes{held: map[string][]RouteKey{sourceNet: {{VNI: 200, Prefix: "fd00::5/128"}}}}
	pool, nf, _ := reconcileRecovered(t, routes, movedVM("B"), nicTwin("B", "nic1", 200, movedIP, "fd00::5"))
	if !stillFenced(pool) || len(nf.released) != 0 {
		t.Fatalf("a held v6 address must hold the fence; fenced=%v", pool.Status.FencedPrefixes)
	}
	if !routes.askedAbout(RouteKey{VNI: 200, Prefix: movedKey}) || !routes.askedAbout(RouteKey{VNI: 200, Prefix: "fd00::5/128"}) {
		t.Fatalf("want both host prefixes asked in VNI 200, asked %v", routes.asked)
	}
}

// Every address placed elsewhere is asked about, so the question is batched to keep each call well
// inside gRPC's message limit — and a key held in the last batch still holds the fence.
func TestReleaseDrained_BatchesTheQuestion(t *testing.T) {
	ips := make([]string, 0, 2*routeBatch+1)
	for i := 0; i < 2*routeBatch+1; i++ {
		ips = append(ips, fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256))
	}
	last := RouteKey{VNI: 100, Prefix: ips[len(ips)-1] + "/32"}
	routes := &fakeRoutes{held: map[string][]RouteKey{sourceNet: {last}}}
	pool, _, _ := reconcileRecovered(t, routes, nicTwin("B", "nic1", 100, ips...))
	if len(routes.asked) != 3 {
		t.Fatalf("want %d keys asked in 3 calls, got %d calls", len(ips), len(routes.asked))
	}
	for _, q := range routes.asked {
		if len(q) > routeBatch {
			t.Fatalf("a call asked %d keys, over the batch size %d", len(q), routeBatch)
		}
	}
	if !stillFenced(pool) {
		t.Fatal("a key held in the last batch must hold the fence")
	}
}

// Not being able to work out what to ask holds the release, like not being able to ask — but it
// must not stop the rest of the pass: a pool lost again still has to be fenced and its VMs moved.
func TestReleaseDrained_LookupFailureHoldsButReconcileContinues(t *testing.T) {
	pool := lostPoolObj("A", sourceNet)
	pool.Status.FencedPrefixes = []string{sourceNet}
	pool.Status.NodeDrain = []platformv1.NodeDrainStatus{{Prefix: sourceNet, Drained: true}}
	vm := vmOn("vm1", "A")
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(pool, readyPoolObj("B"), vm).
		WithStatusSubresource(pool, vm).
		WithInterceptorFuncs(interceptor.Funcs{List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*compiledv1.CompiledNICList); ok {
				return errors.New("compilednics unavailable")
			}
			return cl.List(ctx, list, opts...)
		}}).Build()
	nf := &releaseCountingFencer{}
	r := &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: nf, Routes: &fakeRoutes{}, FailoverThreshold: time.Minute}
	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("a failed lookup must hold the release, not fail the pass: %v", err)
	}
	got := &platformv1.ClusterPool{}
	_ = c.Get(context.Background(), key("A"), got)
	if len(nf.released) != 0 || !stillFenced(got) {
		t.Fatalf("an unknown key set must hold the release; released=%v fenced=%v", nf.released, got.Status.FencedPrefixes)
	}
	if cond := meta.FindStatusCondition(got.Status.Conditions, ConditionFenceReleaseBlocked); cond == nil || cond.Reason != "RouteCheckFailed" {
		t.Fatalf("want FenceReleaseBlocked/RouteCheckFailed, got %+v", cond)
	}
	gotVM := &computev1.VirtualMachine{}
	_ = c.Get(context.Background(), key("vm1"), gotVM)
	if gotVM.Spec.ClusterName != "B" {
		t.Fatalf("the lost-pool pass must still run and rebind vm1, got %q", gotVM.Spec.ClusterName)
	}
}

// Once nothing is fenced, nothing can be waiting: a condition left True from an earlier pass must
// not outlive the fence.
func TestReleaseDrained_NothingFencedClearsTheCondition(t *testing.T) {
	pool := readyPoolObj("A")
	meta.SetStatusCondition(&pool.Status.Conditions, metav1.Condition{Type: ConditionFenceReleaseBlocked, Status: metav1.ConditionTrue, Reason: "RoutesStillAnnounced", Message: "stale"})
	r, c, _ := newRecoveredReconciler(t, &fakeRoutes{}, pool)
	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatal(err)
	}
	got := &platformv1.ClusterPool{}
	_ = c.Get(context.Background(), key("A"), got)
	if cond := meta.FindStatusCondition(got.Status.Conditions, ConditionFenceReleaseBlocked); cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("with nothing fenced FenceReleaseBlocked must be False, got %+v", cond)
	}
}
