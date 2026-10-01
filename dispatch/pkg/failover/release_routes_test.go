// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package failover

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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
// one. So release also waits until the reflector holds none of those addresses from that /64.

const (
	sourceNet = "2001:db8:0:1::/64"
	movedIP   = "10.0.0.5"
	movedKey  = "10.0.0.5/32"
)

// fakeRoutes answers AnnouncedFrom from a fixed table of what each prefix still announces, and
// records every question, so a test can assert what was (and was not) asked.
type fakeRoutes struct {
	held  map[string][]RouteKey
	err   error
	asked [][]RouteKey
}

func (f *fakeRoutes) AnnouncedFrom(_ context.Context, prefix string, keys []RouteKey) ([]RouteKey, error) {
	f.asked = append(f.asked, append([]RouteKey(nil), keys...))
	if f.err != nil {
		return nil, f.err
	}
	var out []RouteKey
	for _, k := range keys {
		for _, h := range f.held[prefix] {
			if h == k {
				out = append(out, k)
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

func reconcileRecovered(t *testing.T, routes RouteHolder, objs ...client.Object) (*platformv1.ClusterPool, *releaseCountingFencer, time.Duration) {
	t.Helper()
	pool := recoveredPool()
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithObjects(append(objs, pool, readyPoolObj("B"))...).WithStatusSubresource(pool).Build()
	nf := &releaseCountingFencer{}
	r := &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: nf, Routes: routes, FailoverThreshold: time.Minute}
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
	if c == nil || c.Status != metav1.ConditionTrue || c.Reason != "RoutesStillAnnounced" ||
		!strings.Contains(c.Message, movedKey) || !strings.Contains(c.Message, "default/vm1") {
		t.Fatalf("want a FenceReleaseBlocked condition naming the held route and its VM, got %+v", c)
	}
	if requeue <= 0 || requeue > routeRecheck {
		t.Fatalf("a held release must be rechecked soon (<= %v), not after the failover threshold; got %v", routeRecheck, requeue)
	}
}

func TestReleaseDrained_ReleasesOnceSourceWithdraws(t *testing.T) {
	routes := &fakeRoutes{} // the source has withdrawn: nothing held anywhere
	pool := recoveredPool()
	meta.SetStatusCondition(&pool.Status.Conditions, metav1.Condition{Type: ConditionFenceReleaseBlocked, Status: metav1.ConditionTrue, Reason: "RoutesStillAnnounced", Message: "earlier"})
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithObjects(pool, readyPoolObj("B"), movedVM("B"), nicTwin("B", "nic1", 100, movedIP)).WithStatusSubresource(pool).Build()
	nf := &releaseCountingFencer{}
	r := &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: nf, Routes: routes, FailoverThreshold: time.Minute}
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
// shared with other pools by design — and none of that may hold its fence. Only the moved VM's
// own overlay addresses are asked about.
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
		t.Fatalf("an LB address is no moved VM's address and must not be asked about, asked %v", routes.asked)
	}
}

// Only VMs failover moved away are waited on. A VM that never failed over runs where it was
// scheduled, and one bound to the recovering pool itself belongs there.
func TestReleaseDrained_VMsNotMovedAwayDoNotBlock(t *testing.T) {
	routes := &fakeRoutes{held: map[string][]RouteKey{sourceNet: {
		{VNI: 100, Prefix: "10.0.0.6/32"}, {VNI: 100, Prefix: "10.0.0.7/32"},
	}}}
	scheduled := vmOn("vm2", "B")
	scheduled.Namespace = "default"
	scheduled.Spec.InterfaceRefs = []computev1.LocalObjectReference{{Name: "nic2"}}
	movedBack := movedVM("A") // failed over at some point, but bound to A now
	movedBack.Name = "vm3"
	movedBack.Spec.InterfaceRefs = []computev1.LocalObjectReference{{Name: "nic3"}}

	pool, nf, _ := reconcileRecovered(t, routes, scheduled, nicTwin("B", "nic2", 100, "10.0.0.6"),
		movedBack, nicTwin("A", "nic3", 100, "10.0.0.7"))
	if stillFenced(pool) || len(nf.released) != 1 {
		t.Fatalf("VMs failover did not move off this pool must not hold its fence; fenced=%v", pool.Status.FencedPrefixes)
	}
	if len(routes.asked) != 0 {
		t.Fatalf("with no moved VM there is nothing to ask the reflector, asked %v", routes.asked)
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
