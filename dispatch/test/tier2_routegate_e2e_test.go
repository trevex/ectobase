// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
	"github.com/trevex/ectobase/dispatch/pkg/clusterpool"
	"github.com/trevex/ectobase/dispatch/pkg/failover"
	"github.com/trevex/ectobase/dispatch/pkg/fence"
	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"github.com/trevex/ectobase/mesh/reflector"
)

// TestTier2_FenceReleaseWaitsForMovedVMRoute drives the route gate on fence release through the
// REAL kit aggregated apiserver and a REAL reflector RIB behind its admin gRPC API:
//
//   - pool-a is lost; failover fences its /64 at the reflector and rebinds vm1 to pool-b. vm1's NIC
//     twin on pool-b carries 10.0.0.5 in VNI 100, and both pools' agents announce its /32.
//   - pool-a recovers and its broker reports the /64 drained, but pool-a's agent has not withdrawn
//     vm1's /32 yet: the fence must hold, and the pool must say why.
//   - The withdraw lands: the next pass releases the fence.
//
// What the gate reads — where vm1's NIC twin is compiled — comes back through the apiserver, as it
// would after a controller restart.
func TestTier2_FenceReleaseWaitsForMovedVMRoute(t *testing.T) {
	c, ctx := startNetEnv(t)
	const (
		ns       = "default"
		prefix   = "2001:db8:0:1::/64"
		sourceNH = "2001:db8:0:1::a"
		targetNH = "2001:db8:0:2::b"
		vmRoute  = "10.0.0.5/32"
	)
	mustHaveNamespaces(t, ctx, c, validate.PoolNamespace("pool-b"))

	stale := metav1.NewMicroTime(time.Now().Add(-10 * time.Minute))
	createPool(t, ctx, c, "pool-a", prefix, func(s *platformv1.ClusterPoolStatus) {
		s.Phase = clusterpool.PhaseUnknown
		s.Lease = &platformv1.ClusterPoolLease{HolderIdentity: "brokerA", RenewTime: &stale}
		s.NodePrefixes = []string{prefix}
	})
	createPool(t, ctx, c, "pool-b", "2001:db8:0:2::/64", func(s *platformv1.ClusterPoolStatus) { s.Phase = clusterpool.PhaseReady })
	vm := &computev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm1"},
		Spec: computev1.VirtualMachineSpec{ClusterName: "pool-a",
			InterfaceRefs: []computev1.LocalObjectReference{{Name: "nic1"}}},
	}
	if err := c.Create(ctx, vm); err != nil {
		t.Fatalf("create vm1: %v", err)
	}

	// The reflector: pool-a's agent announced vm1's /32 before the pool was lost.
	rib := reflector.NewRIB()
	rib.Announce("pool-a-node", 100, vmRoute, []string{sourceNH}, false)
	nf := fence.NewNetworkFencer(reflectorAdmin(t, rib))
	r := &failover.Reconciler{Client: c, StorageFencer: confirmingFencer{}, NetworkFencer: nf, Routes: nf, FailoverThreshold: time.Minute}
	reqA := ctrl.Request{NamespacedName: client.ObjectKey{Name: "pool-a"}}

	// --- Fence + rebind; vm1 comes up on pool-b. ---
	if _, err := r.Reconcile(ctx, reqA); err != nil {
		t.Fatalf("reconcile (fence/rebind): %v", err)
	}
	got := &computev1.VirtualMachine{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(vm), got); err != nil || got.Spec.ClusterName != "pool-b" {
		t.Fatalf("want vm1 rebound to pool-b, got %q (%v)", got.Spec.ClusterName, err)
	}
	twin := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Namespace: validate.PoolNamespace("pool-b"), Name: "default-nic1",
			Annotations: map[string]string{compiledv1.SourceNamespaceAnnotation: ns, compiledv1.SourceNameAnnotation: "nic1"}},
		Spec: compiledv1.CompiledNICSpec{ClusterName: "pool-b", VNI: 100, OverlayIPs: []string{"10.0.0.5"}},
	}
	if err := c.Create(ctx, twin); err != nil {
		t.Fatalf("create nic twin: %v", err)
	}
	rib.Announce("pool-b-node", 100, vmRoute, []string{targetNH}, false)

	// --- pool-a recovers and reports drained, but still announces vm1's /32. ---
	setPoolStatus(t, ctx, c, "pool-a", func(s *platformv1.ClusterPoolStatus) {
		renewed := metav1.NewMicroTime(time.Now())
		s.Phase = clusterpool.PhaseReady
		s.Lease = &platformv1.ClusterPoolLease{HolderIdentity: "brokerA", RenewTime: &renewed}
		s.NodeDrain = []platformv1.NodeDrainStatus{{Prefix: prefix, Drained: true}}
	})
	res, err := r.Reconcile(ctx, reqA)
	if err != nil {
		t.Fatalf("reconcile (held): %v", err)
	}
	held := getPool(t, ctx, c, "pool-a")
	if len(held.Status.FencedPrefixes) != 1 {
		t.Fatalf("a /64 still announcing a moved VM's route must stay fenced, got %v", held.Status.FencedPrefixes)
	}
	cond := meta.FindStatusCondition(held.Status.Conditions, failover.ConditionFenceReleaseBlocked)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "RoutesStillAnnounced" {
		t.Fatalf("want FenceReleaseBlocked=True/RoutesStillAnnounced, got %+v", cond)
	}
	if !strings.Contains(cond.Message, "pool-a-node") || !strings.Contains(cond.Message, sourceNH) {
		t.Fatalf("the condition must name the node and nexthop holding the fence, got %q", cond.Message)
	}
	if res.RequeueAfter >= time.Minute {
		t.Fatalf("a held release must be rechecked before the failover threshold, got %v", res.RequeueAfter)
	}
	// The fence is still up at the reflector: everyone is sent the new pool only. Released here,
	// this would be [sourceNH targetNH], and nodes program the stale source first.
	if got := rib.Advertised(100, vmRoute); !slices.Equal(got, []string{targetNH}) {
		t.Fatalf("while held, vm1's route must be advertised via pool-b only, got %v", got)
	}
	t.Logf("held: %s", cond.Message)

	// --- pool-a's agent withdraws; the next pass releases. ---
	rib.Withdraw("pool-a-node", 100, vmRoute)
	if _, err := r.Reconcile(ctx, reqA); err != nil {
		t.Fatalf("reconcile (release): %v", err)
	}
	released := getPool(t, ctx, c, "pool-a")
	if len(released.Status.FencedPrefixes) != 0 {
		t.Fatalf("with the route withdrawn the fence must be released, still: %v", released.Status.FencedPrefixes)
	}
	if cond := meta.FindStatusCondition(released.Status.Conditions, failover.ConditionFenceReleaseBlocked); cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("want FenceReleaseBlocked=False once released, got %+v", cond)
	}
	if got := rib.Advertised(100, vmRoute); !slices.Equal(got, []string{targetNH}) {
		t.Fatalf("after the release vm1's route must be advertised via pool-b only, got %v", got)
	}
}

// reflectorAdmin serves rib's RouteBusAdmin over an in-memory listener and returns a client of it.
func reflectorAdmin(t *testing.T, rib *reflector.RIB) pb.RouteBusAdminClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterRouteBusAdminServer(srv, reflector.NewAdminServer(rib))
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewRouteBusAdminClient(conn)
}

// createPool creates pool name declaring underlayPrefix (the only coordinate failover fences), then
// sets its status.
func createPool(t *testing.T, ctx context.Context, c client.Client, name, underlayPrefix string, status func(*platformv1.ClusterPoolStatus)) {
	t.Helper()
	if err := c.Create(ctx, &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: platformv1.ClusterPoolSpec{UnderlayPrefix: underlayPrefix}}); err != nil {
		t.Fatalf("create pool %s: %v", name, err)
	}
	setPoolStatus(t, ctx, c, name, status)
}

func setPoolStatus(t *testing.T, ctx context.Context, c client.Client, name string, status func(*platformv1.ClusterPoolStatus)) {
	t.Helper()
	p := getPool(t, ctx, c, name)
	status(&p.Status)
	if err := c.Status().Update(ctx, p); err != nil {
		t.Fatalf("status update pool %s: %v", name, err)
	}
}

func getPool(t *testing.T, ctx context.Context, c client.Client, name string) *platformv1.ClusterPool {
	t.Helper()
	p := &platformv1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, p); err != nil {
		t.Fatalf("get pool %s: %v", name, err)
	}
	return p
}
