package controllers

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ptr[T any](v T) *T { return &v }

func newNIC(name, vpc string, ips ...string) *netv1.NetworkInterface {
	n := &netv1.NetworkInterface{}
	n.Name = name
	n.Namespace = "default"
	n.Spec.VPCRef = netv1.LocalObjectReference{Name: vpc}
	n.Spec.IPs = ips
	// Spec.IPs are pins, which central IPAM validates and then commits to status —
	// so a BYO NIC carries them in BOTH places once Allocated. Mirror that here.
	n.Status.State = "Allocated"
	n.Status.AllocatedIPs = ips
	return n
}

// newAutoNIC is the NORMAL path: the NIC pins nothing and central IPAM picks its
// addresses, so the overlay IPs exist only in status.
func newAutoNIC(name, vpc string, ips ...string) *netv1.NetworkInterface {
	n := &netv1.NetworkInterface{}
	n.Name = name
	n.Namespace = "default"
	n.Spec.VPCRef = netv1.LocalObjectReference{Name: vpc}
	n.Status.State = "Allocated"
	n.Status.AllocatedIPs = ips
	return n
}

// The overlay IP of a NIC lives in status — Spec.IPs is only ever an optional pin.
// A NIC that auto-allocates (the normal path) therefore has an empty Spec.IPs, and
// sourcing the allocation table from spec left it with no SNAT block at all.
func TestSyncAllocatesForAutoAllocatedNICs(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	natgw := &netv1.NATGateway{}
	natgw.Name = "gw"
	natgw.Namespace = "default"
	natgw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	natgw.Spec.PublicIPs = []string{"203.0.113.10"}

	auto := newAutoNIC("nic-auto", "blue", "10.0.0.5")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(natgw, auto).
		WithStatusSubresource(&netv1.NATGateway{}).
		Build()

	r := &NATGatewayReconciler{Client: c, APIReader: c}
	ctx := context.Background()
	if err := r.Sync(ctx, natgw); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	var got netv1.NATGateway
	if err := c.Get(ctx, keyOf(natgw), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Allocations) != 1 {
		t.Fatalf("want 1 allocation for the auto-allocated NIC, got %d: %+v",
			len(got.Status.Allocations), got.Status.Allocations)
	}
	if got.Status.Allocations[0].Source != "10.0.0.5" {
		t.Fatalf("allocation source = %q, want the status-allocated overlay IP 10.0.0.5",
			got.Status.Allocations[0].Source)
	}
}

// A NIC with no allocated address yet is not a NAT source: allocating it a block
// would burn ports on an identity that does not exist on the datapath.
func TestSyncSkipsUnallocatedNICs(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	natgw := &netv1.NATGateway{}
	natgw.Name = "gw"
	natgw.Namespace = "default"
	natgw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	natgw.Spec.PublicIPs = []string{"203.0.113.10"}

	pending := &netv1.NetworkInterface{}
	pending.Name = "nic-pending"
	pending.Namespace = "default"
	pending.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	pending.Status.State = "Pending"

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(natgw, pending).
		WithStatusSubresource(&netv1.NATGateway{}).
		Build()

	r := &NATGatewayReconciler{Client: c, APIReader: c}
	if err := r.Sync(context.Background(), natgw); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	var got netv1.NATGateway
	if err := c.Get(context.Background(), keyOf(natgw), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Allocations) != 0 {
		t.Fatalf("want no allocations, got %+v", got.Status.Allocations)
	}
}

func TestSyncAllocatesDeterministicDisjointBlocks(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	natgw := &netv1.NATGateway{}
	natgw.Name = "gw"
	natgw.Namespace = "default"
	natgw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	natgw.Spec.PublicIPs = []string{"203.0.113.10"}
	natgw.Spec.PortsPerSource = ptr(int32(1024))

	blueA := newNIC("nic-a", "blue", "10.0.0.1")
	blueB := newNIC("nic-b", "blue", "10.0.0.2")
	green := newNIC("nic-c", "green", "10.0.0.9")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(natgw, blueA, blueB, green).
		WithStatusSubresource(&netv1.NATGateway{}).
		Build()

	r := &NATGatewayReconciler{Client: c, APIReader: c}
	ctx := context.Background()

	if err := r.Sync(ctx, natgw); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	var got netv1.NATGateway
	if err := c.Get(ctx, keyOf(natgw), &got); err != nil {
		t.Fatal(err)
	}

	if got.Status.State != "Ready" {
		t.Fatalf("State = %q, want Ready", got.Status.State)
	}
	if len(got.Status.Allocations) != 2 {
		t.Fatalf("want 2 allocations, got %d: %+v", len(got.Status.Allocations), got.Status.Allocations)
	}

	sources := map[string]netv1.NATAllocation{}
	for _, a := range got.Status.Allocations {
		if a.PublicIP != "203.0.113.10" {
			t.Fatalf("allocation %+v not on the public IP", a)
		}
		sources[a.Source] = a
	}
	if _, ok := sources["10.0.0.1"]; !ok {
		t.Fatalf("missing allocation for 10.0.0.1: %+v", got.Status.Allocations)
	}
	if _, ok := sources["10.0.0.2"]; !ok {
		t.Fatalf("missing allocation for 10.0.0.2: %+v", got.Status.Allocations)
	}
	if _, ok := sources["10.0.0.9"]; ok {
		t.Fatalf("green VPC source 10.0.0.9 must not be allocated: %+v", got.Status.Allocations)
	}

	// Disjoint port-blocks within the shared public IP.
	a1, a2 := sources["10.0.0.1"], sources["10.0.0.2"]
	disjoint := a1.PortMax < a2.PortMin || a2.PortMax < a1.PortMin
	if !disjoint {
		t.Fatalf("port-blocks overlap: %+v %+v", a1, a2)
	}

	// A second reconcile must be byte-identical (deterministic/stable).
	before := got.Status.Allocations
	if err := r.Sync(ctx, &got); err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	var again netv1.NATGateway
	if err := c.Get(ctx, keyOf(natgw), &again); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, again.Status.Allocations) {
		t.Fatalf("allocations not stable:\n before %+v\n after  %+v", before, again.Status.Allocations)
	}
}

// natPool is a public pool with a /24 of v4. .0 and .255 are reserved by the allocator, so the
// lowest free address is 198.51.100.1.
func natPool(name string, typ netv1.IPPoolType) *netv1.IPPool {
	p := &netv1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       netv1.IPPoolSpec{Type: typ, V4Prefix: sp("198.51.100.0/24")},
	}
	p.Status.State = "Ready"
	return p
}

// natGw is a gateway drawing from pool (empty pool name = the pre-pool literal path).
// blocksPerIP is the port-block count each address holds: the whole point of the small values
// used below is that one address runs out after a known number of sources.
func natGw(name, pool string, blocksPerIP int32, pins ...string) *netv1.NATGateway {
	gw := &netv1.NATGateway{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: "default", UID: types.UID("uid-" + name),
	}}
	gw.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	gw.Spec.PoolRef = netv1.LocalObjectReference{Name: pool}
	gw.Spec.PublicIPs = pins
	// (65535-1024+1) == 64512 usable ports per address; blocksPerIP divides it exactly for
	// 1 and 2, which is all these tests need.
	gw.Spec.PortsPerSource = ptr(64512 / blocksPerIP)
	return gw
}

func natClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(lbScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&netv1.NATGateway{}).
		Build()
}

func syncNat(t *testing.T, c client.Client, name string) *netv1.NATGateway {
	t.Helper()
	var gw netv1.NATGateway
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: name}, &gw); err != nil {
		t.Fatal(err)
	}
	r := &NATGatewayReconciler{Client: c, APIReader: c}
	if err := r.Sync(context.Background(), &gw); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	var got netv1.NATGateway
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	return &got
}

func natAllocationsIn(t *testing.T, c client.Client) []netv1.IPAllocation {
	t.Helper()
	var list netv1.IPAllocationList
	if err := c.List(context.Background(), &list, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	return list.Items
}

func blockFor(gw *netv1.NATGateway, source string) (netv1.NATAllocation, bool) {
	for _, a := range gw.Status.Allocations {
		if a.Source == source {
			return a, true
		}
	}
	return netv1.NATAllocation{}, false
}

// A gateway with a poolRef and no pins draws its address from the pool — there is no literal
// list any more. The address arrives as an IPAllocation owned by the gateway.
func TestSyncClaimsItsPublicAddressFromThePool(t *testing.T) {
	c := natClient(t, natPool("pub", netv1.IPPoolTypePublic), natGw("gw", "pub", 2), newAutoNIC("nic-a", "blue", "10.0.0.1"))

	got := syncNat(t, c, "gw")
	if got.Status.State != "Ready" {
		t.Fatalf("state = %q, want Ready", got.Status.State)
	}
	a, ok := blockFor(got, "10.0.0.1")
	if !ok || a.PublicIP != "198.51.100.1" {
		t.Fatalf("allocations = %+v, want a block on the pool's lowest free address", got.Status.Allocations)
	}
	allocs := natAllocationsIn(t, c)
	if len(allocs) != 1 || allocs[0].Spec.Address != "198.51.100.1" {
		t.Fatalf("ipallocations = %+v, want exactly one for 198.51.100.1", allocs)
	}
	if ref := metav1.GetControllerOf(&allocs[0]); ref == nil || ref.Kind != "NATGateway" || ref.Name != "gw" {
		t.Fatalf("ipallocation ownerRef = %+v, want the gateway", allocs[0].OwnerReferences)
	}
}

// publicIPs is a PIN inside the pool now, the NAT analogue of LoadBalancer.spec.ip.
func TestSyncHonoursAPinnedPublicIP(t *testing.T) {
	c := natClient(t, natPool("pub", netv1.IPPoolTypePublic), natGw("gw", "pub", 2, "198.51.100.40"),
		newAutoNIC("nic-a", "blue", "10.0.0.1"))

	got := syncNat(t, c, "gw")
	if got.Status.State != "Ready" {
		t.Fatalf("state = %q, want Ready", got.Status.State)
	}
	a, ok := blockFor(got, "10.0.0.1")
	if !ok || a.PublicIP != "198.51.100.40" {
		t.Fatalf("allocations = %+v, want the block on the PINNED 198.51.100.40", got.Status.Allocations)
	}
}

// A pin outside the pool's prefixes is the INTENT being wrong, not a wait: nothing that happens
// later makes 203.0.113.9 a member of 198.51.100.0/24.
func TestSyncRejectsAPinOutsideThePool(t *testing.T) {
	c := natClient(t, natPool("pub", netv1.IPPoolTypePublic), natGw("gw", "pub", 2, "203.0.113.9"),
		newAutoNIC("nic-a", "blue", "10.0.0.1"))

	got := syncNat(t, c, "gw")
	if got.Status.State != "Invalid" {
		t.Fatalf("state = %q, want Invalid for a pin outside the pool", got.Status.State)
	}
	if len(natAllocationsIn(t, c)) != 0 {
		t.Fatalf("a rejected pin must claim nothing: %+v", natAllocationsIn(t, c))
	}
}

// An internal pool cannot be reached from the WAN, so SNATing onto it would black-hole every
// reply. Invalid, not Pending.
func TestSyncRejectsAnInternalPool(t *testing.T) {
	c := natClient(t, natPool("priv", netv1.IPPoolTypeInternal), natGw("gw", "priv", 2),
		newAutoNIC("nic-a", "blue", "10.0.0.1"))

	got := syncNat(t, c, "gw")
	if got.Status.State != "Invalid" {
		t.Fatalf("state = %q, want Invalid for a pool of type internal", got.Status.State)
	}
}

// A pool that is not Ready yet is a WAIT, not a mistake.
func TestSyncWaitsForAPoolThatIsNotReady(t *testing.T) {
	pool := natPool("pub", netv1.IPPoolTypePublic)
	pool.Status.State = "Conflict"
	c := natClient(t, pool, natGw("gw", "pub", 2), newAutoNIC("nic-a", "blue", "10.0.0.1"))

	got := syncNat(t, c, "gw")
	if got.Status.State != "Pending" {
		t.Fatalf("state = %q, want Pending while the pool is not Ready", got.Status.State)
	}
}

// A missing pool is Invalid — the reference names nothing.
func TestSyncRejectsAMissingPool(t *testing.T) {
	c := natClient(t, natGw("gw", "nope", 2), newAutoNIC("nic-a", "blue", "10.0.0.1"))
	got := syncNat(t, c, "gw")
	if got.Status.State != "Invalid" {
		t.Fatalf("state = %q, want Invalid for a poolRef naming nothing", got.Status.State)
	}
}

// Grow on demand: one address holds two blocks, three sources need three. The gateway claims a
// SECOND address and the third source gets its block there.
func TestSyncGrowsWhenPortBlocksRunOut(t *testing.T) {
	c := natClient(t, natPool("pub", netv1.IPPoolTypePublic), natGw("gw", "pub", 2, "198.51.100.40"),
		newAutoNIC("nic-a", "blue", "10.0.0.1"),
		newAutoNIC("nic-b", "blue", "10.0.0.2"),
		newAutoNIC("nic-c", "blue", "10.0.0.3"))

	// Pass 1: two sources fit on the pin, the third forces one new address.
	got := syncNat(t, c, "gw")
	if len(natAllocationsIn(t, c)) != 2 {
		t.Fatalf("ipallocations = %+v, want 2 (the pin plus one grown address)", natAllocationsIn(t, c))
	}
	if len(got.Status.Allocations) != 3 {
		t.Fatalf("allocations = %+v, want all three sources blocked", got.Status.Allocations)
	}
	if got.Status.State != "Ready" {
		t.Fatalf("state = %q, want Ready once every source has a block", got.Status.State)
	}
	// Both addresses carry blocks and no two sources share one — the split between them is
	// whatever the lowest-free walk produces over the ascending address list (here 2 on the
	// grown 198.51.100.1 and 1 on the pin, because .1 sorts first and this pass had nothing
	// persisted to preassign). What matters is that all three are disjoint and stable.
	ips, blocks := map[string]int{}, map[string]bool{}
	for _, a := range got.Status.Allocations {
		ips[a.PublicIP]++
		blocks[fmt.Sprintf("%s:%d", a.PublicIP, a.PortMin)] = true
	}
	if len(ips) != 2 || len(blocks) != 3 {
		t.Fatalf("block layout = %v (%d distinct blocks), want 3 disjoint blocks over 2 addresses",
			ips, len(blocks))
	}

	// And it settles: a second pass, now with the table persisted, changes nothing and claims
	// no further address.
	again := syncNat(t, c, "gw")
	if !reflect.DeepEqual(got.Status.Allocations, again.Status.Allocations) {
		t.Fatalf("allocations moved on the next pass:\n before %+v\n after  %+v",
			got.Status.Allocations, again.Status.Allocations)
	}
	if n := len(natAllocationsIn(t, c)); n != 2 {
		t.Fatalf("a settled gateway grew again: %d ipallocations", n)
	}
}

// One new address per reconcile pass. A gateway with hundreds of NICs must not drain a pool in
// a single tick; the next pass grows again.
func TestSyncClaimsAtMostOneNewAddressPerPass(t *testing.T) {
	objs := []client.Object{natPool("pub", netv1.IPPoolTypePublic), natGw("gw", "pub", 1)}
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		objs = append(objs, newAutoNIC("nic-"+ip, "blue", ip))
	}
	c := natClient(t, objs...)

	for pass, want := range []int{1, 2, 3} {
		got := syncNat(t, c, "gw")
		if n := len(natAllocationsIn(t, c)); n != want {
			t.Fatalf("pass %d: %d ipallocations, want %d — exactly one new address per pass",
				pass+1, n, want)
		}
		if n := len(got.Status.Allocations); n != want {
			t.Fatalf("pass %d: %d blocked sources, want %d", pass+1, n, want)
		}
		if pass < 2 && got.Status.State != "Exhausted" {
			t.Fatalf("pass %d: state = %q, want Exhausted while sources are still unblocked",
				pass+1, got.Status.State)
		}
	}
}

// THE RENUMBERING GUARD. Appending an address changes the allocator's positional layout — the
// grown address sorts BEFORE the pin here, so every index shifts. An existing source must keep
// its exact (publicIP, portMin, portMax) anyway, because Preassign pins each persisted pair by
// value. If this ever fails, live flows are re-NATed.
func TestSyncKeepsEveryBlockWhenAnAddressIsAppended(t *testing.T) {
	c := natClient(t, natPool("pub", netv1.IPPoolTypePublic), natGw("gw", "pub", 2, "198.51.100.40"),
		newAutoNIC("nic-a", "blue", "10.0.0.1"),
		newAutoNIC("nic-b", "blue", "10.0.0.2"))

	before := syncNat(t, c, "gw")
	if len(natAllocationsIn(t, c)) != 1 {
		t.Fatalf("setup: want only the pinned address so far, got %+v", natAllocationsIn(t, c))
	}
	a0, ok := blockFor(before, "10.0.0.1")
	if !ok {
		t.Fatalf("setup: no block for 10.0.0.1: %+v", before.Status.Allocations)
	}
	b0, _ := blockFor(before, "10.0.0.2")
	t.Logf("before: 10.0.0.1 -> (%s, %d, %d); 10.0.0.2 -> (%s, %d, %d)",
		a0.PublicIP, a0.PortMin, a0.PortMax, b0.PublicIP, b0.PortMin, b0.PortMax)

	// A third NIC arrives: the pin is full, so the gateway grows onto 198.51.100.1 — which
	// sorts FIRST, moving every block index of the pin.
	if err := c.Create(context.Background(), newAutoNIC("nic-c", "blue", "10.0.0.3")); err != nil {
		t.Fatal(err)
	}
	after := syncNat(t, c, "gw")
	a1, ok := blockFor(after, "10.0.0.1")
	if !ok {
		t.Fatalf("10.0.0.1 lost its block entirely: %+v", after.Status.Allocations)
	}
	b1, _ := blockFor(after, "10.0.0.2")
	t.Logf("after:  10.0.0.1 -> (%s, %d, %d); 10.0.0.2 -> (%s, %d, %d)",
		a1.PublicIP, a1.PortMin, a1.PortMax, b1.PublicIP, b1.PortMin, b1.PortMax)

	if a1 != a0 {
		t.Fatalf("10.0.0.1 was RENUMBERED: %+v -> %+v; its live flows would break", a0, a1)
	}
	if b1 != b0 {
		t.Fatalf("10.0.0.2 was RENUMBERED: %+v -> %+v", b0, b1)
	}
	c1, ok := blockFor(after, "10.0.0.3")
	if !ok || c1.PublicIP != "198.51.100.1" {
		t.Fatalf("the new source did not land on the grown address: %+v", after.Status.Allocations)
	}
}

// When the pool is out, the gateway reports Exhausted and every source that already had a block
// keeps it — the shortfall never costs a working source its traffic.
func TestSyncPoolExhaustedKeepsExistingBlocks(t *testing.T) {
	// A /30 reserves .0 and .3 and we reserve .2: exactly one address, holding one block.
	pool := &netv1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "tiny", Namespace: "default"},
		Spec: netv1.IPPoolSpec{
			Type: netv1.IPPoolTypePublic, V4Prefix: sp("198.51.100.0/30"),
			ReservedIPs: []string{"198.51.100.2"},
		},
	}
	pool.Status.State = "Ready"
	c := natClient(t, pool, natGw("gw", "tiny", 1), newAutoNIC("nic-a", "blue", "10.0.0.1"))

	first := syncNat(t, c, "gw")
	a0, ok := blockFor(first, "10.0.0.1")
	if !ok {
		t.Fatalf("first pass gave 10.0.0.1 no block: %+v", first.Status.Allocations)
	}

	if err := c.Create(context.Background(), newAutoNIC("nic-b", "blue", "10.0.0.2")); err != nil {
		t.Fatal(err)
	}
	after := syncNat(t, c, "gw")
	if after.Status.State != "Exhausted" {
		t.Fatalf("state = %q, want Exhausted with the pool out of addresses", after.Status.State)
	}
	a1, ok := blockFor(after, "10.0.0.1")
	if !ok || a1 != a0 {
		t.Fatalf("10.0.0.1 lost or moved its block on exhaustion: %+v -> %+v", a0, a1)
	}
	if _, ok := blockFor(after, "10.0.0.2"); ok {
		t.Fatalf("10.0.0.2 must NOT get a colliding block: %+v", after.Status.Allocations)
	}
}

// The pre-pool path: no poolRef means publicIPs are literal addresses, allocated nowhere.
// An existing gateway must keep working exactly as before.
func TestSyncWithoutAPoolTreatsPublicIPsAsLiterals(t *testing.T) {
	gw := natGw("gw", "", 2, "203.0.113.10")
	c := natClient(t, gw, newAutoNIC("nic-a", "blue", "10.0.0.1"))

	got := syncNat(t, c, "gw")
	if got.Status.State != "Ready" {
		t.Fatalf("state = %q, want Ready", got.Status.State)
	}
	a, ok := blockFor(got, "10.0.0.1")
	if !ok || a.PublicIP != "203.0.113.10" {
		t.Fatalf("allocations = %+v, want a block on the literal 203.0.113.10", got.Status.Allocations)
	}
	if n := len(natAllocationsIn(t, c)); n != 0 {
		t.Fatalf("the no-pool path must claim nothing: %d ipallocations", n)
	}
}

// A gateway that drained its pool has nothing to wake it: growth is driven by its own port blocks
// running out, which emits no event. The delete-only IPAllocation watch is its only prompt, and it
// must fire for an address freed by ANY consumer — a LoadBalancer releasing one unblocks a gateway.
func TestNatgwsForFreedAddressWakesOnlyTheParkedGatewaysOnThatPool(t *testing.T) {
	scheme := lbScheme(t)
	mk := func(name, pool, state string) *netv1.NATGateway {
		g := &netv1.NATGateway{}
		g.Name, g.Namespace = name, "default"
		g.Spec.PoolRef.Name = pool
		g.Status.State = state
		return g
	}
	parked := mk("parked", "p", "Exhausted")
	pending := mk("pending", "p", "Pending")
	ready := mk("ready", "p", "Ready")
	otherPool := mk("other", "q", "Exhausted")

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(parked, pending, ready, otherPool).Build()
	r := &NATGatewayReconciler{Client: cl, APIReader: cl}

	freed := &netv1.IPAllocation{}
	freed.Name, freed.Namespace = "p-198-51-100-1", "default"
	freed.Spec.PoolRef.Name = "p"

	got := map[string]bool{}
	for _, req := range r.natgwsForFreedAddress(context.Background(), freed) {
		got[req.Name] = true
	}
	if !got["parked"] || !got["pending"] {
		t.Errorf("a freed address must wake the parked gateways, got %v", got)
	}
	if got["ready"] {
		t.Errorf("a Ready gateway needs no prompt: %v", got)
	}
	if got["other"] {
		t.Errorf("a gateway on another pool is unaffected: %v", got)
	}
}

// An IPAllocation with no pool reference names nothing to wake.
func TestNatgwsForFreedAddressIgnoresAnUnpooledAllocation(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(lbScheme(t)).Build()
	r := &NATGatewayReconciler{Client: cl, APIReader: cl}
	if reqs := r.natgwsForFreedAddress(context.Background(), &netv1.IPAllocation{}); len(reqs) != 0 {
		t.Fatalf("want no requests, got %v", reqs)
	}
}
