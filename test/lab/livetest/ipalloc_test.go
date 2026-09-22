//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	// A documentation prefix (RFC 5737 TEST-NET-2) that no other suite uses. Nothing here sends
	// traffic, so it does not need to be routable — it only has to avoid overlapping another
	// test's pool, since IPPoolReconciler parks the later of two overlapping siblings in one
	// namespace at Conflict.
	reclaimPrefix = "198.51.100.0/24"
	reclaimPool   = "reclaim-pool"
	reclaimLB     = "reclaim-lb"
	// The address the allocator hands out first: .0 is the network and .1 is the lowest free.
	reclaimAddr       = "198.51.100.1"
	reclaimAllocation = reclaimPool + "-198-51-100-1"
)

// TestIPAllocationIsReclaimedWithItsConsumer proves the one property of the IPPool design that
// CANNOT be tested anywhere else: that deleting a consumer frees its address.
//
// An IPAllocation is owned by its consumer through an ownerReference, so Kubernetes garbage
// collection is what reclaims it. envtest runs no garbage collector, so an envtest asserting this
// would fail no matter how correct the code is, and one asserting the allocation SURVIVES would
// pass while proving nothing about production. Unit tests can only check that the ownerRef fields
// are set. That leaves a real cluster as the only place the claim can be made, which is why this
// lives here and not beside the allocator's other tests.
//
// It also covers a second thing worth knowing: that the collector reaches an AGGREGATED api group
// at all. Nothing else in this repo depends on that — the compiled twins are GC'd by a finalizer
// and an orphan sweep precisely because cross-namespace ownerRefs are rejected — so if it ever
// stops being true, this is the test that says so, and the fallback is the finalizer + stamp +
// sweep triad already implemented for those twins.
//
// No Pod, no VPC, no traffic: a LoadBalancer allocates its address from the pool whether or not
// anything is behind it, which keeps this to two objects and a few seconds.
func TestIPAllocationIsReclaimedWithItsConsumer(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	applyDispatch(t, ctx, cfg, fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: IPPool
metadata: {name: %s}
spec: {type: public, v4Prefix: %s}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: LoadBalancer
metadata: {name: %s}
spec:
  ip: ""
  poolRef: {name: %s}
  ports: [{port: 80, proto: TCP}]
  targetSelector: {matchLabels: {app: reclaim-nothing}}
`, reclaimPool, reclaimPrefix, reclaimLB, reclaimPool))

	// 1. The claim exists, and it is the allocation object — not just a status field.
	eventually(t, 2*time.Minute, 3*time.Second, func() error {
		out, err := kubectl(ctx, cfg, "dispatch", "get", "loadbalancer.net.ectobase.dev", reclaimLB,
			"-o", "jsonpath={.status.state} {.status.allocatedIP}")
		if err != nil {
			return fmt.Errorf("get LoadBalancer status: %w", err)
		}
		if got := strings.TrimSpace(out); got != "Allocated "+reclaimAddr {
			return fmt.Errorf("status = %q, want %q", got, "Allocated "+reclaimAddr)
		}
		return nil
	})

	// The ownerReference is what GC acts on, so assert it rather than merely that the object is
	// there: an allocation with no controller ref would leak the address silently forever.
	out, err := kubectl(ctx, cfg, "dispatch", "get", "ipallocation.net.ectobase.dev", reclaimAllocation,
		"-o", "jsonpath={.spec.address}|{.metadata.ownerReferences[0].kind}|{.metadata.ownerReferences[0].name}|{.metadata.ownerReferences[0].controller}")
	require.NoError(t, err, "get IPAllocation %s", reclaimAllocation)
	require.Equal(t, fmt.Sprintf("%s|LoadBalancer|%s|true", reclaimAddr, reclaimLB), strings.TrimSpace(out),
		"the claim must be owned (controller: true) by the LoadBalancer, or GC will never reclaim it")

	// 2. THE POINT. Delete the consumer; the address must come back on its own. Nothing in this
	//    test deletes the IPAllocation, and no controller does either — reclamation is the
	//    garbage collector following the ownerReference.
	_, err = kubectl(ctx, cfg, "dispatch", "delete", "loadbalancer.net.ectobase.dev", reclaimLB, "--wait=true")
	require.NoError(t, err, "delete the LoadBalancer")

	eventually(t, 2*time.Minute, 2*time.Second, func() error {
		out, err := kubectl(ctx, cfg, "dispatch", "get", "ipallocations.net.ectobase.dev",
			"-o", "jsonpath={range .items[*]}{.metadata.name} {end}")
		if err != nil {
			return fmt.Errorf("list IPAllocations: %w", err)
		}
		if strings.Contains(out, reclaimAllocation) {
			return fmt.Errorf("%s still held after its owner was deleted; remaining: %q",
				reclaimAllocation, strings.TrimSpace(out))
		}
		return nil
	})
	t.Logf("reclaim PASS: deleting %s released %s — the allocation %s was collected via its ownerReference",
		reclaimLB, reclaimAddr, reclaimAllocation)

	// 3. And the address is genuinely reusable, not merely un-listed: a fresh consumer gets it
	//    back. A reclaim that left the name taken would fail here on AlreadyExists.
	applyDispatch(t, ctx, cfg, fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: LoadBalancer
metadata: {name: %s-again}
spec:
  ip: ""
  poolRef: {name: %s}
  ports: [{port: 80, proto: TCP}]
  targetSelector: {matchLabels: {app: reclaim-nothing}}
`, reclaimLB, reclaimPool))

	eventually(t, 2*time.Minute, 3*time.Second, func() error {
		out, err := kubectl(ctx, cfg, "dispatch", "get", "loadbalancer.net.ectobase.dev", reclaimLB+"-again",
			"-o", "jsonpath={.status.allocatedIP}")
		if err != nil {
			return fmt.Errorf("get successor LoadBalancer status: %w", err)
		}
		if got := strings.TrimSpace(out); got != reclaimAddr {
			return fmt.Errorf("successor got %q, want the freed %s", got, reclaimAddr)
		}
		return nil
	})
	t.Logf("reuse PASS: a fresh LoadBalancer was handed the freed %s", reclaimAddr)
}
