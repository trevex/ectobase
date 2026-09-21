// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"github.com/trevex/ectobase/mesh/allocator"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// errNotAllocatable means the request cannot be served for a reason that is the REQUEST's
// fault rather than capacity's: a pin outside the pool, reserved, or already held by another
// consumer, or a pool offering no prefix of the requested family. Consumers map it to Invalid.
// Genuine capacity exhaustion is ok=false instead, which consumers map to Exhausted.
var errNotAllocatable = errors.New("address not allocatable from pool")

// claimRetries bounds the re-list-and-retry loop when another allocator wins the address we
// picked. Each lost race removes one address from contention, so a small bound is enough; the
// alternative — spinning — would turn a busy pool into a hot loop.
const claimRetries = 5

// allocationName is the deterministic object name for one (pool, address) allocation. Object
// names are unique within a namespace, so creating this name IS the allocation: two allocators
// racing for the same address cannot both succeed.
//
// The encoding has to be injective over the PAIR, not just over the address, because the pool
// name and the address share one dash-separated string. Expanding IPv6 (StringExpanded, never
// String) is what buys that: an expanded address is always exactly 8 groups, so the address is
// the last 8 groups and the pool is whatever precedes them — one name, one split. Compressed,
// the group count varies and the split is ambiguous: pool "p-2001" with db8::1 and pool "p" with
// 2001:db8::1 would both spell "p-2001-db8--1", so a claim on one address would refuse the other.
// IPv4 is the same argument with a fixed count of 4 groups.
//
// (The tempting justification — that "::" would encode to an illegal leading "--" — does not
// hold: the pool name always precedes it, and "pub---1" is a perfectly legal DNS-1123
// subdomain. Ambiguity, not legality, is the reason to expand.)
//
// Unmap first for the other direction: ::ffff:192.0.2.1 and 192.0.2.1 are ONE address, and one
// address with two names would let two allocators both "win" it.
func allocationName(pool string, addr netip.Addr) (string, error) {
	if !addr.IsValid() {
		return "", fmt.Errorf("allocation name: invalid address")
	}
	a := addr.Unmap()
	var enc string
	if a.Is4() {
		enc = strings.ReplaceAll(a.String(), ".", "-")
	} else {
		enc = strings.ReplaceAll(a.StringExpanded(), ":", "-")
	}
	name := pool + "-" + enc
	// Cheap, and it is the property the whole design rests on: a name the apiserver would
	// reject is a claim that never collides with anything. Refuse rather than allocate.
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return "", fmt.Errorf("allocation name %q is not a legal object name: %s", name, strings.Join(errs, "; "))
	}
	return name, nil
}

// claimAddress allocates one address from pool for consumer, or adopts the one it already
// holds. The IPAllocation's NAME is the claim: Create either wins or returns AlreadyExists,
// so this is correct without assuming a single writer across consumer kinds. That is the whole
// reason this exists instead of each consumer scanning its own kind's statuses — two consumer
// kinds allocating from one pool cannot see each other's in-flight decisions.
//
// Returns the address, or ok=false when the pool is exhausted. errNotAllocatable means the
// request itself cannot be served; see the sentinel.
func claimAddress(ctx context.Context, c client.Client, r client.Reader,
	pool *netv1.IPPool, consumer client.Object, consumerKind string,
	pinned *netip.Addr, preferred *netip.Addr) (netip.Addr, bool, error) {
	prefix, err := poolPrefixFor(pool, pinned)
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("%w: %s", errNotAllocatable, err)
	}
	resv := append(allocator.ReservedFor(prefix), parseAddrs(pool.Spec.ReservedIPs)...)

	for range claimRetries {
		used, mine, err := poolAllocations(ctx, r, pool, consumer, consumerKind)
		if err != nil {
			return netip.Addr{}, false, err
		}

		var want netip.Addr
		if pinned != nil {
			p := pinned.Unmap()
			if !allocator.InPrefix(prefix, p) || isReserved(resv, p) {
				return netip.Addr{}, false, errNotAllocatable
			}
			if _, taken := used[p]; taken {
				if _, ours := mine[p]; !ours {
					return netip.Addr{}, false, errNotAllocatable
				}
			}
			want = p
		} else if a, ok := heldIn(mine, prefix, resv); ok {
			// The allocation this consumer already holds is the strongest sticky record
			// there is — the consumer's own status is only a cache of it.
			want = a
		} else if a, ok := stickyOrLowest(prefix, preferred, used, resv); ok {
			want = a
		} else {
			return netip.Addr{}, false, nil // pool exhausted
		}

		if _, ours := mine[want]; ours {
			return want, true, nil // already ours; nothing to create
		}

		name, err := allocationName(pool.Name, want)
		if err != nil {
			return netip.Addr{}, false, fmt.Errorf("%w: %v", errNotAllocatable, err)
		}
		alloc := &netv1.IPAllocation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: pool.Namespace,
				Labels:    map[string]string{netv1.PoolLabel: pool.Name},
			},
			Spec: netv1.IPAllocationSpec{
				PoolRef:     netv1.LocalObjectReference{Name: pool.Name},
				Address:     want.String(),
				ConsumerRef: netv1.TypedLocalObjectReference{Kind: consumerKind, Name: consumer.GetName()},
			},
		}
		// Same-namespace controller ref: Kubernetes garbage collection reclaims the
		// allocation when the consumer goes, so nothing here has to free it.
		if err := ctrl.SetControllerReference(consumer, alloc, c.Scheme()); err != nil {
			return netip.Addr{}, false, fmt.Errorf("own ipallocation %s: %w", name, err)
		}

		createErr := c.Create(ctx, alloc)
		if createErr == nil {
			return want, true, nil
		}
		if !apierrors.IsAlreadyExists(createErr) {
			return netip.Addr{}, false, fmt.Errorf("create ipallocation %s: %w", name, createErr)
		}

		// Somebody holds this name. Read who, rather than assume: if it is us (a
		// re-reconcile off a stale read) adopt it; if it is somebody else they won the
		// race, so retry against a fresh used-set.
		var existing netv1.IPAllocation
		if err := r.Get(ctx, client.ObjectKey{Namespace: pool.Namespace, Name: name}, &existing); err != nil {
			if apierrors.IsNotFound(err) {
				continue // freed between the Create and the Get; go again
			}
			return netip.Addr{}, false, fmt.Errorf("get ipallocation %s: %w", name, err)
		}
		if ownedBy(&existing, consumer, consumerKind) {
			return want, true, nil
		}
		if pinned != nil {
			return netip.Addr{}, false, errNotAllocatable // the pin belongs to someone else
		}
	}
	// Lost every race in a row. Report exhaustion rather than spin: the consumer parks and
	// the delete-only watch on IPAllocation re-enqueues it as soon as an address frees up.
	return netip.Addr{}, false, nil
}

// releaseClaimsExcept deletes the allocations this consumer holds in pool other than keep.
// A single-address consumer that gets repointed (spec.ip edited) would otherwise hold its old
// claim forever and leak the address — the status-scan allocator this replaces freed it
// implicitly, so skipping this would be a regression, not a simplification.
//
// It deletes ONLY allocations whose controller ref is this consumer. It must never delete one
// whose owner merely looks gone: that is a second allocator racing the garbage collector.
func releaseClaimsExcept(ctx context.Context, c client.Client, r client.Reader,
	pool *netv1.IPPool, consumer client.Object, consumerKind string, keep netip.Addr) error {
	var list netv1.IPAllocationList
	if err := r.List(ctx, &list, client.InNamespace(pool.Namespace),
		client.MatchingLabels{netv1.PoolLabel: pool.Name}); err != nil {
		return fmt.Errorf("list ipallocations for pool %s: %w", pool.Name, err)
	}
	for i := range list.Items {
		o := &list.Items[i]
		if o.Spec.PoolRef.Name != pool.Name || !ownedBy(o, consumer, consumerKind) {
			continue
		}
		if a, err := netip.ParseAddr(o.Spec.Address); err == nil && a.Unmap() == keep {
			continue
		}
		if err := c.Delete(ctx, o); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("release ipallocation %s: %w", o.Name, err)
		}
	}
	return nil
}

// poolAllocations reads the pool's allocations through the STRONG reader — a cached list can
// miss a claim another allocator just made, and the entire design rests on nobody having to
// assume they are the only writer. It returns every allocated address in the pool and the
// subset this consumer already owns.
func poolAllocations(ctx context.Context, r client.Reader, pool *netv1.IPPool,
	consumer client.Object, consumerKind string) (used, mine map[netip.Addr]struct{}, err error) {
	var list netv1.IPAllocationList
	if err := r.List(ctx, &list, client.InNamespace(pool.Namespace),
		client.MatchingLabels{netv1.PoolLabel: pool.Name}); err != nil {
		return nil, nil, fmt.Errorf("list ipallocations for pool %s: %w", pool.Name, err)
	}
	used, mine = map[netip.Addr]struct{}{}, map[netip.Addr]struct{}{}
	for i := range list.Items {
		o := &list.Items[i]
		// The label is an index, not a fact — spec.poolRef is what the object claims.
		if o.Spec.PoolRef.Name != pool.Name {
			continue
		}
		a, perr := netip.ParseAddr(o.Spec.Address)
		if perr != nil {
			continue
		}
		a = a.Unmap()
		used[a] = struct{}{}
		if ownedBy(o, consumer, consumerKind) {
			mine[a] = struct{}{}
		}
	}
	return used, mine, nil
}

// ownedBy reports whether alloc's controller reference is this consumer. UID, not name alone:
// a deleted-and-recreated consumer of the same name is a DIFFERENT consumer, and adopting its
// predecessor's claim would hand out an address nothing owns.
func ownedBy(alloc *netv1.IPAllocation, consumer client.Object, consumerKind string) bool {
	ref := metav1.GetControllerOf(alloc)
	if ref == nil {
		return false
	}
	if ref.Kind != consumerKind || ref.Name != consumer.GetName() {
		return false
	}
	return consumer.GetUID() == "" || ref.UID == consumer.GetUID()
}

// heldIn returns the lowest address this consumer already holds inside prefix that is still
// allocatable there, so a re-reconcile keeps the address it has rather than renumbering. The
// lowest, not an arbitrary map entry, so the choice is deterministic.
func heldIn(mine map[netip.Addr]struct{}, prefix netip.Prefix, resv []netip.Addr) (netip.Addr, bool) {
	var best netip.Addr
	for a := range mine {
		if !allocator.InPrefix(prefix, a) || isReserved(resv, a) {
			continue
		}
		if !best.IsValid() || a.Less(best) {
			best = a
		}
	}
	return best, best.IsValid()
}

// stickyOrLowest keeps the previously-allocated address if it is still valid and free,
// otherwise falls back to the lowest free address in the prefix.
func stickyOrLowest(prefix netip.Prefix, preferred *netip.Addr, used map[netip.Addr]struct{}, resv []netip.Addr) (netip.Addr, bool) {
	if preferred != nil && allocator.InPrefix(prefix, *preferred) {
		if _, taken := used[*preferred]; !taken && !isReserved(resv, *preferred) {
			return *preferred, true
		}
	}
	return allocator.LowestFree(prefix, used, resv)
}

func isReserved(resv []netip.Addr, a netip.Addr) bool {
	for _, x := range resv {
		if x == a {
			return true
		}
	}
	return false
}

// poolPrefixFor returns the pool prefix matching a pinned address's family, or the pool's
// single prefix (preferring v4) when unpinned.
func poolPrefixFor(p *netv1.IPPool, pinned *netip.Addr) (netip.Prefix, error) {
	v4, v6, err := parsePoolPrefixes(p)
	if err != nil {
		return netip.Prefix{}, err
	}
	if pinned != nil {
		if pinned.Unmap().Is4() {
			if v4 != nil {
				return *v4, nil
			}
		} else if v6 != nil {
			return *v6, nil
		}
		return netip.Prefix{}, fmt.Errorf("pinned address family not offered by pool")
	}
	if v4 != nil {
		return *v4, nil
	}
	return *v6, nil
}
