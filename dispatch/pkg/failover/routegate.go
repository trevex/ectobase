// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package failover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
)

// The route gate on fence release. A drained /64 means its broker sees no VMI left there, not that
// no ROUTE is left there: the recovered node's agent withdraws a moved VM's host route only after
// the CNI DEL detaches the interface and its next reconcile tick, and a node whose kubelet died
// under a still-running agent and flowplane never withdraws it. The reflector's fence is a filter
// over what it stores, so releasing it first re-advertises the moved VM's address as {stale
// source, new pool}, and agents program only the first nexthop of that sorted set. Release
// therefore also waits until the reflector holds, from the /64, no address placed on another pool.

// ConditionFenceReleaseBlocked is the ClusterPool condition that says a drained, fenced prefix is
// being held because it still announces an address placed on another pool (RoutesStillAnnounced),
// or because that could not be checked (RouteCheckFailed). False once nothing is held for that
// reason.
const ConditionFenceReleaseBlocked = "FenceReleaseBlocked"

// routeRecheck is how soon a release held on routes is looked at again: about one agent reconcile
// tick, since that is what a normal withdraw waits for. Every second of it keeps the recovered
// pool's own routes hidden too.
const routeRecheck = 5 * time.Second

// routeBatch caps the keys in one AnnouncedFrom call. The question covers every overlay address
// placed off the recovering pool, and a key is ~30 bytes on the wire, so this keeps each call far
// inside gRPC's 4 MiB default message limit however large the fleet.
const routeBatch = 5000

// RouteKey names one overlay route: a host prefix in a VNI, spelled as the agent announces it.
type RouteKey struct {
	VNI    uint32
	Prefix string
}

func (k RouteKey) String() string { return fmt.Sprintf("vni %d %s", k.VNI, k.Prefix) }

// RouteHolding is one node still announcing Key, with the nexthop inside the asked prefix it
// announced it by. Origin is the node's route-bus id; empty if the reflector did not say.
type RouteHolding struct {
	Key     RouteKey
	Origin  string
	Nexthop string
}

// RouteHolder asks the route reflector who still announces any of keys with a nexthop inside
// prefix — stored, whether or not a fence hides it. An error means "unknown", and a release gated
// on it does not happen.
type RouteHolder interface {
	AnnouncedFrom(ctx context.Context, prefix string, keys []RouteKey) ([]RouteHolding, error)
}

// AnnouncedFrom refuses, like the rest of DenyFencer: with no reflector there is no way to show a
// release safe. Release fails there anyway, so this only keeps the two answers consistent.
func (DenyFencer) AnnouncedFrom(context.Context, string, []RouteKey) ([]RouteHolding, error) {
	return nil, errors.New("no route reflector configured")
}

// placedElsewhere is every overlay host route of a NIC compiled for a pool other than lostPool,
// with what each belongs to ("nic <namespace>/<name> on pool <pool>").
//
// It reads placement, not history. A NIC's twin lives in the namespace of the pool its workload is
// bound to now — a VM, a container, or the NIC on its own — so a twin outside lostPool's namespace
// is an address that must not be announced from lostPool's prefixes except while a move off it is
// still in flight, which is exactly what a release has to wait out. Failover's own FailedOver marks
// would not do: the status write after a rebind can lose a conflict or a crash, a planned move off
// a lost pool never gets one, and a reschedule overwrites it. The twin carries the resolved VNI and
// the overlay IPs the agents announce; LB addresses are not overlay IPs and are never asked about.
func (r *Reconciler) placedElsewhere(ctx context.Context, lostPool string) ([]RouteKey, map[RouteKey]string, error) {
	var twins compiledv1.CompiledNICList
	// Read-only and possibly large: skip the cache's per-call deep copy.
	if err := r.Client.List(ctx, &twins, client.UnsafeDisableDeepCopy); err != nil {
		return nil, nil, fmt.Errorf("list compilednics: %w", err)
	}
	here := validate.PoolNamespace(lostPool)
	owner := map[RouteKey]string{}
	var keys []RouteKey
	for i := range twins.Items {
		t := &twins.Items[i]
		if t.Namespace == here || t.Spec.VNI <= 0 {
			continue
		}
		for _, ip := range t.Spec.OverlayIPs {
			prefix, ok := hostPrefix(ip)
			if !ok {
				continue
			}
			k := RouteKey{VNI: uint32(t.Spec.VNI), Prefix: prefix}
			if _, dup := owner[k]; !dup {
				keys = append(keys, k)
				owner[k] = describeTwin(t)
			}
		}
	}
	return keys, owner, nil
}

// describeTwin names a NIC twin by its source and the pool it is compiled for.
func describeTwin(t *compiledv1.CompiledNIC) string {
	ann := t.GetAnnotations()
	src := ann[compiledv1.SourceNamespaceAnnotation] + "/" + ann[compiledv1.SourceNameAnnotation]
	if src == "/" {
		src = t.Namespace + "/" + t.Name
	}
	pool := t.Spec.ClusterName
	if pool == "" {
		pool = strings.TrimPrefix(t.Namespace, validate.PoolNamespace(""))
	}
	return fmt.Sprintf("nic %s on pool %s", src, pool)
}

// hostPrefix is the host route the agent announces for an overlay IP: "/32" for v4, "/128" for v6,
// on the address as spelled (mesh/agent hostPrefix). The reflector also matches canonical form.
func hostPrefix(ip string) (string, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	if parsed.To4() != nil {
		return ip + "/32", true
	}
	return ip + "/128", true
}

// routesGone asks whether prefix still announces any of keys, routeBatch keys per call. ok is true
// only when every call answered and none held anything; otherwise why says what holds the release.
func (r *Reconciler) routesGone(ctx context.Context, prefix string, keys []RouteKey, owner map[RouteKey]string) (ok bool, reason, why string) {
	if len(keys) == 0 {
		return true, "", ""
	}
	if r.Routes == nil {
		return false, "RouteCheckFailed", prefix + ": no route reflector configured"
	}
	var held []RouteHolding
	for start := 0; start < len(keys); start += routeBatch {
		batch := keys[start:min(start+routeBatch, len(keys))]
		hs, err := r.Routes.AnnouncedFrom(ctx, prefix, batch)
		if err != nil {
			return false, "RouteCheckFailed", fmt.Sprintf("%s: cannot ask the reflector what it still announces: %v", prefix, err)
		}
		held = append(held, hs...)
	}
	if len(held) == 0 {
		return true, "", ""
	}
	return false, "RoutesStillAnnounced", fmt.Sprintf("%s still announces addresses placed on other pools, waiting for their withdraw: %s",
		prefix, describeHeld(held, owner))
}

// describeHeld lists held routes with the node announcing each and what it belongs to, capped so a
// condition message stays readable.
func describeHeld(held []RouteHolding, owner map[RouteKey]string) string {
	const shown = 5
	parts := make([]string, 0, len(held))
	for _, h := range held {
		node := h.Origin
		if node == "" {
			node = "an unnamed node"
		}
		parts = append(parts, fmt.Sprintf("%s from node %s via %s (%s)", h.Key, node, h.Nexthop, owner[h.Key]))
	}
	sort.Strings(parts)
	if len(parts) > shown {
		parts = append(parts[:shown], fmt.Sprintf("and %d more", len(held)-shown))
	}
	return strings.Join(parts, ", ")
}
