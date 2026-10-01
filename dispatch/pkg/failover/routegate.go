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

	"k8s.io/apimachinery/pkg/api/meta"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
)

// The route gate on fence release. A drained /64 means its broker sees no VMI left there, not that
// no ROUTE is left there: the recovered node's agent withdraws a moved VM's host route only after
// the CNI DEL detaches the interface and its next reconcile tick, and a node whose kubelet died
// under a still-running agent and flowplane never withdraws it. The reflector's fence is a filter
// over what it stores, so releasing it first re-advertises the moved VM's address as {stale
// source, new pool}, and agents program only the first nexthop of that sorted set. Release
// therefore also waits until the reflector holds none of those addresses from the /64.

// ConditionFenceReleaseBlocked is the ClusterPool condition that says a drained, fenced prefix is
// being held because a VM failover moved away is still announced from it (RoutesStillAnnounced),
// or because the reflector could not be asked (RouteCheckFailed). False once nothing is held for
// that reason.
const ConditionFenceReleaseBlocked = "FenceReleaseBlocked"

// routeRecheck is how soon a release held on routes is looked at again: about one agent reconcile
// tick, since that is what a normal withdraw waits for. Every second of it keeps the recovered
// pool's own routes hidden too.
const routeRecheck = 5 * time.Second

// RouteKey names one overlay route: a host prefix in a VNI, spelled as the agent announces it.
type RouteKey struct {
	VNI    uint32
	Prefix string
}

func (k RouteKey) String() string { return fmt.Sprintf("vni %d %s", k.VNI, k.Prefix) }

// RouteHolder asks the route reflector which of keys some origin still announces with a nexthop
// inside prefix — stored, whether or not a fence hides it. An error means "unknown", and a release
// gated on it does not happen.
type RouteHolder interface {
	AnnouncedFrom(ctx context.Context, prefix string, keys []RouteKey) ([]RouteKey, error)
}

// AnnouncedFrom refuses, like the rest of DenyFencer: with no reflector there is no way to show a
// release safe. Release fails there anyway, so this only keeps the two answers consistent.
func (DenyFencer) AnnouncedFrom(context.Context, string, []RouteKey) ([]RouteKey, error) {
	return nil, errors.New("no route reflector configured")
}

// movedRoutes is every overlay host route of a VM failover moved off lostPool, with the VM each
// belongs to ("namespace/name").
//
// Durable state only, so a controller restart between rebind and release loses nothing. A moved VM
// is one failover marked FailedOver (rebindPoolVMs sets that reason on Scheduled and on
// FailoverBlocked) and that is bound elsewhere now. Neither condition names the pool it left, so
// this is every VM failover has ever moved and not moved back here — a superset that is safe: a
// VM that left another pool is never announced from this one unless that is a stale route too.
// Its addresses come from its NICs' compiled twins, which carry the resolved VNI and overlay IPs
// the agents announce. A NIC with no twin has nothing to look up and is skipped.
func (r *Reconciler) movedRoutes(ctx context.Context, lostPool string) ([]RouteKey, map[RouteKey]string, error) {
	var vms computev1.VirtualMachineList
	if err := r.Client.List(ctx, &vms); err != nil {
		return nil, nil, fmt.Errorf("list vms: %w", err)
	}
	var moved []*computev1.VirtualMachine
	for i := range vms.Items {
		vm := &vms.Items[i]
		if vm.Spec.ClusterName != "" && vm.Spec.ClusterName != lostPool && failedOver(vm) {
			moved = append(moved, vm)
		}
	}
	if len(moved) == 0 {
		return nil, nil, nil
	}
	var twins compiledv1.CompiledNICList
	if err := r.Client.List(ctx, &twins); err != nil {
		return nil, nil, fmt.Errorf("list compilednics: %w", err)
	}
	type source struct{ namespace, name string }
	bySource := map[source][]*compiledv1.CompiledNIC{}
	for i := range twins.Items {
		t := &twins.Items[i]
		ann := t.GetAnnotations()
		s := source{ann[compiledv1.SourceNamespaceAnnotation], ann[compiledv1.SourceNameAnnotation]}
		bySource[s] = append(bySource[s], t)
	}
	owner := map[RouteKey]string{}
	var keys []RouteKey
	for _, vm := range moved {
		for _, ref := range vm.Spec.InterfaceRefs {
			for _, t := range bySource[source{vm.Namespace, ref.Name}] {
				if t.Spec.VNI <= 0 {
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
						owner[k] = vm.Namespace + "/" + vm.Name
					}
				}
			}
		}
	}
	return keys, owner, nil
}

// failedOver reports whether failover rebound vm at some point.
func failedOver(vm *computev1.VirtualMachine) bool {
	for _, t := range []string{"Scheduled", "FailoverBlocked"} {
		if c := meta.FindStatusCondition(vm.Status.Conditions, t); c != nil && c.Reason == "FailedOver" {
			return true
		}
	}
	return false
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

// routesGone asks whether prefix still announces any of keys. ok is true only when the reflector
// answered and held none of them; otherwise why says what holds the release.
func (r *Reconciler) routesGone(ctx context.Context, prefix string, keys []RouteKey, owner map[RouteKey]string) (ok bool, reason, why string) {
	if len(keys) == 0 {
		return true, "", ""
	}
	if r.Routes == nil {
		return false, "RouteCheckFailed", prefix + ": no route reflector configured"
	}
	held, err := r.Routes.AnnouncedFrom(ctx, prefix, keys)
	if err != nil {
		return false, "RouteCheckFailed", fmt.Sprintf("%s: cannot ask the reflector what it still announces: %v", prefix, err)
	}
	if len(held) == 0 {
		return true, "", ""
	}
	return false, "RoutesStillAnnounced", fmt.Sprintf("%s still announces a VM failover moved away, waiting for its withdraw: %s",
		prefix, describeHeld(held, owner))
}

// describeHeld lists held routes with their VMs, capped so a condition message stays readable.
func describeHeld(held []RouteKey, owner map[RouteKey]string) string {
	const shown = 5
	parts := make([]string, 0, len(held))
	for _, k := range held {
		parts = append(parts, fmt.Sprintf("%s (vm %s)", k, owner[k]))
	}
	sort.Strings(parts)
	if len(parts) > shown {
		parts = append(parts[:shown], fmt.Sprintf("and %d more", len(held)-shown))
	}
	return strings.Join(parts, ", ")
}
