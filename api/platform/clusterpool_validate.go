// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/trevex/ectobase/api/validate"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Minimum underlayPrefix lengths. The prefix is a trust grant (the exact IP constraint of the pool's
// route-bus intermediate) and a fence (failover blocklists it in Ceph and hides it on the route bus),
// so a short one is never a harmless typo: it would let one pool vouch for, and fence, everyone
// else's underlay. A /32 is a whole IPv6 provider allocation and a /16 is 65536 IPv4 addresses; no
// single pool needs more, and anything shorter is a mistake. The signer separately refuses a prefix
// that overlaps another pool's or a fleet identity's.
const (
	minUnderlayBitsV6 = 32
	minUnderlayBitsV4 = 16
)

// Validate constrains the pool's NAME and its spec.underlayPrefix. The name IS the cluster
// identifier that workloads reference via spec.clusterName, and it becomes the `pool-<name>`
// namespace holding the pool's compiled objects (and the per-pool RBAC bound to it). Generic
// object-name validation only requires a path segment, which would happily accept `pool.a` or a
// 200-character name and then fail later at namespace creation.
func (o *ClusterPool) Validate(ctx context.Context) field.ErrorList {
	errs := validate.ClusterName(field.NewPath("metadata", "name"), o.Name)
	return append(errs, ValidateUnderlayPrefix(field.NewPath("spec", "underlayPrefix"), o.Spec.UnderlayPrefix)...)
}

// ValidateUpdate implements the kit rest.ValidateUpdater hook. The status subresource runs it too,
// so an unchanged spec passes: a pool stored before a check existed must not lose its own status
// writes (the broker's heartbeat). A changed spec is validated in full.
func (o *ClusterPool) ValidateUpdate(ctx context.Context, old runtime.Object) field.ErrorList {
	if prev, ok := old.(*ClusterPool); ok && equality.Semantic.DeepEqual(prev.Spec, o.Spec) {
		return nil
	}
	return o.Validate(ctx)
}

// ValidateUnderlayPrefix accepts an empty prefix (failover then neither fences nor rebinds; the signer
// denies the pool its intermediate) or a canonical CIDR of a sane length. Canonical means exactly
// the spelling netip prints, with no host bits: the prefix is compared as a string in places
// (status.fencedPrefixes, NetworkFence names), so two spellings of one prefix must not exist.
// IPv4-mapped IPv6 (::ffff:a.b.c.d/n) is refused: the signer and the reflector would each have to
// guess which family it means. The dispatch signer applies it too, to a prefix stored before this
// check existed.
func ValidateUnderlayPrefix(path *field.Path, s string) field.ErrorList {
	if s == "" {
		return nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return field.ErrorList{field.Invalid(path, s, "not a CIDR prefix")}
	}
	if p.Addr().Is4In6() {
		return field.ErrorList{field.Invalid(path, s, "IPv4-mapped IPv6 is not allowed; write an IPv4 prefix")}
	}
	if m := p.Masked(); m != p {
		return field.ErrorList{field.Invalid(path, s, fmt.Sprintf("has host bits set; the prefix is %s", m))}
	}
	if p.String() != s {
		return field.ErrorList{field.Invalid(path, s, fmt.Sprintf("not in canonical form; write %s", p))}
	}
	minBits := minUnderlayBitsV6
	if p.Addr().Is4() {
		minBits = minUnderlayBitsV4
	}
	if p.Bits() < minBits {
		return field.ErrorList{field.Invalid(path, s, fmt.Sprintf("too short: must be at least /%d", minBits))}
	}
	return nil
}
