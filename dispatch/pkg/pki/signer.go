// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package pki is the dispatch-side signer for ectobase PKI. It watches
// RouteBusIdentity requests, signs a per-pool, name-constrained intermediate CA from the
// root CA (a dispatch-only cert-manager Secret), and writes the signed intermediate +
// root bundle back into status. Pools mint their own per-node agent leaves from the
// intermediate; the reflector trusts only the root and gets cross-pool isolation for free
// because Go's TLS chain verification enforces the intermediate's NameConstraints.
package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/trevex/ectobase/api/platform"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// dnsSuffix roots the route-bus SAN namespace. A pool's intermediate is name-constrained to
// <pool>.<dnsSuffix>; its node leaves carry a DNS SAN <node>.<pool>.<dnsSuffix>, so the
// reflector's chain verification rejects a leaf whose pool doesn't match the intermediate.
const dnsSuffix = "routebus.ectobase.dev"

// PoolDNSDomain is the name-constraint domain for a pool's intermediate CA.
func PoolDNSDomain(pool string) string { return pool + "." + dnsSuffix }

// NodeDNSName is the DNS SAN a per-node agent leaf must carry to validate under its pool's
// intermediate. Pools set this when minting node leaves (Phase 4).
func NodeDNSName(node, pool string) string { return node + "." + PoolDNSDomain(pool) }

// intermediateTTL is how long a signed pool intermediate is valid. Long-lived relative to
// the per-node leaves the pool mints beneath it (which rotate on the pool's cadence).
const intermediateTTL = 90 * 24 * time.Hour

// deniedRecheck is how soon a denied identity is reconciled again without an event.
const deniedRecheck = 10 * time.Minute

// SignIntermediate signs the CSR as a pool-scoped, path-len-0 intermediate CA from the root.
// The returned cert IsCA with MaxPathLen 0 (cannot sign further CAs) and is name-constrained to
// the pool's DNS domain AND its underlay IP ranges, so it can only issue leaves for its own pool
// and only with node IP SANs inside the pool's underlay. permittedCIDRs must not be empty: an
// intermediate with no IP constraint could mint a leaf for any VTEP on the route bus. Pure.
func SignIntermediate(rootCert *x509.Certificate, rootKey crypto.Signer, csrDER []byte, poolName string, permittedCIDRs []string, notAfter time.Time) ([]byte, error) {
	if len(permittedCIDRs) == 0 {
		return nil, fmt.Errorf("no permitted underlay CIDRs: an intermediate is only signed with an IP constraint")
	}
	block, _ := pem.Decode(csrDER)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("spec.request is not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR self-signature invalid: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "routebus-intermediate-" + poolName},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		// Cross-pool boundary: this intermediate may only issue leaves whose DNS SANs are
		// under the pool's domain. Go's TLS chain verification enforces this on the reflector.
		PermittedDNSDomains:         []string{PoolDNSDomain(poolName)},
		PermittedDNSDomainsCritical: true,
	}
	// IP boundary: constrain the intermediate to the pool's underlay ranges so it cannot mint a
	// leaf with an IP SAN in another pool's underlay (which the reflector's nexthop==SAN check
	// would otherwise accept).
	for _, c := range permittedCIDRs {
		_, ipNet, perr := net.ParseCIDR(c)
		if perr != nil {
			return nil, fmt.Errorf("bad underlay CIDR %q: %w", c, perr)
		}
		tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, ipNet)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, csr.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("sign intermediate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// RootCA holds the root signing material (loaded from the dispatch cert-manager Secret).
type RootCA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	PEM  []byte // root cert PEM, published as status.caBundle
}

// Signer reconciles RouteBusIdentity: it signs each request's CSR into a pool intermediate
// and writes the result to status. Inactive (skips) when Root is nil (mTLS not configured).
//
// The intermediate's IP constraint never comes from a field the constrained party writes. A pool's
// broker files its own RouteBusIdentity (it holds update on it), so a pool's constraint is its
// ClusterPool's operator-authored spec.underlayPrefix, and the request's permittedUnderlayCIDRs is
// ignored. Only a fleet identity — one the operator names in FleetIdentities, such as the WAN edge
// fleet, created by the operator and writable by no broker — is constrained to its own spec. Which
// rule applies is configuration, never inferred: a missing ClusterPool does not make an identity a
// fleet identity, because an identity left behind by a deleted ClusterPool is still broker-writable.
type Signer struct {
	Client client.Client
	// Reader reads ClusterPools for the constraint decision. It should be uncached
	// (mgr.GetAPIReader()), so a ClusterPool the cache has not caught up with is still seen. nil
	// uses Client.
	Reader client.Reader
	Root   *RootCA
	// ClientCA signs the brokers' dispatch client certificates (--dispatch-client-ca-cert/key). It
	// is a separate root, the only one the dispatch apiserver accepts client certificates from, so
	// nothing a pool intermediate (under Root) mints can authenticate there. nil signs none.
	ClientCA *RootCA
	// FleetIdentities names the RouteBusIdentities that are not pools and whose operator-written
	// spec.permittedUnderlayCIDRs is trusted (--routebus-fleet-identities). Empty trusts none.
	FleetIdentities []string
}

func (s *Signer) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var id platformv1.RouteBusIdentity
	if err := s.Client.Get(ctx, req.NamespacedName, &id); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if s.Root == nil && s.ClientCA == nil {
		// mTLS not configured on this dispatch — nothing to sign. (Requeue is driven by
		// events; a later config that mounts the roots re-runs on the next request.)
		return ctrl.Result{}, nil
	}
	orig := id.Status.DeepCopy()
	res, poolMark, err := s.reconcileIntermediate(ctx, &id)
	if err != nil {
		return ctrl.Result{}, err
	}
	clientRes, err := s.reconcileClient(ctx, &id)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !equality.Semantic.DeepEqual(*orig, id.Status) {
		if err := s.Client.Status().Update(ctx, &id); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil // the object changed; its event re-runs this
			}
			return ctrl.Result{}, err
		}
	}
	if poolMark != nil {
		if err := s.markPool(ctx, id.Name, *poolMark); err != nil {
			return ctrl.Result{}, err
		}
	}
	return soonest(res, clientRes), nil
}

// soonest merges two results, keeping the earlier requeue.
func soonest(a, b ctrl.Result) ctrl.Result {
	switch {
	case a.RequeueAfter == 0:
		return b
	case b.RequeueAfter == 0 || a.RequeueAfter < b.RequeueAfter:
		return a
	}
	return b
}

// reconcileIntermediate decides the route-bus intermediate in id's status, in memory. poolMark, when
// not nil, is what to record on the ClusterPool: the denial, or "" once signed.
func (s *Signer) reconcileIntermediate(ctx context.Context, id *platformv1.RouteBusIdentity) (res ctrl.Result, poolMark *string, err error) {
	denyPool := func(msg string) *string { setDenied(id, msg); return &msg }
	signed := ""
	if s.Root == nil {
		return ctrl.Result{}, nil, nil
	}
	if id.Spec.PoolName == "" || len(id.Spec.Request) == 0 {
		setDenied(id, "spec.poolName and spec.request are required")
		return ctrl.Result{}, nil, nil
	}
	// RBAC binds a broker to the identity NAMED after its pool; spec.poolName is a field it
	// writes. Signing for any other poolName would hand it another identity's DNS domain and range.
	if id.Spec.PoolName != id.Name {
		return ctrl.Result{}, denyPool(fmt.Sprintf("spec.poolName %q must equal the RouteBusIdentity name %q", id.Spec.PoolName, id.Name)), nil
	}
	permitted, note, denial, err := s.constraint(ctx, id)
	if err != nil {
		return ctrl.Result{}, nil, err
	}
	if denial != "" {
		// A denial can hinge on objects the signer does not watch (the pool it overlapped is
		// deleted, a fleet identity's ranges change), so look again later.
		return ctrl.Result{RequeueAfter: deniedRecheck}, denyPool(denial), nil
	}
	// Idempotent: if already signed for THIS public key under THIS constraint and not near
	// expiry, leave it. A cert carrying a different constraint (signed under an earlier rule, or
	// before the operator changed the prefix) is re-signed now, not at its expiry.
	if fresh, err := s.alreadySigned(id, permitted); err == nil && fresh {
		return ctrl.Result{RequeueAfter: intermediateTTL / 3}, &signed, nil
	}

	cert, err := SignIntermediate(s.Root.Cert, s.Root.Key, id.Spec.Request, id.Spec.PoolName, permitted, time.Now().Add(intermediateTTL))
	if err != nil {
		return ctrl.Result{}, denyPool(err.Error()), nil
	}
	msg := fmt.Sprintf("intermediate CA signed for pool %s, IP-constrained to %s", id.Spec.PoolName, strings.Join(permitted, ","))
	if note != "" {
		msg += "; " + note
		log.FromContext(ctx).Info(note, "identity", id.Name)
	}
	id.Status.Certificate = cert
	id.Status.CABundle = s.Root.PEM
	meta.SetStatusCondition(&id.Status.Conditions, metav1.Condition{
		Type: "Signed", Status: metav1.ConditionTrue, Reason: "Issued", Message: msg,
	})
	return ctrl.Result{RequeueAfter: intermediateTTL / 3}, &signed, nil
}

// ConditionRouteBusIdentityDenied is set on a ClusterPool while the signer denies the pool's
// RouteBusIdentity. A denied pool keeps running on the intermediate it already has and only fails at
// renewal, months later, so the denial has to be visible where the operator looks at the pool.
const ConditionRouteBusIdentityDenied = "RouteBusIdentityDenied"

// markPool sets RouteBusIdentityDenied on ClusterPool name: True with msg when denied (msg
// non-empty), False once signed, and nothing for a pool that was never denied. Other writers patch
// the same status (the broker's heartbeat, pool health, failover), so this patches with an
// optimistic lock and retries on conflict. A missing ClusterPool (a fleet identity) is no error.
func (s *Signer) markPool(ctx context.Context, name, msg string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var pool platformv1.ClusterPool
		if err := s.Client.Get(ctx, client.ObjectKey{Name: name}, &pool); err != nil {
			return client.IgnoreNotFound(err)
		}
		c := metav1.Condition{Type: ConditionRouteBusIdentityDenied, ObservedGeneration: pool.Generation}
		switch {
		case msg != "":
			c.Status, c.Reason, c.Message = metav1.ConditionTrue, "Denied", msg
		case meta.FindStatusCondition(pool.Status.Conditions, ConditionRouteBusIdentityDenied) != nil:
			c.Status, c.Reason, c.Message = metav1.ConditionFalse, "Signed", "the pool's intermediate is signed"
		default:
			return nil
		}
		orig := pool.DeepCopy()
		if !meta.SetStatusCondition(&pool.Status.Conditions, c) {
			return nil
		}
		return s.Client.Status().Patch(ctx, &pool, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{}))
	})
}

// constraint decides the IP ranges id's intermediate is constrained to. For a fleet identity it is
// the identity's own spec; for any other identity it must be a pool, and the range is exactly its
// ClusterPool's spec.underlayPrefix (note says so when the request asked for ranges outside it).
// denial is non-empty when there is no range to sign under: the signer fails closed. err is a
// failed read (retry).
func (s *Signer) constraint(ctx context.Context, id *platformv1.RouteBusIdentity) (permitted []string, note, denial string, err error) {
	reader := s.Reader
	if reader == nil {
		reader = s.Client
	}
	var pool platformv1.ClusterPool
	err = reader.Get(ctx, client.ObjectKey{Name: id.Spec.PoolName}, &pool)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, "", "", fmt.Errorf("get ClusterPool %s: %w", id.Spec.PoolName, err)
	}
	poolExists := err == nil
	if slices.Contains(s.FleetIdentities, id.Name) {
		switch {
		case poolExists:
			// The pool's broker would write this identity's spec, and a fleet identity's spec is trusted.
			return nil, "", fmt.Sprintf("RouteBusIdentity %s is both a fleet identity and a ClusterPool "+
				"(--routebus-fleet-identities names it); rename one of them", id.Name), nil
		case len(id.Spec.PermittedUnderlayCIDRs) == 0:
			return nil, "", fmt.Sprintf("fleet identity %s has no spec.permittedUnderlayCIDRs; "+
				"an intermediate is only signed with an IP constraint", id.Name), nil
		}
		return canonicalCIDRs(id.Spec.PermittedUnderlayCIDRs), "", "", nil
	}
	if !poolExists {
		return nil, "", fmt.Sprintf("no ClusterPool %s and not a fleet identity (--routebus-fleet-identities); "+
			"a pool intermediate is only signed for an enrolled ClusterPool", id.Spec.PoolName), nil
	}
	if pool.Spec.UnderlayPrefix == "" {
		return nil, "", fmt.Sprintf("ClusterPool %s has no spec.underlayPrefix; a pool intermediate is only signed "+
			"with an operator-declared IP constraint", pool.Name), nil
	}
	// Admission refuses such a prefix now, but one stored before it did (or written past it) must
	// not become a constraint either.
	if errs := platform.ValidateUnderlayPrefix(field.NewPath("spec", "underlayPrefix"), pool.Spec.UnderlayPrefix); len(errs) > 0 {
		return nil, "", fmt.Sprintf("ClusterPool %s: %s", pool.Name, errs.ToAggregate()), nil
	}
	prefix, perr := netip.ParsePrefix(pool.Spec.UnderlayPrefix)
	if perr != nil {
		return nil, "", fmt.Sprintf("ClusterPool %s spec.underlayPrefix %q is not a CIDR: %v", pool.Name, pool.Spec.UnderlayPrefix, perr), nil
	}
	prefix = canonical(prefix)
	if denial, err := s.overlap(ctx, reader, &pool, prefix); denial != "" || err != nil {
		return nil, "", denial, err
	}
	var outside []string
	for _, c := range id.Spec.PermittedUnderlayCIDRs {
		if p, err := netip.ParsePrefix(c); err != nil || !prefixWithin(p, prefix) {
			outside = append(outside, c)
		}
	}
	if len(outside) > 0 {
		note = fmt.Sprintf("ignored spec.permittedUnderlayCIDRs %v outside ClusterPool %s spec.underlayPrefix %s",
			outside, pool.Name, prefix)
	}
	return []string{prefix.String()}, note, "", nil
}

// overlap denies a pool prefix that overlaps one another identity is constrained to: another
// ClusterPool's underlayPrefix, or a fleet identity's permittedUnderlayCIDRs. Either way two holders
// could mint leaves for the same VTEPs.
//
// Between two pools the INCUMBENT wins: a pool whose identity already holds a root-signed, unexpired
// intermediate covering part of the other's prefix keeps it, and the pool whose prefix moved into that
// range is denied. Otherwise an operator edit of an older pool's prefix into a newer pool's range
// would take that range away the moment the edited pool is re-signed. Only when neither or both hold
// such a certificate does enrollment order decide (creation time, then name).
//
// Two pools are never both signed for overlapping ranges, not even briefly: the signer reconciles one
// identity at a time (MaxConcurrentReconciles 1, one leader), and reads ClusterPools and identities
// uncached, so each decision sees the certificate the previous one wrote. A pool that loses is
// denied and its certificate cleared before the next decision runs.
func (s *Signer) overlap(ctx context.Context, reader client.Reader, pool *platformv1.ClusterPool, prefix netip.Prefix) (denial string, err error) {
	var pools platformv1.ClusterPoolList
	if err := reader.List(ctx, &pools); err != nil {
		return "", fmt.Errorf("list ClusterPools: %w", err)
	}
	for i := range pools.Items {
		other := &pools.Items[i]
		op, perr := netip.ParsePrefix(other.Spec.UnderlayPrefix)
		if other.Name == pool.Name || perr != nil || !canonical(op).Overlaps(prefix) {
			continue
		}
		theirs, err := s.holdsOverlap(ctx, reader, other.Name, prefix)
		if err != nil {
			return "", err
		}
		ours, err := s.holdsOverlap(ctx, reader, pool.Name, canonical(op))
		if err != nil {
			return "", err
		}
		switch {
		case theirs && !ours:
			return fmt.Sprintf("ClusterPool %s spec.underlayPrefix %s overlaps ClusterPool %s's %s, which already holds "+
				"a certificate for it", pool.Name, prefix, other.Name, other.Spec.UnderlayPrefix), nil
		case ours && !theirs:
			continue
		case enrolledBefore(other, pool):
			return fmt.Sprintf("ClusterPool %s spec.underlayPrefix %s overlaps ClusterPool %s's %s, enrolled earlier",
				pool.Name, prefix, other.Name, other.Spec.UnderlayPrefix), nil
		}
	}
	for _, name := range s.FleetIdentities {
		var fleet platformv1.RouteBusIdentity
		if err := reader.Get(ctx, client.ObjectKey{Name: name}, &fleet); apierrors.IsNotFound(err) {
			continue
		} else if err != nil {
			return "", fmt.Errorf("get fleet identity %s: %w", name, err)
		}
		for _, c := range fleet.Spec.PermittedUnderlayCIDRs {
			if p, err := netip.ParsePrefix(c); err == nil && canonical(p).Overlaps(prefix) {
				return fmt.Sprintf("ClusterPool %s spec.underlayPrefix %s overlaps fleet identity %s's %s",
					pool.Name, prefix, name, c), nil
			}
		}
	}
	return "", nil
}

// holdsOverlap reports whether identity name currently holds a root-signed, unexpired intermediate
// whose permitted IP ranges overlap prefix.
func (s *Signer) holdsOverlap(ctx context.Context, reader client.Reader, name string, prefix netip.Prefix) (bool, error) {
	var id platformv1.RouteBusIdentity
	if err := reader.Get(ctx, client.ObjectKey{Name: name}, &id); apierrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("get RouteBusIdentity %s: %w", name, err)
	}
	cb, _ := pem.Decode(id.Status.Certificate)
	if cb == nil {
		return false, nil
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil || cert.CheckSignatureFrom(s.Root.Cert) != nil || time.Now().After(cert.NotAfter) {
		return false, nil
	}
	for _, r := range cert.PermittedIPRanges {
		addr, ok := netip.AddrFromSlice(r.IP)
		if !ok {
			continue
		}
		ones, _ := r.Mask.Size()
		if canonical(netip.PrefixFrom(addr, ones)).Overlaps(prefix) {
			return true, nil
		}
	}
	return false, nil
}

// enrolledBefore orders ClusterPools by creation time, then by name.
func enrolledBefore(a, b *platformv1.ClusterPool) bool {
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	return a.Name < b.Name
}

// prefixWithin reports whether inner lies entirely inside outer (same family).
func prefixWithin(inner, outer netip.Prefix) bool {
	return inner.Addr().Is4() == outer.Addr().Is4() && inner.Bits() >= outer.Bits() && outer.Contains(inner.Addr())
}

// alreadySigned reports whether status carries a cert the root signed, for the current CSR's public
// key, name-constrained exactly to the identity's DNS domain and to permitted, and comfortably before
// expiry (so re-issuing on rotation or a changed constraint but not every reconcile).
func (s *Signer) alreadySigned(id *platformv1.RouteBusIdentity, permitted []string) (bool, error) {
	if len(id.Status.Certificate) == 0 {
		return false, nil
	}
	cb, _ := pem.Decode(id.Status.Certificate)
	if cb == nil {
		return false, nil
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return false, err
	}
	if time.Until(cert.NotAfter) < intermediateTTL/2 {
		return false, nil // due for rotation
	}
	if cert.CheckSignatureFrom(s.Root.Cert) != nil {
		return false, nil // not ours: another issuer, or a root since rotated
	}
	if !slices.Equal(cert.PermittedDNSDomains, []string{PoolDNSDomain(id.Spec.PoolName)}) ||
		!sameRanges(cert.PermittedIPRanges, permitted) {
		return false, nil // signed under another constraint
	}
	rb, _ := pem.Decode(id.Spec.Request)
	if rb == nil {
		return false, nil
	}
	csr, err := x509.ParseCertificateRequest(rb.Bytes)
	if err != nil {
		return false, err
	}
	return publicKeysEqual(cert.PublicKey, csr.PublicKey), nil
}

// sameRanges reports whether a cert's permitted IP ranges are exactly the CIDRs in want, as sets
// of canonical prefixes.
func sameRanges(got []*net.IPNet, want []string) bool {
	set := func(ps []netip.Prefix) []string {
		out := make([]string, 0, len(ps))
		for _, p := range ps {
			out = append(out, canonical(p).String())
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	var g, w []netip.Prefix
	for _, n := range got {
		addr, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			return false
		}
		ones, _ := n.Mask.Size()
		g = append(g, netip.PrefixFrom(addr, ones))
	}
	for _, c := range want {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return false
		}
		w = append(w, p)
	}
	return slices.Equal(set(g), set(w))
}

// canonical is p masked, with an IPv4-mapped IPv6 prefix turned into the IPv4 prefix it maps. Both
// sides of every comparison go through it: the certificate encodes a mapped range as IPv4, so
// unmapping only one side never matches and re-signs on every reconcile.
func canonical(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() {
		return netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0)).Masked()
	}
	return p.Masked()
}

// canonicalCIDRs rewrites each CIDR in canonical form, leaving one that does not parse for
// SignIntermediate to reject.
func canonicalCIDRs(cidrs []string) []string {
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			c = canonical(p).String()
		}
		out = append(out, c)
	}
	return out
}

// setDenied records Signed=False and drops any intermediate from status, in memory: a denied
// identity must not keep presenting an intermediate the signer would no longer issue.
func setDenied(id *platformv1.RouteBusIdentity, msg string) {
	id.Status.Certificate = nil
	meta.SetStatusCondition(&id.Status.Conditions, metav1.Condition{
		Type: "Signed", Status: metav1.ConditionFalse, Reason: "Denied", Message: msg,
	})
}

func (s *Signer) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&platformv1.RouteBusIdentity{}, builder.WithPredicates(identitySpecChanged)).
		// The constraint is the ClusterPool's spec.underlayPrefix, so declaring or changing it
		// re-signs (or unblocks a denied) identity right away, and every other pool's too, since an
		// overlap is decided between two pools.
		Watches(&platformv1.ClusterPool{}, handler.EnqueueRequestsFromMapFunc(s.identitiesForPool),
			builder.WithPredicates(underlayPrefixChanged)).
		// One decision at a time is what keeps two pools from being signed for overlapping ranges
		// at once (see overlap). Pinned rather than left to the default.
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(s)
}

// identitySpecChanged admits RouteBusIdentity create and delete events and updates that change the
// spec (a new CSR). Status-only updates, the signer's own writes among them, do not re-trigger it.
// metadata.generation cannot carry this: the aggregated apiserver does not bump it for this type.
var identitySpecChanged = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		o, ok1 := e.ObjectOld.(*platformv1.RouteBusIdentity)
		n, ok2 := e.ObjectNew.(*platformv1.RouteBusIdentity)
		return !ok1 || !ok2 || !equality.Semantic.DeepEqual(o.Spec, n.Spec)
	},
}

// identitiesForPool maps a ClusterPool event to the RouteBusIdentity of every pool (the signer only
// signs an identity named after its pool), the changed one included even when it was just deleted.
// An overlap is decided between two pools, so both sides are looked at again at once.
func (s *Signer) identitiesForPool(ctx context.Context, o client.Object) []reconcile.Request {
	reqs := []reconcile.Request{{NamespacedName: types.NamespacedName{Name: o.GetName()}}}
	var pools platformv1.ClusterPoolList
	if err := s.Client.List(ctx, &pools); err != nil {
		log.FromContext(ctx).Error(err, "list ClusterPools to re-evaluate their identities; only the changed one is")
		return reqs
	}
	for _, p := range pools.Items {
		if p.Name != o.GetName() {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Name: p.Name}})
		}
	}
	return reqs
}

// underlayPrefixChanged admits ClusterPool events that can change an intermediate's constraint:
// create, delete, and an update to spec.underlayPrefix. The broker patches the pool's status every
// few seconds; those must not wake the signer.
var underlayPrefixChanged = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		o, ok1 := e.ObjectOld.(*platformv1.ClusterPool)
		n, ok2 := e.ObjectNew.(*platformv1.ClusterPool)
		return !ok1 || !ok2 || o.Spec.UnderlayPrefix != n.Spec.UnderlayPrefix
	},
}

// publicKeysEqual compares two public keys by their PKIX DER encoding.
func publicKeysEqual(a, b any) bool {
	ad, err1 := x509.MarshalPKIXPublicKey(a)
	bd, err2 := x509.MarshalPKIXPublicKey(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ad) == string(bd)
}

// LoadRootCA reads the root CA cert + key PEM (the dispatch cert-manager ectobase-ca Secret,
// mounted as tls.crt/tls.key) into signing material. Returns nil,nil when both paths are empty
// (mTLS not configured — the signer stays inactive).
func LoadRootCA(certPath, keyPath string) (*RootCA, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil
	}
	certPEM, err := readFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read root cert: %w", err)
	}
	keyPEM, err := readFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read root key: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("root cert is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root cert: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("root cert is not a CA")
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("root key is not PEM")
	}
	key, err := parsePrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root key: %w", err)
	}
	return &RootCA{Cert: cert, Key: key, PEM: certPEM}, nil
}

// parsePrivateKey accepts PKCS#8, EC (SEC1), or PKCS#1 keys (cert-manager emits PKCS#8).
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, fmt.Errorf("PKCS#8 key is not a crypto.Signer")
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }
