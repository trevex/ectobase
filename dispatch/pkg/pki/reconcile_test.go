// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// The signer decides a pool intermediate's IP constraint from the operator-authored
// ClusterPool.spec.underlayPrefix, never from the RouteBusIdentity the pool's broker writes.

const poolPrefix = "fd00:cafe:1914::/48"

func signerScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := platformv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func testSigner(t *testing.T, objs ...client.Object) (*Signer, client.Client) {
	t.Helper()
	root, rootKey, rootPEM := makeRoot(t)
	c := fake.NewClientBuilder().WithScheme(signerScheme(t)).WithObjects(objs...).
		WithStatusSubresource(&platformv1.RouteBusIdentity{}).Build()
	return &Signer{Client: c, Root: &RootCA{Cert: root, Key: rootKey, PEM: rootPEM}}, c
}

func clusterPool(name, prefix string) *platformv1.ClusterPool {
	return &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: platformv1.ClusterPoolSpec{UnderlayPrefix: prefix}}
}

func identity(t *testing.T, name string, cidrs ...string) *platformv1.RouteBusIdentity {
	t.Helper()
	csr, _ := makePoolCSR(t, name)
	return &platformv1.RouteBusIdentity{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: platformv1.RouteBusIdentitySpec{PoolName: name, Request: csr, PermittedUnderlayCIDRs: cidrs}}
}

func reconcileIdentity(t *testing.T, s *Signer, c client.Client, name string) *platformv1.RouteBusIdentity {
	t.Helper()
	if _, err := s.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
		t.Fatalf("reconcile %s: %v", name, err)
	}
	var got platformv1.RouteBusIdentity
	if err := c.Get(context.Background(), client.ObjectKey{Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	return &got
}

func signedCert(t *testing.T, id *platformv1.RouteBusIdentity) *x509.Certificate {
	t.Helper()
	if !meta.IsStatusConditionTrue(id.Status.Conditions, "Signed") {
		t.Fatalf("want Signed=True, got %+v", id.Status.Conditions)
	}
	b, _ := pem.Decode(id.Status.Certificate)
	if b == nil {
		t.Fatal("no certificate in status")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func ranges(c *x509.Certificate) []string {
	out := make([]string, 0, len(c.PermittedIPRanges))
	for _, r := range c.PermittedIPRanges {
		out = append(out, r.String())
	}
	return out
}

func requireDenied(t *testing.T, id *platformv1.RouteBusIdentity, contains string) {
	t.Helper()
	c := meta.FindStatusCondition(id.Status.Conditions, "Signed")
	if c == nil || c.Status != metav1.ConditionFalse {
		t.Fatalf("want Signed=False, got %+v", id.Status.Conditions)
	}
	if !strings.Contains(c.Message, contains) {
		t.Fatalf("denial message %q does not mention %q", c.Message, contains)
	}
	if len(id.Status.Certificate) != 0 {
		t.Fatal("a denied identity must carry no certificate")
	}
}

// A pool whose ClusterPool declares no underlayPrefix gets no intermediate at all: without an
// operator-declared range there is nothing to constrain it to that the pool did not choose itself.
func TestSigner_PoolWithoutUnderlayPrefixIsDenied(t *testing.T) {
	s, c := testSigner(t, clusterPool("k02", ""), identity(t, "k02", poolPrefix))
	got := reconcileIdentity(t, s, c, "k02")
	requireDenied(t, got, "ClusterPool k02 has no spec.underlayPrefix")
}

// The declared prefix is the constraint, exactly, whatever the broker asked for.
func TestSigner_PoolIsConstrainedToTheClusterPoolPrefix(t *testing.T) {
	s, c := testSigner(t, clusterPool("k02", poolPrefix), identity(t, "k02", "fd00::/8"))
	got := reconcileIdentity(t, s, c, "k02")
	cert := signedCert(t, got)
	if r := ranges(cert); len(r) != 1 || r[0] != poolPrefix {
		t.Fatalf("PermittedIPRanges = %v, want exactly [%s]", r, poolPrefix)
	}
	if msg := meta.FindStatusCondition(got.Status.Conditions, "Signed").Message; !strings.Contains(msg, "fd00::/8") {
		t.Errorf("the ignored, wider request should be called out in the condition, got %q", msg)
	}
}

// A broker that asks for nothing still gets the declared prefix.
func TestSigner_PoolWithNoRequestedCIDRsGetsThePrefix(t *testing.T) {
	s, c := testSigner(t, clusterPool("k02", poolPrefix), identity(t, "k02"))
	cert := signedCert(t, reconcileIdentity(t, s, c, "k02"))
	if r := ranges(cert); len(r) != 1 || r[0] != poolPrefix {
		t.Fatalf("PermittedIPRanges = %v, want exactly [%s]", r, poolPrefix)
	}
}

// A fleet identity (the WAN edge fleet) is named on the dispatch-controller's command line, created
// by the operator and writable by no broker; its own spec is its range.
func TestSigner_FleetIdentityUsesItsSpec(t *testing.T) {
	s, c := testSigner(t, identity(t, "edge", "fd00:ffff::/32"))
	s.FleetIdentities = []string{"edge"}
	cert := signedCert(t, reconcileIdentity(t, s, c, "edge"))
	if r := ranges(cert); len(r) != 1 || r[0] != "fd00:ffff::/32" {
		t.Fatalf("PermittedIPRanges = %v, want [fd00:ffff::/32]", r)
	}
}

func TestSigner_FleetIdentityWithoutCIDRsIsDenied(t *testing.T) {
	s, c := testSigner(t, identity(t, "edge"))
	s.FleetIdentities = []string{"edge"}
	requireDenied(t, reconcileIdentity(t, s, c, "edge"), "no spec.permittedUnderlayCIDRs")
}

// A name that is both a fleet identity and a ClusterPool is ambiguous: the pool's broker writes the
// identity's spec, so trusting that spec would hand the pool its own constraint. Neither rule wins.
func TestSigner_FleetIdentityCollidingWithAClusterPoolIsDenied(t *testing.T) {
	s, c := testSigner(t, clusterPool("edge", poolPrefix), identity(t, "edge", "fd00:ffff::/32"))
	s.FleetIdentities = []string{"edge"}
	requireDenied(t, reconcileIdentity(t, s, c, "edge"), "both a fleet identity and a ClusterPool")
}

// Not being a pool is never inferred from a missing ClusterPool: an identity left behind by a
// deleted ClusterPool, whose broker can still write its spec, must not be signed on that spec.
func TestSigner_UnknownIdentityWithoutClusterPoolIsDenied(t *testing.T) {
	s, c := testSigner(t, identity(t, "k02", "fd00::/8"))
	s.FleetIdentities = []string{"edge"}
	requireDenied(t, reconcileIdentity(t, s, c, "k02"), "no ClusterPool k02 and not a fleet identity")
}

// RBAC scopes a broker to the identity NAMED after its pool, but spec.poolName is a field the
// broker writes. Signing for a poolName other than the object's name would hand pool k02 the
// intermediate (DNS domain and underlay range) of k03, or of a fleet identity.
func TestSigner_PoolNameMustMatchTheObjectName(t *testing.T) {
	id := identity(t, "k02", "fd00::/8")
	id.Spec.PoolName = "edge"
	s, c := testSigner(t, clusterPool("k02", poolPrefix), id)
	requireDenied(t, reconcileIdentity(t, s, c, "k02"), "must equal")
}

// An intermediate signed under the old rule (the broker's own, wider range) is replaced on the next
// reconcile, for the same key, even though it is nowhere near expiry.
func TestSigner_ResignsWhenTheConstraintDiffers(t *testing.T) {
	id := identity(t, "k02")
	root, rootKey, rootPEM := makeRoot(t)
	old, err := SignIntermediate(root, rootKey, id.Spec.Request, "k02", []string{"fd00::/8"}, time.Now().Add(intermediateTTL))
	if err != nil {
		t.Fatal(err)
	}
	id.Status.Certificate = old
	c := fake.NewClientBuilder().WithScheme(signerScheme(t)).WithObjects(clusterPool("k02", poolPrefix), id).
		WithStatusSubresource(&platformv1.RouteBusIdentity{}).Build()
	s := &Signer{Client: c, Root: &RootCA{Cert: root, Key: rootKey, PEM: rootPEM}}

	cert := signedCert(t, reconcileIdentity(t, s, c, "k02"))
	if r := ranges(cert); len(r) != 1 || r[0] != poolPrefix {
		t.Fatalf("PermittedIPRanges = %v, want the re-signed [%s]", r, poolPrefix)
	}
}

// The re-sign check must not churn: a fresh cert under the current constraint is left alone.
func TestSigner_LeavesAFreshMatchingCertAlone(t *testing.T) {
	s, c := testSigner(t, clusterPool("k02", poolPrefix), identity(t, "k02"))
	first := reconcileIdentity(t, s, c, "k02").Status.Certificate
	second := reconcileIdentity(t, s, c, "k02").Status.Certificate
	if string(first) != string(second) {
		t.Fatal("a fresh cert with the current constraint was re-signed")
	}
}

// A previously signed pool whose prefix is later removed is denied, and its status cert goes.
func TestSigner_DenialClearsAStaleCertificate(t *testing.T) {
	s, c := testSigner(t, clusterPool("k02", poolPrefix), identity(t, "k02"))
	signedCert(t, reconcileIdentity(t, s, c, "k02"))
	var pool platformv1.ClusterPool
	if err := c.Get(context.Background(), client.ObjectKey{Name: "k02"}, &pool); err != nil {
		t.Fatal(err)
	}
	pool.Spec.UnderlayPrefix = ""
	if err := c.Update(context.Background(), &pool); err != nil {
		t.Fatal(err)
	}
	requireDenied(t, reconcileIdentity(t, s, c, "k02"), "no spec.underlayPrefix")
}

// Setting or changing underlayPrefix must reach the identity of the same name, so a denied pool is
// signed as soon as the operator declares its range. Status-only churn (the lease heartbeat) must not.
func TestSigner_ClusterPoolPrefixChangesWakeTheIdentity(t *testing.T) {
	if got := identityForPool(context.Background(), clusterPool("k02", "")); len(got) != 1 || got[0].Name != "k02" {
		t.Fatalf("identityForPool = %v, want [k02]", got)
	}
	old, upd := clusterPool("k02", ""), clusterPool("k02", poolPrefix)
	if !underlayPrefixChanged.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: upd}) {
		t.Error("setting underlayPrefix must wake the signer")
	}
	hb := upd.DeepCopy()
	hb.Status.Phase = "Ready"
	if underlayPrefixChanged.Update(event.UpdateEvent{ObjectOld: upd, ObjectNew: hb}) {
		t.Error("a status-only update must not wake the signer")
	}
	if !underlayPrefixChanged.Create(event.CreateEvent{Object: upd}) || !underlayPrefixChanged.Delete(event.DeleteEvent{Object: upd}) {
		t.Error("ClusterPool create and delete change which rule applies and must wake the signer")
	}
}

// No IP-unconstrained intermediate is ever issued, whichever caller asks.
func TestSignIntermediate_RefusesNoIPConstraint(t *testing.T) {
	root, rootKey, _ := makeRoot(t)
	csr, _ := makePoolCSR(t, "k02")
	if _, err := SignIntermediate(root, rootKey, csr, "k02", nil, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("an intermediate with no IP constraint must be refused")
	}
}

func poolAt(name, prefix string, created time.Time) *platformv1.ClusterPool {
	p := clusterPool(name, prefix)
	p.CreationTimestamp = metav1.NewTime(created)
	return p
}

// Two pools whose prefixes overlap could each mint a leaf for the other's VTEPs. The pool enrolled
// later is denied; the one already running keeps signing, so an operator's mistake on a new pool
// cannot take an existing pool off the route bus at its next renewal.
func TestSigner_PoolPrefixOverlappingAnOlderPoolIsDenied(t *testing.T) {
	now := time.Now()
	older := poolAt("k02", "fd00:cafe:1914::/48", now.Add(-time.Hour))
	newer := poolAt("k03", "fd00:cafe:1914:8000::/49", now)
	s, c := testSigner(t, older, newer, identity(t, "k02"), identity(t, "k03"))

	requireDenied(t, reconcileIdentity(t, s, c, "k03"), "overlaps ClusterPool k02")
	signedCert(t, reconcileIdentity(t, s, c, "k02"))
}

// The same creation time falls back to the name, so exactly one of the two is denied.
func TestSigner_OverlapTieBreaksOnName(t *testing.T) {
	at := time.Now().Add(-time.Hour)
	s, c := testSigner(t, poolAt("k02", "fd00:cafe:1914::/48", at), poolAt("k03", "fd00:cafe:1914::/48", at),
		identity(t, "k02"), identity(t, "k03"))
	signedCert(t, reconcileIdentity(t, s, c, "k02"))
	requireDenied(t, reconcileIdentity(t, s, c, "k03"), "overlaps ClusterPool k02")
}

// A pool may not take a range a fleet identity (the edge loopbacks) is constrained to.
func TestSigner_PoolPrefixOverlappingAFleetIdentityIsDenied(t *testing.T) {
	s, c := testSigner(t, clusterPool("k02", "fd00:ffff::/48"), identity(t, "k02"), identity(t, "edge", "fd00:ffff::/32"))
	s.FleetIdentities = []string{"edge"}
	requireDenied(t, reconcileIdentity(t, s, c, "k02"), "overlaps fleet identity edge")
}

// Disjoint prefixes, the normal case, are signed.
func TestSigner_DisjointPoolPrefixesAreSigned(t *testing.T) {
	s, c := testSigner(t, clusterPool("k02", "fd00:cafe:1914::/48"), clusterPool("k03", "fd00:cafe:2a3b::/48"),
		identity(t, "k02"), identity(t, "k03"), identity(t, "edge", "fd00:ffff::/32"))
	s.FleetIdentities = []string{"edge"}
	signedCert(t, reconcileIdentity(t, s, c, "k02"))
	signedCert(t, reconcileIdentity(t, s, c, "k03"))
}

// An IPv4-mapped prefix (stored before admission refused one) must sign once and then read as
// already signed. Unmapping only the certificate's side made every reconcile re-sign, and each
// re-sign's status write triggered the next.
func TestSigner_IPv4MappedPrefixDoesNotReSignInALoop(t *testing.T) {
	s, c := testSigner(t, clusterPool("k02", "::ffff:10.20.0.0/112"), identity(t, "k02"))
	first := signedCert(t, reconcileIdentity(t, s, c, "k02"))
	if r := ranges(first); len(r) != 1 || r[0] != "10.20.0.0/16" {
		t.Fatalf("PermittedIPRanges = %v, want the unmapped [10.20.0.0/16]", r)
	}
	again := reconcileIdentity(t, s, c, "k02")
	if string(again.Status.Certificate) != string(pemOf(first)) {
		t.Fatal("an unchanged 4in6 constraint was re-signed")
	}
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func TestSameRanges_UnmapsBothSides(t *testing.T) {
	_, v4, _ := net.ParseCIDR("10.20.0.0/16")
	_, mapped, _ := net.ParseCIDR("::ffff:10.20.0.0/112")
	for name, tc := range map[string]struct {
		got  []*net.IPNet
		want []string
	}{
		"v4 cert, mapped want":     {[]*net.IPNet{v4}, []string{"::ffff:10.20.0.0/112"}},
		"mapped cert, v4 want":     {[]*net.IPNet{mapped}, []string{"10.20.0.0/16"}},
		"mapped cert, mapped want": {[]*net.IPNet{mapped}, []string{"::ffff:10.20.0.0/112"}},
	} {
		if !sameRanges(tc.got, tc.want) {
			t.Errorf("%s: sameRanges = false, want true", name)
		}
	}
}

// The signer's own status write must not wake it again; a spec change (a new CSR) must.
func TestSigner_IgnoresStatusOnlyIdentityUpdates(t *testing.T) {
	old := identity(t, "k02")
	statusOnly := old.DeepCopy()
	statusOnly.Status.Certificate = []byte("cert")
	if identitySpecChanged.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: statusOnly}) {
		t.Error("a status-only update must not re-trigger the signer")
	}
	newCSR := old.DeepCopy()
	newCSR.Spec.Request = []byte("another csr")
	if !identitySpecChanged.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: newCSR}) {
		t.Error("a new CSR must trigger the signer")
	}
}

// A certificate in status is the signer's only if the root signed it. Status is writable by more
// than the signer (and a root may be rotated), so a cert with the right key and constraint from any
// other issuer is replaced, not kept as "already signed".
func TestSigner_ResignsACertTheRootDidNotSign(t *testing.T) {
	id := identity(t, "k02")
	otherRoot, otherKey, _ := makeRoot(t)
	foreign, err := SignIntermediate(otherRoot, otherKey, id.Spec.Request, "k02", []string{poolPrefix}, time.Now().Add(intermediateTTL))
	if err != nil {
		t.Fatal(err)
	}
	id.Status.Certificate = foreign
	s, c := testSigner(t, clusterPool("k02", poolPrefix), id)
	got := signedCert(t, reconcileIdentity(t, s, c, "k02"))
	if err := got.CheckSignatureFrom(s.Root.Cert); err != nil {
		t.Fatalf("the cert left in status was not signed by the root: %v", err)
	}
}
