// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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

// An identity with no ClusterPool (the WAN edge fleet) is operator-created; its own spec is the range.
func TestSigner_IdentityWithoutClusterPoolUsesItsSpec(t *testing.T) {
	s, c := testSigner(t, identity(t, "edge", "fd00:ffff::/32"))
	cert := signedCert(t, reconcileIdentity(t, s, c, "edge"))
	if r := ranges(cert); len(r) != 1 || r[0] != "fd00:ffff::/32" {
		t.Fatalf("PermittedIPRanges = %v, want [fd00:ffff::/32]", r)
	}
}

func TestSigner_IdentityWithoutClusterPoolOrCIDRsIsDenied(t *testing.T) {
	s, c := testSigner(t, identity(t, "edge"))
	requireDenied(t, reconcileIdentity(t, s, c, "edge"), "no spec.permittedUnderlayCIDRs")
}

// RBAC scopes a broker to the identity NAMED after its pool, but spec.poolName is a field the
// broker writes. Signing for a poolName other than the object's name would hand pool k02 the
// intermediate (DNS domain and underlay range) of k03, or of an identity with no ClusterPool.
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
