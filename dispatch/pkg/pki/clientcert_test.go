// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// The dispatch apiserver authenticates a broker by its client certificate: the CN becomes the
// username and each O a group, and O=system:masters bypasses authorization entirely. So the signer
// takes only the public key from a broker's CSR and writes everything else itself.

// clientCSR is a PEM CSR with whatever subject, SANs and extension requests the requester likes.
func clientCSR(t *testing.T, tmpl *x509.CertificateRequest) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

// hostileCSR asks for cluster-admin: O=system:masters, another pool's CN, SANs, and CA basic
// constraints, all of which the signer must ignore.
func hostileCSR(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	bc, err := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{true})
	if err != nil {
		t.Fatal(err)
	}
	return clientCSR(t, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "ectobase:cluster:k03", Organization: []string{"system:masters"}, OrganizationalUnit: []string{"x"}},
		DNSNames:    []string{"kubernetes.default"},
		IPAddresses: []net.IP{net.ParseIP("fd00:cafe:2a3b::1")},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bc}, // basicConstraints CA:TRUE
		},
	})
}

func parsePEMCert(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatal("no PEM certificate")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// requireBrokerCert checks every property a dispatch client certificate must have.
func requireBrokerCert(t *testing.T, c *x509.Certificate, pool string) {
	t.Helper()
	if c.Subject.CommonName != "ectobase:cluster:"+pool {
		t.Errorf("CN = %q, want ectobase:cluster:%s", c.Subject.CommonName, pool)
	}
	if !slices.Equal(c.Subject.Organization, []string{"ectobase:brokers"}) {
		t.Errorf("O = %v, want [ectobase:brokers]", c.Subject.Organization)
	}
	if len(c.Subject.OrganizationalUnit) != 0 || len(c.Subject.Names) != 2 {
		t.Errorf("subject carries more than CN and O: %v", c.Subject.Names)
	}
	if !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || len(c.UnknownExtKeyUsage) != 0 {
		t.Errorf("ExtKeyUsage = %v, want clientAuth only", c.ExtKeyUsage)
	}
	if c.IsCA || !c.BasicConstraintsValid {
		t.Errorf("IsCA=%v BasicConstraintsValid=%v, want a non-CA with explicit basic constraints", c.IsCA, c.BasicConstraintsValid)
	}
	if len(c.DNSNames)+len(c.IPAddresses)+len(c.URIs)+len(c.EmailAddresses) != 0 {
		t.Errorf("SANs present: dns=%v ip=%v uri=%v email=%v", c.DNSNames, c.IPAddresses, c.URIs, c.EmailAddresses)
	}
	if life := c.NotAfter.Sub(c.NotBefore); life < clientCertTTL || life > clientCertTTL+10*time.Minute {
		t.Errorf("lifetime %v, want %v", life, clientCertTTL)
	}
}

func TestSignClientCert_IgnoresEverythingButTheKey(t *testing.T) {
	ca, caKey, _ := makeRoot(t)
	csr, key := hostileCSR(t)
	certPEM, err := SignClientCert(ca, caKey, csr, "k02", time.Now().Add(clientCertTTL))
	if err != nil {
		t.Fatal(err)
	}
	c := parsePEMCert(t, certPEM)
	requireBrokerCert(t, c, "k02")
	if !publicKeysEqual(c.PublicKey, &key.PublicKey) {
		t.Error("the certificate is not for the CSR's key")
	}
	if err := c.CheckSignatureFrom(ca); err != nil {
		t.Errorf("not signed by the client CA: %v", err)
	}
}

func TestSignClientCert_RejectsABadCSR(t *testing.T) {
	ca, caKey, _ := makeRoot(t)
	if _, err := SignClientCert(ca, caKey, []byte("garbage"), "k02", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("a non-PEM CSR must be refused")
	}
}

// withClientCA gives s a dispatch client CA distinct from its route-bus root.
func withClientCA(t *testing.T, s *Signer) *Signer {
	t.Helper()
	c, k, p := makeRoot(t)
	s.ClientCA = &RootCA{Cert: c, Key: k, PEM: p}
	return s
}

func clientIdentity(t *testing.T, name string, csr []byte) *platformv1.RouteBusIdentity {
	id := identity(t, name)
	id.Spec.ClientRequest = csr
	return id
}

func clientCondition(id *platformv1.RouteBusIdentity) *metav1.Condition {
	return meta.FindStatusCondition(id.Status.Conditions, ConditionClientSigned)
}

func requireClientDenied(t *testing.T, id *platformv1.RouteBusIdentity, contains string) {
	t.Helper()
	c := clientCondition(id)
	if c == nil || c.Status != metav1.ConditionFalse || !strings.Contains(c.Message, contains) {
		t.Fatalf("want %s=False mentioning %q, got %+v", ConditionClientSigned, contains, c)
	}
	if len(id.Status.ClientCertificate) != 0 {
		t.Fatal("a denied client request must carry no client certificate")
	}
}

// A pool's broker gets a client certificate from the client CA, never from the route-bus root, with
// its subject forced however the CSR is dressed up.
func TestSigner_PoolClientCertIsForcedAndFromTheClientCA(t *testing.T) {
	csr, key := hostileCSR(t)
	s, c := testSigner(t, clusterPool("k02", poolPrefix), clientIdentity(t, "k02", csr))
	withClientCA(t, s)
	got := reconcileIdentity(t, s, c, "k02")
	if cond := clientCondition(got); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("want %s=True, got %+v", ConditionClientSigned, cond)
	}
	cert := parsePEMCert(t, got.Status.ClientCertificate)
	requireBrokerCert(t, cert, "k02")
	if !publicKeysEqual(cert.PublicKey, &key.PublicKey) {
		t.Error("client certificate is not for the CSR's key")
	}
	if err := cert.CheckSignatureFrom(s.ClientCA.Cert); err != nil {
		t.Errorf("client certificate not signed by the client CA: %v", err)
	}
	if cert.CheckSignatureFrom(s.Root.Cert) == nil {
		t.Error("client certificate signed by the route-bus root, which pool intermediates chain to")
	}
}

// The broker's credential does not depend on its route-bus intermediate: a pool still denied an
// intermediate (no underlayPrefix yet), or one that has not filed that CSR, can reach the dispatch.
func TestSigner_ClientCertDoesNotWaitForTheIntermediate(t *testing.T) {
	csr, _ := clientCSR(t, &x509.CertificateRequest{})
	id := clientIdentity(t, "k02", csr)
	id.Spec.Request = nil
	s, c := testSigner(t, clusterPool("k02", ""), id)
	withClientCA(t, s)
	got := reconcileIdentity(t, s, c, "k02")
	if cond := clientCondition(got); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("want %s=True without an intermediate, got %+v", ConditionClientSigned, cond)
	}
	if meta.IsStatusConditionTrue(got.Status.Conditions, "Signed") {
		t.Fatal("no intermediate was requested")
	}
}

// A fleet identity (the edge) is not a broker and never talks to the dispatch apiserver.
func TestSigner_FleetIdentityGetsNoClientCert(t *testing.T) {
	csr, _ := clientCSR(t, &x509.CertificateRequest{})
	id := clientIdentity(t, "edge", csr)
	id.Spec.PermittedUnderlayCIDRs = []string{"fd00:ffff::/32"}
	s, c := testSigner(t, id)
	s.FleetIdentities = []string{"edge"}
	withClientCA(t, s)
	got := reconcileIdentity(t, s, c, "edge")
	requireClientDenied(t, got, "fleet identity")
	signedCert(t, got) // its intermediate is unaffected
}

func TestSigner_ClientCertNeedsAClusterPool(t *testing.T) {
	csr, _ := clientCSR(t, &x509.CertificateRequest{})
	s, c := testSigner(t, clientIdentity(t, "k02", csr))
	withClientCA(t, s)
	requireClientDenied(t, reconcileIdentity(t, s, c, "k02"), "no ClusterPool k02")
}

func TestSigner_ClientCertNeedsTheClientCA(t *testing.T) {
	csr, _ := clientCSR(t, &x509.CertificateRequest{})
	s, c := testSigner(t, clusterPool("k02", poolPrefix), clientIdentity(t, "k02", csr))
	requireClientDenied(t, reconcileIdentity(t, s, c, "k02"), "client CA")
}

func TestSigner_ClientCertNameMustMatch(t *testing.T) {
	csr, _ := clientCSR(t, &x509.CertificateRequest{})
	id := clientIdentity(t, "k02", csr)
	id.Spec.PoolName = "k03"
	s, c := testSigner(t, clusterPool("k02", poolPrefix), clusterPool("k03", "fd00:cafe:2a3b::/48"), id)
	withClientCA(t, s)
	requireClientDenied(t, reconcileIdentity(t, s, c, "k02"), "must equal")
}

// A new key (the broker rotated) is re-signed; the same key is left alone.
func TestSigner_ClientCertReSignedOnKeyChangeOnly(t *testing.T) {
	csr, _ := clientCSR(t, &x509.CertificateRequest{})
	s, c := testSigner(t, clusterPool("k02", poolPrefix), clientIdentity(t, "k02", csr))
	withClientCA(t, s)
	first := reconcileIdentity(t, s, c, "k02").Status.ClientCertificate
	if again := reconcileIdentity(t, s, c, "k02").Status.ClientCertificate; string(again) != string(first) {
		t.Fatal("a fresh client certificate for the same key was re-signed")
	}

	csr2, key2 := clientCSR(t, &x509.CertificateRequest{})
	var id platformv1.RouteBusIdentity
	if err := c.Get(t.Context(), client.ObjectKey{Name: "k02"}, &id); err != nil {
		t.Fatal(err)
	}
	id.Spec.ClientRequest = csr2
	if err := c.Update(t.Context(), &id); err != nil {
		t.Fatal(err)
	}
	cert := parsePEMCert(t, reconcileIdentity(t, s, c, "k02").Status.ClientCertificate)
	if !publicKeysEqual(cert.PublicKey, &key2.PublicKey) {
		t.Fatal("the client certificate was not re-signed for the broker's new key")
	}
}

// A certificate in status counts only if the client CA signed it: one from the route-bus root (what
// a pool intermediate chains to) or any other issuer is replaced.
func TestSigner_ClientCertFromTheWrongCAIsReplaced(t *testing.T) {
	csr, _ := clientCSR(t, &x509.CertificateRequest{})
	id := clientIdentity(t, "k02", csr)
	s, c := testSigner(t, clusterPool("k02", poolPrefix), id)
	withClientCA(t, s)
	wrong, err := SignClientCert(s.Root.Cert, s.Root.Key, csr, "k02", time.Now().Add(clientCertTTL))
	if err != nil {
		t.Fatal(err)
	}
	var cur platformv1.RouteBusIdentity
	if err := c.Get(t.Context(), client.ObjectKey{Name: "k02"}, &cur); err != nil {
		t.Fatal(err)
	}
	cur.Status.ClientCertificate = wrong
	if err := c.Status().Update(t.Context(), &cur); err != nil {
		t.Fatal(err)
	}
	cert := parsePEMCert(t, reconcileIdentity(t, s, c, "k02").Status.ClientCertificate)
	if err := cert.CheckSignatureFrom(s.ClientCA.Cert); err != nil {
		t.Fatalf("a certificate from the wrong CA was kept: %v", err)
	}
}
