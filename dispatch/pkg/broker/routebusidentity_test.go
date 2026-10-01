// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// selfSignedFor builds a cert whose public key is keyPEM's public half.
func selfSignedFor(t *testing.T, keyPEM []byte, notAfter time.Time) []byte {
	t.Helper()
	kb, _ := pem.Decode(keyPEM)
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := k.(*ecdsa.PrivateKey)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "x"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestGenerateIntermediateKeyAndCSR(t *testing.T) {
	keyPEM, csrPEM, err := GenerateIntermediateKeyAndCSR("k02")
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := pem.Decode(csrPEM)
	if cb == nil || cb.Type != "CERTIFICATE REQUEST" {
		t.Fatal("csr is not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR self-signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "routebus-intermediate-k02" {
		t.Errorf("CSR CN = %q", csr.Subject.CommonName)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		t.Fatal("key is not a PEM PRIVATE KEY (PKCS#8)")
	}
}

func TestCertMatchesKey(t *testing.T) {
	keyPEM, _, _ := GenerateIntermediateKeyAndCSR("k02")
	otherKeyPEM, _, _ := GenerateIntermediateKeyAndCSR("k02")

	cert := selfSignedFor(t, keyPEM, time.Now().Add(time.Hour))
	if !certMatchesKey(cert, keyPEM) {
		t.Error("cert should match its own key")
	}
	if certMatchesKey(cert, otherKeyPEM) {
		t.Error("cert should NOT match a different key")
	}
	if certMatchesKey(nil, keyPEM) {
		t.Error("nil cert should not match")
	}
}

func TestCertNeedsRenewal(t *testing.T) {
	keyPEM, _, _ := GenerateIntermediateKeyAndCSR("k02")
	now := time.Now()
	renew := 30 * 24 * time.Hour

	if !certNeedsRenewal(nil, renew, now) {
		t.Error("empty cert needs renewal")
	}
	if !certNeedsRenewal([]byte("garbage"), renew, now) {
		t.Error("garbage cert needs renewal")
	}
	fresh := selfSignedFor(t, keyPEM, now.Add(90*24*time.Hour))
	if certNeedsRenewal(fresh, renew, now) {
		t.Error("cert with 90d left should NOT need renewal (30d window)")
	}
	soon := selfSignedFor(t, keyPEM, now.Add(10*24*time.Hour))
	if !certNeedsRenewal(soon, renew, now) {
		t.Error("cert with 10d left SHOULD need renewal (30d window)")
	}
}

// adoptFixture is a bootstrapper whose pool Secret holds a fresh intermediate (oldCert) for key,
// and whose RouteBusIdentity status carries statusCert.
func adoptFixture(t *testing.T, keyPEM, oldCert, statusCert []byte) (*PoolCertBootstrapper, client.Client) {
	t.Helper()
	s := runtime.NewScheme()
	if err := platformv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	id := &platformv1.RouteBusIdentity{ObjectMeta: metav1.ObjectMeta{Name: "k02"},
		Spec:   platformv1.RouteBusIdentitySpec{PoolName: "k02"},
		Status: platformv1.RouteBusIdentityStatus{Certificate: statusCert, CABundle: []byte("root")}}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ectobase-system", Name: "pool-ca"},
		Data: map[string][]byte{"tls.crt": oldCert, "tls.key": keyPEM, "ca.crt": []byte("root")}}
	dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(id).WithStatusSubresource(id).Build()
	downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(sec).Build()
	return &PoolCertBootstrapper{Dispatch: dispatch, Downstream: downstream, PoolName: "k02",
		SecretName: "pool-ca", SecretNS: "ectobase-system"}, downstream
}

func secretCert(t *testing.T, c client.Client) []byte {
	t.Helper()
	var sec corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ectobase-system", Name: "pool-ca"}, &sec); err != nil {
		t.Fatal(err)
	}
	return sec.Data["tls.crt"]
}

// The signer re-signs an intermediate whose IP constraint no longer matches the rule, for the same
// key. The pool must pick that up while its old intermediate is still fresh, not months later at
// renewal, or the re-sign changes nothing the route bus sees.
func TestEnsure_AdoptsAReSignedIntermediateForTheCurrentKey(t *testing.T) {
	keyPEM, _, _ := GenerateIntermediateKeyAndCSR("k02")
	oldCert := selfSignedFor(t, keyPEM, time.Now().Add(80*24*time.Hour))
	resigned := selfSignedFor(t, keyPEM, time.Now().Add(90*24*time.Hour))
	b, downstream := adoptFixture(t, keyPEM, oldCert, resigned)
	if err := b.EnsureOnce(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if !bytes.Equal(secretCert(t, downstream), resigned) {
		t.Fatal("the re-signed intermediate was not adopted into the pool Secret")
	}
}

// A status cert for some other key (a CSR in flight, or garbage) never replaces the Secret's.
func TestEnsure_IgnoresAStatusCertForAnotherKey(t *testing.T) {
	keyPEM, _, _ := GenerateIntermediateKeyAndCSR("k02")
	otherKey, _, _ := GenerateIntermediateKeyAndCSR("k02")
	oldCert := selfSignedFor(t, keyPEM, time.Now().Add(80*24*time.Hour))
	b, downstream := adoptFixture(t, keyPEM, oldCert, selfSignedFor(t, otherKey, time.Now().Add(90*24*time.Hour)))
	if err := b.EnsureOnce(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if !bytes.Equal(secretCert(t, downstream), oldCert) {
		t.Fatal("a status cert for another key replaced the pool's intermediate")
	}
}
