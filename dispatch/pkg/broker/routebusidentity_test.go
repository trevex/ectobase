// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
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
