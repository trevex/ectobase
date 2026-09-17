// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSignedPEM returns a throwaway CA certificate expiring in `ttl`. Only its NotAfter matters to
// the callers here.
func selfSignedPEM(t *testing.T, ttl time.Duration) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return selfSign(t, key, ttl)
}

// selfSignedFromKeyPEM returns a certificate for the PKCS#8 key in keyPEM, so a test can pair (or
// deliberately mispair) a certificate with a key.
func selfSignedFromKeyPEM(t *testing.T, keyPEM []byte) []byte {
	t.Helper()
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		t.Fatal("key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("key is %T, want ECDSA", k)
	}
	return selfSign(t, key, 90*24*time.Hour)
}

func selfSign(t *testing.T, key *ecdsa.PrivateKey, ttl time.Duration) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "routebus-intermediate-edge"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
