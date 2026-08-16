// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package routebusca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

func makeRoot(t *testing.T) (*x509.Certificate, crypto.Signer, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-routebus-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// makePoolCSR returns a PEM CSR for a pool intermediate plus the pool's private key.
func makePoolCSR(t *testing.T, cn string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

// mintLeaf signs a client leaf under the intermediate with the given DNS SAN.
func mintLeaf(t *testing.T, inter *x509.Certificate, interKey crypto.Signer, dnsSAN string) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsSAN},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{dnsSAN},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestSignIntermediate_IsConstrainedCA(t *testing.T) {
	root, rootKey, _ := makeRoot(t)
	csr, _ := makePoolCSR(t, "k02")

	interPEM, err := SignIntermediate(root, rootKey, csr, "k02", nil, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	block, _ := pem.Decode(interPEM)
	inter, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !inter.IsCA {
		t.Error("intermediate must be a CA")
	}
	if inter.MaxPathLen != 0 || !inter.MaxPathLenZero {
		t.Errorf("intermediate must be pathlen:0, got MaxPathLen=%d zero=%v", inter.MaxPathLen, inter.MaxPathLenZero)
	}
	if len(inter.PermittedDNSDomains) != 1 || inter.PermittedDNSDomains[0] != PoolDNSDomain("k02") {
		t.Errorf("intermediate name-constraint = %v, want [%s]", inter.PermittedDNSDomains, PoolDNSDomain("k02"))
	}
}

// TestNameConstraint_BlocksCrossPoolLeaf is the security test: a k02 intermediate may issue
// a k02-scoped node leaf that chains to root, but a leaf claiming a k03 identity is REJECTED
// by chain verification (Go enforces the intermediate's name constraints).
func TestNameConstraint_BlocksCrossPoolLeaf(t *testing.T) {
	root, rootKey, _ := makeRoot(t)
	csr, poolKey := makePoolCSR(t, "k02")
	interPEM, err := SignIntermediate(root, rootKey, csr, "k02", nil, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(interPEM)
	inter, _ := x509.ParseCertificate(block.Bytes)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	inters.AddCert(inter)
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}

	// In-pool leaf: chains + satisfies the constraint.
	good := mintLeaf(t, inter, poolKey, NodeDNSName("node1", "k02"))
	if _, err := good.Verify(opts); err != nil {
		t.Errorf("in-pool leaf should verify, got: %v", err)
	}
	// Cross-pool leaf: the k02 intermediate signed a k03-scoped SAN — must FAIL verification.
	evil := mintLeaf(t, inter, poolKey, NodeDNSName("node1", "k03"))
	if _, err := evil.Verify(opts); err == nil {
		t.Error("cross-pool leaf (k03 SAN under k02 intermediate) MUST be rejected by name constraints, but verified")
	}
}

// TestIPRangeConstraint_BlocksForeignUnderlaySAN proves the IP name-constraint stops a pool
// intermediate from minting a node leaf whose IP SAN is outside the pool's underlay — the
// cross-pool underlay-hijack boundary that backs the reflector's nexthop==SAN check.
func TestIPRangeConstraint_BlocksForeignUnderlaySAN(t *testing.T) {
	root, rootKey, _ := makeRoot(t)
	csr, poolKey := makePoolCSR(t, "k02")
	interPEM, err := SignIntermediate(root, rootKey, csr, "k02", []string{"fd00:cafe:1914::/48"}, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(interPEM)
	inter, _ := x509.ParseCertificate(block.Bytes)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	inters.AddCert(inter)
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}

	mintIP := func(node, ip string) *x509.Certificate {
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: node},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			DNSNames:     []string{NodeDNSName(node, "k02")},
			IPAddresses:  []net.IP{net.ParseIP(ip)},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, &leafKey.PublicKey, poolKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	if _, err := mintIP("node1", "fd00:cafe:1914::1").Verify(opts); err != nil {
		t.Errorf("in-range underlay SAN should verify: %v", err)
	}
	if _, err := mintIP("node1", "fd00:cafe:9999::1").Verify(opts); err == nil {
		t.Error("foreign-underlay IP SAN MUST be rejected by the intermediate's IP constraint, but verified")
	}
}

func TestLoadRootCA_RoundTrip(t *testing.T) {
	_, key, certPEM := makeRoot(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	certPath := dir + "/tls.crt"
	keyPath := dir + "/tls.key"
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := LoadRootCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if root == nil || !root.Cert.IsCA || root.Key == nil {
		t.Fatal("expected a loaded CA")
	}
	// Empty paths => inactive (nil, nil).
	r, err := LoadRootCA("", "")
	if err != nil || r != nil {
		t.Errorf("empty paths should be inactive, got %v %v", r, err)
	}
}

func TestSignIntermediate_RejectsGarbageCSR(t *testing.T) {
	root, rootKey, _ := makeRoot(t)
	if _, err := SignIntermediate(root, rootKey, []byte("not a csr"), "k02", nil, time.Now().Add(time.Hour)); err == nil {
		t.Error("expected error on non-PEM CSR")
	}
}
