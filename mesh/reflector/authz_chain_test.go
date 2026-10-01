// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// testCA is a CA certificate with its key.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64 = 100

func issue(t *testing.T, tmpl *x509.Certificate, parent *testCA) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	signer, signerCert := key, tmpl
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func newRoot(t *testing.T) *testCA {
	c, k := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "ectobase-ca"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	return &testCA{c, k}
}

// newPoolIntermediate is a pool intermediate as the signer issues it: path length 0, DNS- and
// IP-constrained.
func newPoolIntermediate(t *testing.T, root *testCA, permitted string) *testCA {
	_, ipNet, _ := net.ParseCIDR(permitted)
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "routebus-intermediate-k02"}, IsCA: true,
		BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
		PermittedDNSDomains: []string{"k02.routebus.ectobase.dev"}}
	if ipNet != nil {
		tmpl.PermittedIPRanges = []*net.IPNet{ipNet}
	}
	c, k := issue(t, tmpl, root)
	return &testCA{c, k}
}

// verified runs leaf through the reflector's chain verification and returns the chains.
func verified(t *testing.T, root *testCA, leaf *x509.Certificate, inters ...*testCA) [][]*x509.Certificate {
	t.Helper()
	roots, ipool := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root.cert)
	for _, i := range inters {
		ipool.AddCert(i.cert)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: ipool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return chains
}

func chainCtx(chains [][]*x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: chains}},
	})
}

// The fence API is the dispatch-controller's, whose certificate the root ClusterIssuer issues
// directly. Every pool holds an intermediate under the same root and can mint a leaf with any CN
// inside its DNS constraint, CN included (a CN is not a SAN); the CN alone therefore names
// nobody. Only a leaf the root itself issued may fence.
func TestRequireClientCN_OnlyARootIssuedLeafMayFence(t *testing.T) {
	root := newRoot(t)
	inter := newPoolIntermediate(t, root, "fd00:cafe:1914::/48")
	leafTmpl := func() *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: "dispatch-controller"},
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	}
	direct, _ := issue(t, leafTmpl(), root)
	forged, _ := issue(t, leafTmpl(), inter)

	h := func(context.Context, any) (any, error) { return "ok", nil }
	gate := RequireClientCN("dispatch-controller")
	if _, err := gate(chainCtx(verified(t, root, direct)), nil, &grpc.UnaryServerInfo{}, h); err != nil {
		t.Fatalf("the root-issued dispatch-controller leaf must be allowed to fence: %v", err)
	}
	_, err := gate(chainCtx(verified(t, root, forged, inter)), nil, &grpc.UnaryServerInfo{}, h)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a CN=dispatch-controller leaf from a pool intermediate must be refused, got %v", err)
	}
}
