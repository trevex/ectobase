// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package routebus

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var nextSerial int64 = 1

func mint(t *testing.T, tmpl *x509.Certificate, parent *ca) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nextSerial++
	tmpl.SerialNumber = big.NewInt(nextSerial)
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
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

func caTmpl(cn string, permitted ...string) *x509.Certificate {
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	for _, p := range permitted {
		_, n, _ := net.ParseCIDR(p)
		tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, n)
	}
	return tmpl
}

func clientLeaf(cn string, ip string) *x509.Certificate {
	l := &x509.Certificate{Subject: pkix.Name{CommonName: cn}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	if ip != "" {
		l.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	return l
}

func newCA(t *testing.T, tmpl *x509.Certificate, parent *ca) *ca {
	c, k := mint(t, tmpl, parent)
	return &ca{c, k}
}

// handshake runs a real mutual-TLS handshake against the reflector's server config, with the
// client presenting leaf and its chain. It returns the server-side error.
func handshake(t *testing.T, root *ca, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, chain ...*x509.Certificate) error {
	t.Helper()
	srvCert, srvKey := mint(t, clientLeaf("reflector", "127.0.0.1"), root)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	cfg := serverConfig(tls.Certificate{Certificate: [][]byte{srvCert.Raw}, PrivateKey: srvKey}, pool)

	certChain := [][]byte{leaf.Raw}
	for _, c := range chain {
		certChain = append(certChain, c.Raw)
	}
	cli := &tls.Config{Certificates: []tls.Certificate{{Certificate: certChain, PrivateKey: leafKey}},
		RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}

	lis, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	srvErr := make(chan error, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer func() { _ = conn.Close() }()
		// The server verifies the client certificate inside its own handshake.
		srvErr <- conn.(*tls.Conn).Handshake()
	}()
	c, err := tls.Dial("tcp", lis.Addr().String(), cli)
	if err == nil {
		_ = c.Close()
	}
	return <-srvErr
}

// An intermediate signed before the signer required an IP constraint can mint a leaf for any VTEP,
// and it stays valid until it expires. The reflector refuses any chain through an intermediate with
// no permitted IP ranges, so the fix holds from the moment the reflector runs it.
func TestServerTLS_RefusesAnUnconstrainedIntermediate(t *testing.T) {
	root := newCA(t, caTmpl("ectobase-ca"), nil)
	old := newCA(t, caTmpl("routebus-intermediate-old"), root)
	leaf, key := mint(t, clientLeaf("k02-1", "fd00:cafe:9999::1"), old)
	err := handshake(t, root, leaf, key, old.cert)
	if err == nil || !strings.Contains(err.Error(), "no IP name constraint") {
		t.Fatalf("a chain through an unconstrained intermediate must be refused, got %v", err)
	}
}

func TestServerTLS_AcceptsAConstrainedIntermediate(t *testing.T) {
	root := newCA(t, caTmpl("ectobase-ca"), nil)
	inter := newCA(t, caTmpl("routebus-intermediate-k02", "fd00:cafe:1914::/48"), root)
	leaf, key := mint(t, clientLeaf("k02-1", "fd00:cafe:1914::1"), inter)
	if err := handshake(t, root, leaf, key, inter.cert); err != nil {
		t.Fatalf("a constrained pool chain must be accepted: %v", err)
	}
}

// A leaf the root issues directly (the dispatch-controller's) has no intermediate to check.
func TestServerTLS_AcceptsARootIssuedLeaf(t *testing.T) {
	root := newCA(t, caTmpl("ectobase-ca"), nil)
	leaf, key := mint(t, clientLeaf("dispatch-controller", ""), root)
	if err := handshake(t, root, leaf, key); err != nil {
		t.Fatalf("a root-issued leaf must be accepted: %v", err)
	}
}

func TestRequireIPConstrainedIntermediates(t *testing.T) {
	root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}}
	_, n, _ := net.ParseCIDR("fd00:cafe:1914::/48")
	good := &x509.Certificate{Subject: pkix.Name{CommonName: "good"}, PermittedIPRanges: []*net.IPNet{n}}
	bad := &x509.Certificate{Subject: pkix.Name{CommonName: "bad"}}
	for name, tc := range map[string]struct {
		chains [][]*x509.Certificate
		ok     bool
	}{
		"root-issued leaf":              {[][]*x509.Certificate{{leaf, root}}, true},
		"constrained intermediate":      {[][]*x509.Certificate{{leaf, good, root}}, true},
		"unconstrained intermediate":    {[][]*x509.Certificate{{leaf, bad, root}}, false},
		"any bad chain refuses":         {[][]*x509.Certificate{{leaf, good, root}, {leaf, bad, root}}, false},
		"no verified chain is not ours": {nil, true},
	} {
		if err := requireIPConstrainedIntermediates(nil, tc.chains); (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", name, err, tc.ok)
		}
	}
}
