// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trevex/ectobase/dispatch/pkg/broker"
	"github.com/trevex/ectobase/dispatch/pkg/pki"
	"github.com/trevex/ectobase/mesh/routebus"
)

// The WAN edge's route-bus identity, end to end across the two halves that have to agree: the
// DISPATCH signs the edge fleet an ordinary name-constrained intermediate (pki.SignIntermediate —
// no new CRD, no new kind, no signer change: the edge is modelled as a RouteBusIdentity named
// `edge` whose permittedUnderlayCIDRs is the edge loopback aggregate), and each EDGE mints its own
// leaf from it locally (routebus.MintEdgeLeaf), with no cert-manager and no API server.
//
// These live in the dispatch module because it is the only one that can import both.

// loopAggr is the edge loopback aggregate (test/lab/internal/fabric.LoopAggr). Edge underlays live
// here, outside every pool's fd00:cafe:<h>::/48 by construction.
const loopAggr = "fd00:ffff::/32"

// edgeFleetPKI signs an edge intermediate the way the dispatch signer does and writes the resulting
// ca.crt/tls.crt/tls.key trio into a directory, as an edge's provisioner would. It returns the dir
// and the root, so callers can verify a minted leaf the way the reflector does.
func edgeFleetPKI(t *testing.T, permittedCIDRs []string) (dir string, root *x509.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ectobase-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	// Exactly what the broker does for a pool, for the fleet named "edge".
	keyPEM, csrPEM, err := broker.GenerateIntermediateKeyAndCSR("edge")
	if err != nil {
		t.Fatal(err)
	}
	// Exactly what the dispatch signer does with that CSR.
	interPEM, err := pki.SignIntermediate(root, rootKey, csrPEM, "edge", permittedCIDRs, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	dir = t.TempDir()
	for name, content := range map[string][]byte{"ca.crt": rootPEM, "tls.crt": interPEM, "tls.key": keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, root
}

// verifyLikeReflector runs the chain through the same check the reflector's TLS stack does: leaf ->
// intermediate -> root, anchored on the root alone, with the intermediate's name constraints
// enforced. It returns the verified leaf.
func verifyLikeReflector(t *testing.T, chainPEM []byte, root *x509.Certificate) (*x509.Certificate, error) {
	t.Helper()
	var certs []*x509.Certificate
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse chain element: %v", err)
		}
		certs = append(certs, c)
	}
	if len(certs) != 2 {
		t.Fatalf("want chain of leaf+intermediate, got %d certs", len(certs))
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(certs[1])
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return certs[0], err
}

func TestEdgeLeafMintsAndVerifiesUnderTheFleetIntermediate(t *testing.T) {
	dir, root := edgeFleetPKI(t, []string{loopAggr})

	// An edge announces for BOTH its datapath underlay and its control loopback: the reflector's
	// guard matches the EXACT cert SAN, and the EDGE_UNDERLAY record pairs the two.
	chainPEM, keyPEM, notAfter, err := routebus.MintEdgeLeaf(routebus.EdgeIdentity{
		Dir: dir, Node: "edge1", IPSANs: []string{"fd00:ffff::e1", "fd00:ffff::1e"},
	})
	if err != nil {
		t.Fatalf("MintEdgeLeaf: %v", err)
	}
	if len(keyPEM) == 0 {
		t.Fatal("no private key returned")
	}
	if notAfter.After(time.Now().Add(90 * 24 * time.Hour)) {
		t.Errorf("leaf outlives its intermediate: notAfter=%s", notAfter)
	}

	leaf, err := verifyLikeReflector(t, chainPEM, root)
	if err != nil {
		t.Fatalf("the reflector would reject this leaf: %v", err)
	}
	if leaf.Subject.CommonName != "edge1" {
		t.Errorf("CN = %q, want edge1", leaf.Subject.CommonName)
	}
	if len(leaf.IPAddresses) != 2 {
		t.Fatalf("want both IP SANs on the leaf, got %v", leaf.IPAddresses)
	}
	for _, want := range []string{"fd00:ffff::e1", "fd00:ffff::1e"} {
		var found bool
		for _, ip := range leaf.IPAddresses {
			if ip.String() == want {
				found = true
			}
		}
		if !found {
			t.Errorf("IP SAN %s missing from the leaf: %v", want, leaf.IPAddresses)
		}
	}
}

// The security property the whole arrangement rests on. Local minting moves a signing operation
// into the agent, so what stops a compromised edge from issuing itself a pool node's VTEP is NOT
// the minting code — it is the intermediate's IP name constraint, enforced by the verifier.
func TestEdgeLeafOutsideTheEdgeAggregateIsRejected(t *testing.T) {
	dir, root := edgeFleetPKI(t, []string{loopAggr})

	// A pool node's underlay (fd00:cafe::/32), which this intermediate must not be able to speak for.
	chainPEM, _, _, err := routebus.MintEdgeLeaf(routebus.EdgeIdentity{
		Dir: dir, Node: "edge1", IPSANs: []string{"fd00:cafe:1914::1"},
	})
	if err != nil {
		t.Fatalf("MintEdgeLeaf: %v", err) // signing succeeds locally; verification is what must fail
	}

	if _, err := verifyLikeReflector(t, chainPEM, root); err == nil {
		t.Fatal("a leaf with an IP SAN outside the edge aggregate must fail verification")
	} else if !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("want a name-constraint rejection, got: %v", err)
	}
}

// A mis-provisioned directory must fail where it is diagnosable, not as an opaque handshake error.
func TestEdgeLeafRejectsMismatchedIntermediateKey(t *testing.T) {
	dir, _ := edgeFleetPKI(t, []string{loopAggr})

	// Overwrite the key with a fresh, unrelated one.
	otherKeyPEM, _, err := broker.GenerateIntermediateKeyAndCSR("edge")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), otherKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, _, err = routebus.MintEdgeLeaf(routebus.EdgeIdentity{Dir: dir, Node: "edge1", IPSANs: []string{"fd00:ffff::e1"}})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want a key/cert mismatch error, got: %v", err)
	}
}
