// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package routebus

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
)

// The edge's route-bus identity.
//
// A WAN edge is a router, not a Kubernetes node: it has no API server and no cert-manager, so it
// cannot take the pool's path (ProvisionNodeCert, which creates a Certificate object and waits for
// the Secret). Instead the EDGE FLEET holds one ordinary route-bus intermediate — requested exactly
// like a pool's, as a RouteBusIdentity named `edge` with permittedUnderlayCIDRs set to the edge
// loopback aggregate — and each edge mints its OWN leaf from it, in process. That is nodecert.go's
// idea with the cert-manager round-trip replaced by local signing, which is what keeps the edge
// API-less in steady state.
//
// What bounds this is the intermediate's IP name constraint, not the minting code: Go's chain
// verification on the reflector rejects a leaf whose IP SAN falls outside the edge aggregate, so a
// compromised edge cannot forge a pool node's VTEP. The reflector's own announce guard then binds
// every nexthop/owner the session speaks for to exactly one of these SANs.
//
// Like the pool's node leaves, an edge leaf carries IP SANs and no DNS SAN. Name constraints are
// checked per SAN type, so the intermediate's DNS constraint simply does not apply.

const (
	// edgeCARootFile / edgeCACertFile / edgeCAKeyFile are the three files the edge's PKI directory
	// holds. The layout is deliberately the pool CA Secret's (ca.crt/tls.crt/tls.key), so whatever
	// provisions an edge in production can write out that Secret verbatim.
	edgeCARootFile = "ca.crt"  // the ROOT the reflector is verified against
	edgeCACertFile = "tls.crt" // the edge fleet's intermediate CA
	edgeCAKeyFile  = "tls.key" // its private key

	// edgeLeafTTL is how long a self-minted edge leaf is valid, and edgeLeafRenewBefore how close to
	// expiry a new handshake re-mints. Minting is local and free, so this is short by design.
	edgeLeafTTL         = 7 * 24 * time.Hour
	edgeLeafRenewBefore = 24 * time.Hour
)

// EdgeIdentity is one edge's route-bus credential source: the fleet PKI directory plus the identity
// this edge is entitled to speak for.
type EdgeIdentity struct {
	// Dir holds ca.crt / tls.crt / tls.key (see the edgeCA*File constants).
	Dir string
	// Node is the leaf's CommonName (the edge's node id).
	Node string
	// IPSANs are the addresses this edge announces for. BOTH the datapath underlay and the control
	// loopback belong here: the reflector authorizes an announce against the EXACT cert SAN, and the
	// EDGE_UNDERLAY record pairs the two, so a leaf carrying only one of them cannot announce it.
	// (In the lab they are the same address, so this collapses to a single SAN.)
	IPSANs []string
}

// WaitForMaterial blocks until every file of the edge PKI directory is present, or ctx ends. An
// edge is provisioned out of band — in the lab the harness writes the fleet intermediate during the
// substrate deploy, after the containers already exist — so at first boot the directory is normally
// empty for a while. Waiting (loudly) is the honest behaviour: an edge without credentials cannot
// join the route bus, and the operator should see exactly which file is missing.
func (e EdgeIdentity) WaitForMaterial(ctx context.Context) error {
	const poll = 3 * time.Second
	logEvery, last := 30*time.Second, time.Time{}
	for {
		missing, err := e.missingFiles()
		if err != nil {
			return err
		}
		if len(missing) == 0 {
			return nil
		}
		if time.Since(last) >= logEvery {
			log.Printf("waiting for edge route-bus material in %s: missing %v", e.Dir, missing)
			last = time.Now()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func (e EdgeIdentity) missingFiles() ([]string, error) {
	var missing []string
	for _, f := range []string{edgeCARootFile, edgeCACertFile, edgeCAKeyFile} {
		st, err := os.Stat(filepath.Join(e.Dir, f))
		switch {
		case os.IsNotExist(err):
			missing = append(missing, f)
		case err != nil:
			return nil, fmt.Errorf("stat %s: %w", filepath.Join(e.Dir, f), err)
		case st.Size() == 0:
			missing = append(missing, f) // present but not written yet
		}
	}
	return missing, nil
}

// ClientTLS builds route-bus client credentials that present a locally-minted leaf and verify the
// reflector against the fleet root. The leaf is minted lazily per handshake and cached until it
// nears expiry, so a long-lived edge rotates on reconnect without a restart — and re-reads the
// intermediate from disk each time, so an externally rotated intermediate is picked up too.
func (e EdgeIdentity) ClientTLS() (credentials.TransportCredentials, error) {
	rootPEM, err := os.ReadFile(filepath.Join(e.Dir, edgeCARootFile))
	if err != nil {
		return nil, fmt.Errorf("read edge root CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("no certs parsed from edge root CA %s", filepath.Join(e.Dir, edgeCARootFile))
	}
	m := &edgeMinter{id: e}
	// Mint once up front so a misconfigured identity fails at startup with a clear error rather than
	// silently, inside a handshake, as an opaque connection failure.
	if _, err := m.certificate(); err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return m.certificate()
		},
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}), nil
}

// edgeMinter caches this edge's current leaf and re-mints it as it nears expiry.
type edgeMinter struct {
	id EdgeIdentity

	mu       sync.Mutex
	cur      *tls.Certificate
	notAfter time.Time
}

func (m *edgeMinter) certificate() (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur != nil && time.Until(m.notAfter) > edgeLeafRenewBefore {
		return m.cur, nil
	}
	chainPEM, keyPEM, notAfter, err := MintEdgeLeaf(m.id)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load minted edge leaf: %w", err)
	}
	m.cur, m.notAfter = &cert, notAfter
	// Report the SANs actually on the leaf, not the requested list: the reflector authorizes each
	// announce against an EXACT SAN, so this line is what you check when one is rejected. (They
	// differ whenever the underlay and the loopback are the same address, as in the lab, since
	// MintEdgeLeaf dedupes.)
	log.Printf("minted edge route-bus leaf cn=%s sans=%v notAfter=%s",
		m.id.Node, leafSANs(&cert), notAfter.Format(time.RFC3339))
	return m.cur, nil
}

// leafSANs returns the IP SANs on a parsed keypair's leaf, for logging.
func leafSANs(cert *tls.Certificate) []string {
	if cert.Leaf == nil {
		if len(cert.Certificate) == 0 {
			return nil
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil
		}
		cert.Leaf = parsed
	}
	out := make([]string, 0, len(cert.Leaf.IPAddresses))
	for _, ip := range cert.Leaf.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// MintEdgeLeaf signs a fresh client leaf for this edge from the fleet intermediate on disk. It
// returns the CHAIN (leaf + intermediate) so the root-anchored reflector can build the path, the
// leaf's private key, and the leaf's expiry. The key is generated here and never leaves the edge.
func MintEdgeLeaf(id EdgeIdentity) (chainPEM, keyPEM []byte, notAfter time.Time, err error) {
	caCertPEM, err := os.ReadFile(filepath.Join(id.Dir, edgeCACertFile))
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("read edge intermediate: %w", err)
	}
	caKeyPEM, err := os.ReadFile(filepath.Join(id.Dir, edgeCAKeyFile))
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("read edge intermediate key: %w", err)
	}
	caCert, caKey, err := parseEdgeCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, time.Time{}, err
	}

	ips := make([]net.IP, 0, len(id.IPSANs))
	seen := map[string]bool{}
	for _, s := range id.IPSANs {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, nil, time.Time{}, fmt.Errorf("edge IP SAN %q is not an IP address", s)
		}
		if k := ip.String(); !seen[k] { // the underlay and the loopback are the same address in the lab
			seen[k] = true
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, nil, time.Time{}, fmt.Errorf("edge leaf needs at least one IP SAN")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("generate edge leaf key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("serial: %w", err)
	}
	// Never outlive the issuer: a leaf valid past its intermediate is a chain that fails verification
	// anyway, and pretending otherwise just moves the failure to a confusing place.
	notAfter = time.Now().Add(edgeLeafTTL)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: id.Node},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("sign edge leaf: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("marshal edge leaf key: %w", err)
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chainPEM = append(append([]byte{}, leafPEM...), caCertPEM...)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return chainPEM, keyPEM, notAfter, nil
}

// parseEdgeCA decodes the intermediate cert + key and checks it can actually issue leaves, so a
// mis-provisioned directory (e.g. the ROOT copied into tls.crt, or a mismatched key) fails here
// with a clear message instead of as a chain-verification failure on the reflector.
func parseEdgeCA(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, fmt.Errorf("edge intermediate is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse edge intermediate: %w", err)
	}
	if !cert.IsCA {
		return nil, nil, fmt.Errorf("edge intermediate %q is not a CA", cert.Subject.CommonName)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("edge intermediate key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse edge intermediate key: %w", err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("edge intermediate key is %T, want an ECDSA key", key)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&ec.PublicKey) {
		return nil, nil, fmt.Errorf("edge intermediate key does not match its certificate")
	}
	return cert, ec, nil
}
