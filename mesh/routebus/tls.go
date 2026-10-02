// Package routebus holds route-bus transport helpers shared by the agent and
// reflector — currently mutual-TLS credential loading.
package routebus

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

func loadCAPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certs parsed from CA %q", caFile)
	}
	return pool, nil
}

// ServerTLS builds server credentials that REQUIRE and verify a client cert (mTLS).
func ServerTLS(caFile, certFile, keyFile string) (credentials.TransportCredentials, error) {
	if caFile == "" || certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("mTLS requires --tls-ca, --tls-cert and --tls-key")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(serverConfig(cert, pool)), nil
}

// serverConfig is ServerTLS's tls.Config: mutual TLS against pool, refusing any client chain
// through an intermediate without an IP name constraint.
func serverConfig(cert tls.Certificate, pool *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             pool,
		MinVersion:            tls.VersionTLS13,
		VerifyPeerCertificate: requireIPConstrainedIntermediates,
	}
}

// requireIPConstrainedIntermediates refuses a client whose verified chains pass through an
// intermediate CA with no permitted IP ranges. The reflector trusts a route's nexthop when it equals
// an IP SAN of the session's leaf, so an intermediate without an IP constraint could vouch for any
// VTEP. The dispatch signer no longer issues one, but one it signed earlier stays valid until it
// expires; refusing it here makes the rule hold at once. A leaf the root issues directly (the
// dispatch-controller's) has no intermediate and is unaffected. Every chain is checked, not just
// one: a chain the client could have used is a chain it can use.
func requireIPConstrainedIntermediates(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	for _, chain := range verifiedChains {
		if len(chain) < 3 {
			continue
		}
		for _, ca := range chain[1 : len(chain)-1] {
			if len(ca.PermittedIPRanges) == 0 {
				return fmt.Errorf("client chain passes through intermediate %q, which has no IP name constraint", ca.Subject.CommonName)
			}
		}
	}
	return nil
}

// ClientTLS builds client credentials that present a client cert and verify the server.
func ClientTLS(caFile, certFile, keyFile string) (credentials.TransportCredentials, error) {
	if caFile == "" || certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("mTLS requires --tls-ca, --tls-cert and --tls-key")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}), nil
}

// ClientTLSFromPEM builds client credentials from in-memory PEM (the agent obtains its per-node
// leaf from the k8s API, not a file). certPEM should be the full chain (leaf + intermediate) so
// the reflector can build leaf -> intermediate -> root; caPEM is the ROOT the agent trusts.
func ClientTLSFromPEM(caPEM, certPEM, keyPEM []byte) (credentials.TransportCredentials, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client keypair from PEM: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certs parsed from root CA PEM")
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}), nil
}
