// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/wait"
)

// The WAN edge fleet's route-bus identity.
//
// An edge is a router, not a Kubernetes node: it runs no pool chart, has no ServiceAccount and no
// cert-manager, so it cannot take the per-node path. Instead the whole edge FLEET gets one ordinary
// route-bus intermediate — an ordinary RouteBusIdentity named `edge`, name-constrained to the edge
// loopback aggregate, signed by the same dispatch signer that serves every pool. No new CRD, no new
// kind, no signer change. Each edge agent then mints its OWN leaf from it in-process.
//
// This mirrors the pool's PoolCertBootstrapper one level down, with the roles moved: there the
// pool's broker generates the keypair and submits the CSR; here the lab HARNESS does it, standing in
// for whatever provisions an edge in production. Either way the key is generated where it will be
// used and only the CSR travels.
//
// It is written with stdlib crypto plus kubectl rather than by importing dispatch/pkg/broker,
// because test/lab deliberately depends on no ectobase module — pulling the dispatch tree in for
// two dozen lines of key generation would be a poor trade.

const (
	// edgeIdentityName is the RouteBusIdentity (and pool name) for the whole edge fleet.
	edgeIdentityName = "edge"
	// edgeIntermediateRenewBefore is how close to expiry the local material is re-requested. The
	// signer issues 90d intermediates, so this re-mints in the last third of their life.
	edgeIntermediateRenewBefore = 30 * 24 * time.Hour
)

// provisionEdgeIdentity makes sure the edge fleet's route-bus CA exists on disk at
// s.EdgePKIDir: it generates the intermediate keypair locally, submits the CSR as the `edge`
// RouteBusIdentity, waits for the dispatch signer, and writes {ca.crt, tls.crt, tls.key}. The
// edge agent containers bind that directory read-only and mint their own leaves from it.
//
// Idempotent: a still-fresh local trio is left alone, so a re-run of `lab deploy` does not
// needlessly rotate the fleet CA out from under running edges.
func provisionEdgeIdentity(ctx context.Context, s EctobaseSpec) error {
	// The CURRENT dispatch root is part of the freshness test, not just a thing to write out: a
	// reinstalled dispatch mints a new root, and material chaining to the old one would leave every
	// edge silently unable to authenticate — with three perfectly valid-looking files on disk.
	_, rootPEM, err := dispatchRootCA(ctx, s.DispatchKubeconfig)
	if err != nil {
		return err
	}
	if fresh, ferr := edgeMaterialFresh(s.EdgePKIDir, rootPEM); ferr != nil {
		return ferr
	} else if fresh {
		slog.Info("edge route-bus CA already provisioned", "dir", s.EdgePKIDir)
		return nil
	}

	slog.Info("provisioning the WAN edge fleet route-bus CA", "identity", edgeIdentityName, "permitted", s.EdgeUnderlayCIDRs)
	keyPEM, csrPEM, err := generateIntermediateKeyAndCSR(edgeIdentityName)
	if err != nil {
		return err
	}
	if err := kubectlApplyStdin(ctx, s.DispatchKubeconfig, edgeIdentityManifest(csrPEM, s.EdgeUnderlayCIDRs)); err != nil {
		return fmt.Errorf("apply %s RouteBusIdentity: %w", edgeIdentityName, err)
	}

	var certPEM, caPEM []byte
	// The signer reconciles on the apply's watch event; a minute is generous for a local sign.
	if err := wait.WaitFor(ctx, time.Minute, 2*time.Second, func() (bool, error) {
		certPEM, caPEM, err = signedEdgeIntermediate(ctx, s.DispatchKubeconfig, keyPEM)
		return err == nil && len(certPEM) > 0, nil
	}); err != nil {
		return fmt.Errorf("wait for the %s RouteBusIdentity to be signed: %w", edgeIdentityName, err)
	}

	if err := os.MkdirAll(s.EdgePKIDir, 0o755); err != nil {
		return fmt.Errorf("mkdir edge pki dir: %w", err)
	}
	// ca.crt/tls.crt/tls.key is the pool CA Secret's own layout, which is what the edge agent reads
	// (see mesh/agent/edgecert.go) — so production can mount that Secret verbatim.
	for name, content := range map[string][]byte{"ca.crt": caPEM, "tls.crt": certPEM, "tls.key": keyPEM} {
		if err := os.WriteFile(filepath.Join(s.EdgePKIDir, name), content, 0o600); err != nil {
			return fmt.Errorf("write edge %s: %w", name, err)
		}
	}
	slog.Info("edge route-bus CA written", "dir", s.EdgePKIDir)
	return nil
}

// edgeIdentityManifest renders the fleet's RouteBusIdentity. `request` is a []byte field, so it
// serializes as base64. permittedUnderlayCIDRs is what actually bounds the edge fleet: the signer
// turns it into the intermediate's IP name constraint, so an edge leaf carrying a pool node's VTEP
// fails chain verification at the reflector.
func edgeIdentityManifest(csrPEM []byte, permittedCIDRs []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `apiVersion: platform.ectobase.dev/v1alpha1
kind: RouteBusIdentity
metadata:
  name: %s
spec:
  poolName: %s
  request: %s
  permittedUnderlayCIDRs:
`, edgeIdentityName, edgeIdentityName, base64.StdEncoding.EncodeToString(csrPEM))
	for _, c := range permittedCIDRs {
		fmt.Fprintf(&b, "    - %q\n", c)
	}
	return b.String()
}

// signedEdgeIntermediate reads the identity's status and returns the intermediate + root, but only
// once the published certificate actually matches the key we just generated — otherwise a re-run
// would happily pick up the PREVIOUS intermediate and pair it with a key that cannot use it.
func signedEdgeIntermediate(ctx context.Context, kubeconfig string, keyPEM []byte) (certPEM, caPEM []byte, err error) {
	certPEM, err = identityStatusField(ctx, kubeconfig, "certificate")
	if err != nil || len(certPEM) == 0 {
		return nil, nil, err
	}
	if !certMatchesKey(certPEM, keyPEM) {
		return nil, nil, nil // stale status from a prior CSR; keep waiting
	}
	caPEM, err = identityStatusField(ctx, kubeconfig, "caBundle")
	if err != nil || len(caPEM) == 0 {
		return nil, nil, err
	}
	return certPEM, caPEM, nil
}

// identityStatusField reads one base64 []byte field off the edge RouteBusIdentity's status.
func identityStatusField(ctx context.Context, kubeconfig, field string) ([]byte, error) {
	out, err := exec.OutputStr(ctx, "kubectl", "--kubeconfig", kubeconfig,
		"get", "routebusidentity", edgeIdentityName, "-o", "jsonpath={.status."+field+"}")
	if err != nil {
		return nil, nil // not signed yet (or not visible yet); the caller retries
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	decoded, derr := base64.StdEncoding.DecodeString(out)
	if derr != nil {
		return nil, fmt.Errorf("decode status.%s: %w", field, derr)
	}
	return decoded, nil
}

// edgeMaterialFresh reports whether the on-disk trio can be left alone: complete, its intermediate
// not near expiry (the same renewal test the pool's bootstrapper applies to its Secret), and
// anchored on the root the dispatch is serving RIGHT NOW.
//
// That last check is the one that matters in practice. A reinstalled dispatch mints a fresh root,
// and material left over from the previous one still looks complete and unexpired — so without it
// the deploy would skip re-provisioning and every edge would fail to authenticate, with three
// perfectly healthy-looking files on disk. Pass a nil wantRoot to skip the anchor check.
func edgeMaterialFresh(dir string, wantRoot []byte) (bool, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read edge tls.crt: %w", err)
	}
	for _, f := range []string{"ca.crt", "tls.key"} {
		st, serr := os.Stat(filepath.Join(dir, f))
		if os.IsNotExist(serr) || (serr == nil && st.Size() == 0) {
			return false, nil
		}
		if serr != nil {
			return false, fmt.Errorf("stat edge %s: %w", f, serr)
		}
	}
	cert := parseCertPEM(certPEM)
	if cert == nil {
		return false, nil // unparseable: re-provision rather than fail the deploy
	}
	if !time.Now().Add(edgeIntermediateRenewBefore).Before(cert.NotAfter) {
		return false, nil
	}
	if len(wantRoot) == 0 {
		return true, nil
	}
	// Compare the DER, not the PEM bytes: whitespace/line-ending differences between the Secret and
	// the signer's republished caBundle would otherwise read as a root change.
	have, want := parseCertPEM(mustReadOrNil(filepath.Join(dir, "ca.crt"))), parseCertPEM(wantRoot)
	if have == nil || want == nil {
		return false, nil
	}
	return string(have.Raw) == string(want.Raw), nil
}

func parseCertPEM(p []byte) *x509.Certificate {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

func mustReadOrNil(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

// generateIntermediateKeyAndCSR mints a fresh ECDSA P-256 intermediate keypair and its PKCS#10 CSR.
// Mirrors dispatch/pkg/broker.GenerateIntermediateKeyAndCSR — the private key never leaves here.
func generateIntermediateKeyAndCSR(name string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate edge intermediate key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal edge intermediate key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "routebus-intermediate-" + name},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create edge intermediate CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// certMatchesKey reports whether certPEM's public key is the public half of keyPEM.
func certMatchesKey(certPEM, keyPEM []byte) bool {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return false
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return false
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return false
	}
	signer, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return false
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && pub.Equal(&signer.PublicKey)
}
