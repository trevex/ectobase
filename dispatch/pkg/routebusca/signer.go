// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package routebusca is the dispatch-side signer for route-bus PKI. It watches
// RouteBusIdentity requests, signs a per-pool, name-constrained intermediate CA from the
// root CA (a dispatch-only cert-manager Secret), and writes the signed intermediate +
// root bundle back into status. Pools mint their own per-node agent leaves from the
// intermediate; the reflector trusts only the root and gets cross-pool isolation for free
// because Go's TLS chain verification enforces the intermediate's NameConstraints.
package routebusca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/trevex/ectobase/api/platform"
)

// dnsSuffix roots the route-bus SAN namespace. A pool's intermediate is name-constrained to
// <pool>.<dnsSuffix>; its node leaves carry a DNS SAN <node>.<pool>.<dnsSuffix>, so the
// reflector's chain verification rejects a leaf whose pool doesn't match the intermediate.
const dnsSuffix = "routebus.ectobase.dev"

// PoolDNSDomain is the name-constraint domain for a pool's intermediate CA.
func PoolDNSDomain(pool string) string { return pool + "." + dnsSuffix }

// NodeDNSName is the DNS SAN a per-node agent leaf must carry to validate under its pool's
// intermediate. Pools set this when minting node leaves (Phase 4).
func NodeDNSName(node, pool string) string { return node + "." + PoolDNSDomain(pool) }

// intermediateTTL is how long a signed pool intermediate is valid. Long-lived relative to
// the per-node leaves the pool mints beneath it (which rotate on the pool's cadence).
const intermediateTTL = 90 * 24 * time.Hour

// SignIntermediate signs the CSR as a pool-scoped, path-len-0 intermediate CA from the root.
// The returned cert IsCA with MaxPathLen 0 (cannot sign further CAs) and is name-constrained to
// the pool's DNS domain AND (when permittedCIDRs is non-empty) its underlay IP ranges, so it can
// only issue leaves for its own pool and only with node IP SANs inside the pool's underlay. Pure.
func SignIntermediate(rootCert *x509.Certificate, rootKey crypto.Signer, csrDER []byte, poolName string, permittedCIDRs []string, notAfter time.Time) ([]byte, error) {
	block, _ := pem.Decode(csrDER)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("spec.request is not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR self-signature invalid: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "routebus-intermediate-" + poolName},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		// Cross-pool boundary: this intermediate may only issue leaves whose DNS SANs are
		// under the pool's domain. Go's TLS chain verification enforces this on the reflector.
		PermittedDNSDomains:         []string{PoolDNSDomain(poolName)},
		PermittedDNSDomainsCritical: true,
	}
	// IP boundary: constrain the intermediate to the pool's underlay ranges so it cannot mint a
	// leaf with an IP SAN in another pool's underlay (which the reflector's nexthop==SAN check
	// would otherwise accept). Empty ranges => no IP constraint (bootstrap before prefixes known).
	for _, c := range permittedCIDRs {
		_, ipNet, perr := net.ParseCIDR(c)
		if perr != nil {
			return nil, fmt.Errorf("bad underlay CIDR %q: %w", c, perr)
		}
		tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, ipNet)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, csr.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("sign intermediate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// RootCA holds the root signing material (loaded from the dispatch cert-manager Secret).
type RootCA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	PEM  []byte // root cert PEM, published as status.caBundle
}

// Signer reconciles RouteBusIdentity: it signs each request's CSR into a pool intermediate
// and writes the result to status. Inactive (skips) when Root is nil (mTLS not configured).
type Signer struct {
	Client client.Client
	Root   *RootCA
}

func (s *Signer) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var id platform.RouteBusIdentity
	if err := s.Client.Get(ctx, req.NamespacedName, &id); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if s.Root == nil {
		// mTLS not configured on this dispatch — nothing to sign. (Requeue is driven by
		// events; a later config that mounts the root re-runs on the next request.)
		return ctrl.Result{}, nil
	}
	if id.Spec.PoolName == "" || len(id.Spec.Request) == 0 {
		return ctrl.Result{}, s.deny(ctx, &id, "spec.poolName and spec.request are required")
	}
	// Idempotent: if already signed for THIS public key and not near expiry, leave it.
	if fresh, err := s.alreadySigned(&id); err == nil && fresh {
		return ctrl.Result{RequeueAfter: intermediateTTL / 3}, nil
	}

	cert, err := SignIntermediate(s.Root.Cert, s.Root.Key, id.Spec.Request, id.Spec.PoolName, id.Spec.PermittedUnderlayCIDRs, time.Now().Add(intermediateTTL))
	if err != nil {
		return ctrl.Result{}, s.deny(ctx, &id, err.Error())
	}
	id.Status.Certificate = cert
	id.Status.CABundle = s.Root.PEM
	meta.SetStatusCondition(&id.Status.Conditions, metav1.Condition{
		Type: "Signed", Status: metav1.ConditionTrue, Reason: "Issued",
		Message: "intermediate CA signed for pool " + id.Spec.PoolName,
	})
	if err := s.Client.Status().Update(ctx, &id); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: intermediateTTL / 3}, nil
}

// alreadySigned reports whether status carries a cert matching the current CSR's public key
// and comfortably before expiry (so re-issuing on rotation but not every reconcile).
func (s *Signer) alreadySigned(id *platform.RouteBusIdentity) (bool, error) {
	if len(id.Status.Certificate) == 0 {
		return false, nil
	}
	cb, _ := pem.Decode(id.Status.Certificate)
	if cb == nil {
		return false, nil
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return false, err
	}
	if time.Until(cert.NotAfter) < intermediateTTL/2 {
		return false, nil // due for rotation
	}
	rb, _ := pem.Decode(id.Spec.Request)
	if rb == nil {
		return false, nil
	}
	csr, err := x509.ParseCertificateRequest(rb.Bytes)
	if err != nil {
		return false, err
	}
	return publicKeysEqual(cert.PublicKey, csr.PublicKey), nil
}

func (s *Signer) deny(ctx context.Context, id *platform.RouteBusIdentity, msg string) error {
	meta.SetStatusCondition(&id.Status.Conditions, metav1.Condition{
		Type: "Signed", Status: metav1.ConditionFalse, Reason: "Denied", Message: msg,
	})
	if err := s.Client.Status().Update(ctx, id); err != nil && !errors.IsConflict(err) {
		return err
	}
	return nil
}

func (s *Signer) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&platform.RouteBusIdentity{}).
		Complete(s)
}

// publicKeysEqual compares two public keys by their PKIX DER encoding.
func publicKeysEqual(a, b any) bool {
	ad, err1 := x509.MarshalPKIXPublicKey(a)
	bd, err2 := x509.MarshalPKIXPublicKey(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ad) == string(bd)
}

// LoadRootCA reads the root CA cert + key PEM (the dispatch cert-manager routebus-ca Secret,
// mounted as tls.crt/tls.key) into signing material. Returns nil,nil when both paths are empty
// (mTLS not configured — the signer stays inactive).
func LoadRootCA(certPath, keyPath string) (*RootCA, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil
	}
	certPEM, err := readFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read root cert: %w", err)
	}
	keyPEM, err := readFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read root key: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("root cert is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root cert: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("root cert is not a CA")
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("root key is not PEM")
	}
	key, err := parsePrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root key: %w", err)
	}
	return &RootCA{Cert: cert, Key: key, PEM: certPEM}, nil
}

// parsePrivateKey accepts PKCS#8, EC (SEC1), or PKCS#1 keys (cert-manager emits PKCS#8).
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, fmt.Errorf("PKCS#8 key is not a crypto.Signer")
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }
