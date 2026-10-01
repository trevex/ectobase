// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// GenerateIntermediateKeyAndCSR generates a fresh ECDSA P-256 intermediate keypair for a pool
// and a PKCS#10 CSR for it. The private key stays in the pool (only the CSR is sent up). Pure.
func GenerateIntermediateKeyAndCSR(poolName string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "routebus-intermediate-" + poolName},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

// certNeedsRenewal reports whether an intermediate PEM is missing/unparseable or within the
// renewal window of expiry (so the bootstrapper re-requests). Pure.
func certNeedsRenewal(certPEM []byte, renewBefore time.Duration, now time.Time) bool {
	if len(certPEM) == 0 {
		return true
	}
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return true
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return true
	}
	return now.Add(renewBefore).After(c.NotAfter)
}

// certMatchesKey reports whether the cert's public key is the public half of keyPEM (so a
// polled status cert corresponds to the CSR we just submitted, not a stale one). Pure.
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
	cd, e1 := x509.MarshalPKIXPublicKey(cert.PublicKey)
	kd, e2 := x509.MarshalPKIXPublicKey(&signer.PublicKey)
	return e1 == nil && e2 == nil && string(cd) == string(kd)
}

// PoolCertBootstrapper is a broker Runnable that provisions this pool's route-bus intermediate
// CA: it generates the keypair locally, submits a CSR as a RouteBusIdentity on dispatch, waits
// for the signer, and writes the intermediate + root bundle into a pool Secret that backs the
// pool cert-manager CA Issuer (which mints per-node agent leaves). The private key never leaves
// the pool. Re-runs periodically to handle rotation.
type PoolCertBootstrapper struct {
	Dispatch   client.Client // dispatch aggregated apiserver (create RouteBusIdentity + poll status)
	Downstream client.Client // pool cluster (write the Secret)
	PoolName   string
	SecretName string
	SecretNS   string
	// PermittedCIDRs are the pool's underlay ranges (from config, e.g. the pool's /48), sent with
	// the CSR. ADVISORY ONLY: the signer constrains a pool intermediate to the operator-authored
	// ClusterPool.spec.underlayPrefix and ignores these, because a constraint the constrained party
	// chooses bounds nothing. They only surface in the Signed condition when outside the prefix.
	PermittedCIDRs []string

	RenewBefore  time.Duration // re-request when the intermediate is within this of expiry
	PollInterval time.Duration // status poll cadence
	PollTimeout  time.Duration // give up one attempt after this
	Recheck      time.Duration // re-ensure cadence (rotation)
}

func (b *PoolCertBootstrapper) defaults() {
	if b.RenewBefore == 0 {
		b.RenewBefore = 30 * 24 * time.Hour
	}
	if b.PollInterval == 0 {
		b.PollInterval = 3 * time.Second
	}
	if b.PollTimeout == 0 {
		b.PollTimeout = 5 * time.Minute
	}
	if b.Recheck == 0 {
		b.Recheck = 12 * time.Hour
	}
}

// Start ensures the intermediate at boot (retrying), then re-ensures every Recheck for rotation.
func (b *PoolCertBootstrapper) Start(ctx context.Context) error {
	b.defaults()
	for {
		if err := b.ensure(ctx); err != nil {
			log.Printf("routebus cert bootstrap: %v (retrying)", err)
			if !sleepCtx(ctx, b.PollInterval) {
				return nil
			}
			continue
		}
		if !sleepCtx(ctx, b.Recheck) {
			return nil
		}
	}
}

// EnsureOnce provisions the pool intermediate exactly once (idempotent: a no-op if the
// existing intermediate is still fresh). Used at broker first-boot to break the credential
// bootstrap chicken-and-egg before the steady-state mTLS leaf exists.
func (b *PoolCertBootstrapper) EnsureOnce(ctx context.Context) error {
	b.defaults()
	return b.ensure(ctx)
}

// ensure provisions or renews the pool intermediate Secret. Idempotent: a no-op when the
// existing Secret carries a still-fresh intermediate.
func (b *PoolCertBootstrapper) ensure(ctx context.Context) error {
	var sec corev1.Secret
	err := b.Downstream.Get(ctx, types.NamespacedName{Namespace: b.SecretNS, Name: b.SecretName}, &sec)
	if err == nil && !certNeedsRenewal(sec.Data["tls.crt"], b.RenewBefore, time.Now()) {
		return b.adoptResigned(ctx, &sec)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("get pool CA secret: %w", err)
	}

	// The intermediate is IP-constrained to the ClusterPool's spec.underlayPrefix, which the
	// signer reads itself; a pool whose ClusterPool declares none is denied and pollSigned times
	// out (see the RouteBusIdentity's Signed condition).
	keyPEM, csrPEM, err := GenerateIntermediateKeyAndCSR(b.PoolName)
	if err != nil {
		return err
	}
	if err := b.submitCSR(ctx, csrPEM, b.PermittedCIDRs); err != nil {
		return err
	}
	certPEM, caPEM, err := b.pollSigned(ctx, keyPEM)
	if err != nil {
		return err
	}
	return b.writeSecret(ctx, keyPEM, certPEM, caPEM)
}

// adoptResigned copies into the pool Secret an intermediate the signer re-issued for the Secret's
// CURRENT key. The signer re-signs when the constraint it would issue differs from the one the
// cert carries (the operator changed the pool's underlayPrefix, or the cert predates the rule), and
// without this the pool would keep presenting the old one until its renewal window. Best effort: a
// failed read leaves the Secret as it is, to be retried at the next recheck.
func (b *PoolCertBootstrapper) adoptResigned(ctx context.Context, sec *corev1.Secret) error {
	var id platformv1.RouteBusIdentity
	if err := b.Dispatch.Get(ctx, types.NamespacedName{Name: b.PoolName}, &id); err != nil {
		log.Printf("routebus cert bootstrap: cannot check for a re-signed intermediate: %v", err)
		return nil
	}
	cert := id.Status.Certificate
	if len(cert) == 0 || bytes.Equal(cert, sec.Data["tls.crt"]) ||
		!certMatchesKey(cert, sec.Data["tls.key"]) || certNeedsRenewal(cert, b.RenewBefore, time.Now()) {
		return nil
	}
	ca := id.Status.CABundle
	if len(ca) == 0 {
		ca = sec.Data["ca.crt"]
	}
	log.Printf("routebus cert bootstrap: adopting the intermediate the signer re-issued for this pool's key")
	return b.writeSecret(ctx, sec.Data["tls.key"], cert, ca)
}

// submitCSR creates or updates this pool's RouteBusIdentity on dispatch with the new CSR + the
// pool's configured underlay CIDRs (advisory: the signer takes the constraint from the ClusterPool).
func (b *PoolCertBootstrapper) submitCSR(ctx context.Context, csrPEM []byte, cidrs []string) error {
	id := &platformv1.RouteBusIdentity{}
	err := b.Dispatch.Get(ctx, types.NamespacedName{Name: b.PoolName}, id)
	if apierrors.IsNotFound(err) {
		id = &platformv1.RouteBusIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: b.PoolName},
			Spec:       platformv1.RouteBusIdentitySpec{PoolName: b.PoolName, Request: csrPEM, PermittedUnderlayCIDRs: cidrs},
		}
		return b.Dispatch.Create(ctx, id)
	}
	if err != nil {
		return fmt.Errorf("get RouteBusIdentity: %w", err)
	}
	id.Spec.PoolName = b.PoolName
	id.Spec.Request = csrPEM
	id.Spec.PermittedUnderlayCIDRs = cidrs
	// The status is left alone: it is the signer's, and the broker holds no grant on it. A stale
	// cert there is for the old key, which pollSigned does not accept.
	if err := b.Dispatch.Update(ctx, id); err != nil {
		return fmt.Errorf("update RouteBusIdentity: %w", err)
	}
	return nil
}

// pollSigned waits until the signer publishes a cert matching our key, or times out.
func (b *PoolCertBootstrapper) pollSigned(ctx context.Context, keyPEM []byte) (certPEM, caPEM []byte, err error) {
	deadline := time.Now().Add(b.PollTimeout)
	var last string
	for {
		var id platformv1.RouteBusIdentity
		if e := b.Dispatch.Get(ctx, types.NamespacedName{Name: b.PoolName}, &id); e == nil {
			if len(id.Status.Certificate) > 0 && certMatchesKey(id.Status.Certificate, keyPEM) {
				return id.Status.Certificate, id.Status.CABundle, nil
			}
			if c := meta.FindStatusCondition(id.Status.Conditions, "Signed"); c != nil {
				last = c.Message
			}
		}
		if time.Now().After(deadline) {
			// The signer's last word, e.g. a denial because the ClusterPool declares no underlayPrefix.
			return nil, nil, fmt.Errorf("timed out waiting for RouteBusIdentity %q to be signed (last Signed condition: %q)", b.PoolName, last)
		}
		if !sleepCtx(ctx, b.PollInterval) {
			return nil, nil, ctx.Err()
		}
	}
}

// writeSecret upserts the pool CA Secret {tls.crt=intermediate, tls.key=pool key, ca.crt=root}.
func (b *PoolCertBootstrapper) writeSecret(ctx context.Context, keyPEM, certPEM, caPEM []byte) error {
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: b.SecretNS, Name: b.SecretName}}
	data := map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM, "ca.crt": caPEM}
	err := b.Downstream.Get(ctx, types.NamespacedName{Namespace: b.SecretNS, Name: b.SecretName}, sec)
	if apierrors.IsNotFound(err) {
		sec.Type = corev1.SecretTypeTLS
		sec.Data = data
		return b.Downstream.Create(ctx, sec)
	}
	if err != nil {
		return fmt.Errorf("get pool CA secret: %w", err)
	}
	sec.Data = data
	return b.Downstream.Update(ctx, sec)
}

// sleepCtx sleeps for d or until ctx is done; returns false if the context ended.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
