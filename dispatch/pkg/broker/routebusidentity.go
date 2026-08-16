// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/trevex/ectobase/api/platform"
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

// ensure provisions or renews the pool intermediate Secret. Idempotent: a no-op when the
// existing Secret carries a still-fresh intermediate.
func (b *PoolCertBootstrapper) ensure(ctx context.Context) error {
	var sec corev1.Secret
	err := b.Downstream.Get(ctx, types.NamespacedName{Namespace: b.SecretNS, Name: b.SecretName}, &sec)
	if err == nil && !certNeedsRenewal(sec.Data["tls.crt"], b.RenewBefore, time.Now()) {
		return nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("get pool CA secret: %w", err)
	}

	keyPEM, csrPEM, err := GenerateIntermediateKeyAndCSR(b.PoolName)
	if err != nil {
		return err
	}
	if err := b.submitCSR(ctx, csrPEM); err != nil {
		return err
	}
	certPEM, caPEM, err := b.pollSigned(ctx, keyPEM)
	if err != nil {
		return err
	}
	return b.writeSecret(ctx, keyPEM, certPEM, caPEM)
}

// submitCSR creates or updates this pool's RouteBusIdentity on dispatch with the new CSR.
func (b *PoolCertBootstrapper) submitCSR(ctx context.Context, csrPEM []byte) error {
	id := &platform.RouteBusIdentity{}
	err := b.Dispatch.Get(ctx, types.NamespacedName{Name: b.PoolName}, id)
	if apierrors.IsNotFound(err) {
		id = &platform.RouteBusIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: b.PoolName},
			Spec:       platform.RouteBusIdentitySpec{PoolName: b.PoolName, Request: csrPEM},
		}
		return b.Dispatch.Create(ctx, id)
	}
	if err != nil {
		return fmt.Errorf("get RouteBusIdentity: %w", err)
	}
	id.Spec.PoolName = b.PoolName
	id.Spec.Request = csrPEM
	// Clear the old status cert so pollSigned waits for the re-sign, not the stale one.
	id.Status.Certificate = nil
	if err := b.Dispatch.Update(ctx, id); err != nil {
		return fmt.Errorf("update RouteBusIdentity: %w", err)
	}
	_ = b.Dispatch.Status().Update(ctx, id) // best-effort clear of stale status
	return nil
}

// pollSigned waits until the signer publishes a cert matching our key, or times out.
func (b *PoolCertBootstrapper) pollSigned(ctx context.Context, keyPEM []byte) (certPEM, caPEM []byte, err error) {
	deadline := time.Now().Add(b.PollTimeout)
	for {
		var id platform.RouteBusIdentity
		if e := b.Dispatch.Get(ctx, types.NamespacedName{Name: b.PoolName}, &id); e == nil {
			if len(id.Status.Certificate) > 0 && certMatchesKey(id.Status.Certificate, keyPEM) {
				return id.Status.Certificate, id.Status.CABundle, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, nil, fmt.Errorf("timed out waiting for RouteBusIdentity %q to be signed", b.PoolName)
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
