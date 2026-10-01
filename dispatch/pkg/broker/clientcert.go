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
	"errors"
	"fmt"
	"log"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// ClientCertAnnotation marks a broker-dispatch-tls Secret the broker wrote from a dispatch-issued
// client certificate. A Secret without it (the pool chart's old cert-manager certificate, issued from
// the pool intermediate) is not a dispatch credential.
const ClientCertAnnotation = "ectobase.dev/dispatch-client-cert"

// errNoBootstrap is returned when the broker has no usable client certificate and no bootstrap
// credential to enroll with.
var errNoBootstrap = errors.New("no usable dispatch client certificate and no bootstrap credential to enroll with")

// DispatchClientCert keeps the broker's dispatch client certificate in the pool Secret the broker
// loads its dispatch credential from (broker-dispatch-tls; client-go re-reads the mounted files, so
// a new certificate needs no restart). The key is generated here and never leaves the pool: only a
// CSR goes up, as RouteBusIdentity spec.clientRequest, and the dispatch signer answers in
// status.clientCertificate with a certificate from its client CA, the only CA the dispatch apiserver
// trusts for clients.
//
// Enrollment and recovery use the bootstrap credential (the short-lived enrollment token); renewal
// uses the certificate itself.
type DispatchClientCert struct {
	Dispatch   client.Client                 // the mTLS dispatch client, authenticated by this certificate
	Bootstrap  func() (client.Client, error) // a dispatch client on the bootstrap token; nil if none
	Downstream client.Client                 // the pool cluster (the Secret)
	PoolName   string
	SecretName string
	SecretNS   string

	RenewBefore  time.Duration // renew within this of expiry (30d of 90d: two thirds of its life)
	PollInterval time.Duration // status poll cadence
	PollTimeout  time.Duration // give up one enrollment after this
	Recheck      time.Duration // how often Start checks the certificate and the dispatch's acceptance of it
}

func (d *DispatchClientCert) defaults() {
	if d.RenewBefore == 0 {
		d.RenewBefore = 30 * 24 * time.Hour
	}
	if d.PollInterval == 0 {
		d.PollInterval = 3 * time.Second
	}
	if d.PollTimeout == 0 {
		d.PollTimeout = 5 * time.Minute
	}
	if d.Recheck == 0 {
		d.Recheck = time.Minute
	}
}

// certState is what the Secret holds.
type certState int

const (
	certUnusable certState = iota // absent, not dispatch-issued, expired, or not for its key
	certRenew                     // dispatch-issued and valid, but due for renewal
	certFresh                     // dispatch-issued and valid beyond the renewal window
)

// Usable reports whether the Secret holds a dispatch-issued certificate the broker can start on.
func (d *DispatchClientCert) Usable(ctx context.Context) (bool, error) {
	d.defaults()
	_, st, err := d.read(ctx)
	return st != certUnusable, err
}

func (d *DispatchClientCert) read(ctx context.Context) (*corev1.Secret, certState, error) {
	var sec corev1.Secret
	err := d.Downstream.Get(ctx, types.NamespacedName{Namespace: d.SecretNS, Name: d.SecretName}, &sec)
	if apierrors.IsNotFound(err) {
		return nil, certUnusable, nil
	}
	if err != nil {
		return nil, certUnusable, fmt.Errorf("get %s/%s: %w", d.SecretNS, d.SecretName, err)
	}
	crt, key := sec.Data[corev1.TLSCertKey], sec.Data[corev1.TLSPrivateKeyKey]
	if sec.Annotations[ClientCertAnnotation] == "" || !certMatchesKey(crt, key) || certNeedsRenewal(crt, 0, time.Now()) {
		return &sec, certUnusable, nil
	}
	if certNeedsRenewal(crt, d.RenewBefore, time.Now()) {
		return &sec, certRenew, nil
	}
	return &sec, certFresh, nil
}

// Start keeps the certificate current until ctx ends (manager.Runnable).
func (d *DispatchClientCert) Start(ctx context.Context) error {
	d.defaults()
	for {
		if err := d.ensure(ctx); err != nil {
			log.Printf("dispatch client certificate: %v", err)
		}
		if !sleepCtx(ctx, d.Recheck) {
			return nil
		}
	}
}

// ensure makes the Secret hold a fresh, dispatch-issued certificate the dispatch accepts. A fresh one
// is kept, after adopting a re-signed certificate for its key; one due for renewal is renewed over the
// mTLS credential; anything else, or a certificate the dispatch rejects as unauthenticated, is
// replaced by enrolling again through the bootstrap credential.
func (d *DispatchClientCert) ensure(ctx context.Context) error {
	d.defaults()
	sec, st, err := d.read(ctx)
	if err != nil {
		return err
	}
	switch st {
	case certFresh:
		err = d.adopt(ctx, sec)
	case certRenew:
		_, err = d.Enroll(ctx, d.Dispatch)
	}
	if st != certUnusable && !apierrors.IsUnauthorized(err) {
		return err
	}
	if st != certUnusable {
		log.Printf("dispatch client certificate: the dispatch rejects it (%v); enrolling again with the bootstrap credential", err)
	}
	if d.Bootstrap == nil {
		return errNoBootstrap
	}
	boot, berr := d.Bootstrap()
	if berr != nil {
		return fmt.Errorf("%w: %w", errNoBootstrap, berr)
	}
	_, err = d.Enroll(ctx, boot)
	return err
}

// adopt copies into the Secret a certificate the signer re-issued for the Secret's current key. The
// Get is also the check that the dispatch still accepts this credential.
func (d *DispatchClientCert) adopt(ctx context.Context, sec *corev1.Secret) error {
	var id platformv1.RouteBusIdentity
	if err := d.Dispatch.Get(ctx, types.NamespacedName{Name: d.PoolName}, &id); err != nil {
		return fmt.Errorf("get RouteBusIdentity %s: %w", d.PoolName, err)
	}
	crt, key := id.Status.ClientCertificate, sec.Data[corev1.TLSPrivateKeyKey]
	if len(crt) == 0 || bytes.Equal(crt, sec.Data[corev1.TLSCertKey]) || !certMatchesKey(crt, key) ||
		certNeedsRenewal(crt, d.RenewBefore, time.Now()) {
		return nil
	}
	log.Printf("dispatch client certificate: adopting the one the signer re-issued for this broker's key")
	return d.write(ctx, key, crt)
}

// Enroll obtains a new client certificate through dispatch: a fresh key and CSR, filed as the
// RouteBusIdentity's spec.clientRequest, then the signer's answer, written with the key into the
// Secret. It returns the certificate PEM.
func (d *DispatchClientCert) Enroll(ctx context.Context, dispatch client.Client) ([]byte, error) {
	d.defaults()
	keyPEM, csrPEM, err := generateClientKeyAndCSR(d.PoolName)
	if err != nil {
		return nil, err
	}
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var id platformv1.RouteBusIdentity
		if err := dispatch.Get(ctx, types.NamespacedName{Name: d.PoolName}, &id); err != nil {
			return err
		}
		id.Spec.ClientRequest = csrPEM
		return dispatch.Update(ctx, &id)
	})
	if err != nil {
		return nil, fmt.Errorf("file client CSR on RouteBusIdentity %s: %w", d.PoolName, err)
	}
	certPEM, err := d.pollSigned(ctx, dispatch, keyPEM)
	if err != nil {
		return nil, err
	}
	return certPEM, d.write(ctx, keyPEM, certPEM)
}

// pollSigned waits until status.clientCertificate is for keyPEM.
func (d *DispatchClientCert) pollSigned(ctx context.Context, dispatch client.Client, keyPEM []byte) ([]byte, error) {
	deadline := time.Now().Add(d.PollTimeout)
	var last string
	for {
		var id platformv1.RouteBusIdentity
		if err := dispatch.Get(ctx, types.NamespacedName{Name: d.PoolName}, &id); err == nil {
			if crt := id.Status.ClientCertificate; len(crt) > 0 && certMatchesKey(crt, keyPEM) {
				return crt, nil
			}
			if c := meta.FindStatusCondition(id.Status.Conditions, "ClientSigned"); c != nil {
				last = c.Message
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for the client certificate on RouteBusIdentity %q (last ClientSigned condition: %q)", d.PoolName, last)
		}
		if !sleepCtx(ctx, d.PollInterval) {
			return nil, ctx.Err()
		}
	}
}

// write upserts the Secret {tls.crt, tls.key} and marks it dispatch-issued.
func (d *DispatchClientCert) write(ctx context.Context, keyPEM, certPEM []byte) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		sec := &corev1.Secret{}
		err := d.Downstream.Get(ctx, types.NamespacedName{Namespace: d.SecretNS, Name: d.SecretName}, sec)
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("get %s/%s: %w", d.SecretNS, d.SecretName, err)
		}
		sec.Namespace, sec.Name = d.SecretNS, d.SecretName
		if sec.Annotations == nil {
			sec.Annotations = map[string]string{}
		}
		sec.Annotations[ClientCertAnnotation] = "true"
		sec.Data = map[string][]byte{corev1.TLSCertKey: certPEM, corev1.TLSPrivateKeyKey: keyPEM}
		if apierrors.IsNotFound(err) {
			sec.Type = corev1.SecretTypeTLS
			return d.Downstream.Create(ctx, sec)
		}
		return d.Downstream.Update(ctx, sec)
	})
}

// generateClientKeyAndCSR makes the broker's client key and a CSR for it. The CSR's subject is
// informational: the signer replaces it.
func generateClientKeyAndCSR(pool string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ectobase:cluster:" + pool},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}
