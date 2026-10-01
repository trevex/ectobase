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
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/dispatch/pkg/pki"
)

func clientScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := platformv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// signingDispatch is a dispatch whose signer answers every clientRequest at once, from its own CA,
// for the given lifetime. requests counts the CSRs it saw.
type signingDispatch struct {
	client.Client
	requests int
}

func newSigningDispatch(t *testing.T, life time.Duration) *signingDispatch {
	t.Helper()
	caCert, caKey := testCA(t)
	id := &platformv1.RouteBusIdentity{ObjectMeta: metav1.ObjectMeta{Name: "k02"}, Spec: platformv1.RouteBusIdentitySpec{PoolName: "k02"}}
	d := &signingDispatch{}
	d.Client = fake.NewClientBuilder().WithScheme(clientScheme(t)).WithObjects(id).WithStatusSubresource(id).
		WithInterceptorFuncs(interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if err := c.Update(ctx, obj, opts...); err != nil {
				return err
			}
			rbi, ok := obj.(*platformv1.RouteBusIdentity)
			if !ok || len(rbi.Spec.ClientRequest) == 0 {
				return nil
			}
			d.requests++
			cert, err := pki.SignClientCert(caCert, caKey, rbi.Spec.ClientRequest, "k02", time.Now().Add(life))
			if err != nil {
				return err
			}
			rbi.Status.ClientCertificate = cert
			return c.Status().Update(ctx, rbi)
		}}).Build()
	return d
}

// rejectingDispatch refuses everything as Unauthorized: the dispatch no longer trusts the
// certificate the client presents.
func rejectingDispatch(t *testing.T) client.Client {
	t.Helper()
	unauthorized := apierrors.NewUnauthorized("certificate signed by unknown authority")
	return fake.NewClientBuilder().WithScheme(clientScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return unauthorized
		},
		Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
			return unauthorized
		},
	}).Build()
}

func clientCertFor(t *testing.T, downstream client.Client) (*corev1.Secret, *x509.Certificate) {
	t.Helper()
	var sec corev1.Secret
	if err := downstream.Get(context.Background(), client.ObjectKey{Namespace: "ectobase-system", Name: "broker-dispatch-tls"}, &sec); err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(sec.Data["tls.crt"])
	if b == nil {
		t.Fatal("no certificate in the Secret")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !certMatchesKey(sec.Data["tls.crt"], sec.Data["tls.key"]) {
		t.Fatal("the Secret's certificate is not for its key")
	}
	return &sec, c
}

func newDispatchClientCert(downstream, dispatch client.Client, bootstrap client.Client) *DispatchClientCert {
	d := &DispatchClientCert{Dispatch: dispatch, Downstream: downstream, PoolName: "k02",
		SecretName: "broker-dispatch-tls", SecretNS: "ectobase-system", PollInterval: time.Millisecond, PollTimeout: time.Second}
	if bootstrap != nil {
		d.Bootstrap = func() (client.Client, error) { return bootstrap, nil }
	}
	return d
}

// First boot: no Secret. The broker enrolls through the bootstrap credential, generating its key
// locally, and writes the dispatch-issued certificate with its key into broker-dispatch-tls.
func TestDispatchClientCert_EnrollsThroughTheBootstrapCredential(t *testing.T) {
	downstream := fake.NewClientBuilder().WithScheme(clientScheme(t)).Build()
	boot := newSigningDispatch(t, 90*24*time.Hour)
	d := newDispatchClientCert(downstream, rejectingDispatch(t), boot)
	if err := d.ensure(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	sec, cert := clientCertFor(t, downstream)
	if cert.Subject.CommonName != "ectobase:cluster:k02" {
		t.Fatalf("Secret holds %q, not the dispatch-issued certificate", cert.Subject.CommonName)
	}
	if sec.Annotations[ClientCertAnnotation] == "" {
		t.Fatal("the Secret is not marked as holding a dispatch-issued certificate")
	}
	if boot.requests != 1 {
		t.Fatalf("want one CSR through the bootstrap credential, got %d", boot.requests)
	}
}

// A fresh, dispatch-issued certificate is left alone.
func TestDispatchClientCert_KeepsAFreshCertificate(t *testing.T) {
	downstream := fake.NewClientBuilder().WithScheme(clientScheme(t)).Build()
	dispatch := newSigningDispatch(t, 90*24*time.Hour)
	d := newDispatchClientCert(downstream, dispatch, nil)
	if _, err := d.Enroll(context.Background(), dispatch); err != nil {
		t.Fatal(err)
	}
	before, _ := clientCertFor(t, downstream)
	if err := d.ensure(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	after, _ := clientCertFor(t, downstream)
	if dispatch.requests != 1 || !bytes.Equal(before.Data["tls.crt"], after.Data["tls.crt"]) {
		t.Fatalf("a fresh certificate was replaced (%d CSRs)", dispatch.requests)
	}
}

// At two thirds of its lifetime the broker renews over its own mTLS credential, with a new key.
func TestDispatchClientCert_RenewsInTheRenewalWindow(t *testing.T) {
	downstream := fake.NewClientBuilder().WithScheme(clientScheme(t)).Build()
	dispatch := newSigningDispatch(t, 20*24*time.Hour) // inside the 30-day window
	d := newDispatchClientCert(downstream, dispatch, nil)
	if _, err := d.Enroll(context.Background(), dispatch); err != nil {
		t.Fatal(err)
	}
	before, _ := clientCertFor(t, downstream)
	if err := d.ensure(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	after, _ := clientCertFor(t, downstream)
	if dispatch.requests != 2 || bytes.Equal(before.Data["tls.key"], after.Data["tls.key"]) {
		t.Fatalf("want a renewal with a new key over the mTLS credential (%d CSRs)", dispatch.requests)
	}
}

// A certificate the broker did not write (the pool chart's old cert-manager one, issued from the
// pool intermediate) is not a dispatch credential any more: re-enroll with the bootstrap token.
func TestDispatchClientCert_ReplacesACertificateItDidNotWrite(t *testing.T) {
	keyPEM, _, _ := GenerateIntermediateKeyAndCSR("k02")
	old := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ectobase-system", Name: "broker-dispatch-tls",
		Annotations: map[string]string{"cert-manager.io/certificate-name": "broker-dispatch-tls"}},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": selfSignedFor(t, keyPEM, time.Now().Add(80*24*time.Hour)), "tls.key": keyPEM}}
	downstream := fake.NewClientBuilder().WithScheme(clientScheme(t)).WithObjects(old).Build()
	boot := newSigningDispatch(t, 90*24*time.Hour)
	d := newDispatchClientCert(downstream, rejectingDispatch(t), boot)
	if err := d.ensure(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, cert := clientCertFor(t, downstream); cert.Subject.CommonName != "ectobase:cluster:k02" || boot.requests != 1 {
		t.Fatalf("the leftover certificate was not replaced through the bootstrap credential (%d CSRs)", boot.requests)
	}
}

// The dispatch stops accepting a certificate the broker still thinks is fresh (the dispatch was
// reinstalled with a new client CA): re-enroll with the bootstrap credential.
func TestDispatchClientCert_ReEnrollsWhenTheDispatchRejectsIt(t *testing.T) {
	downstream := fake.NewClientBuilder().WithScheme(clientScheme(t)).Build()
	first := newSigningDispatch(t, 90*24*time.Hour)
	d := newDispatchClientCert(downstream, first, nil)
	if _, err := d.Enroll(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	before, _ := clientCertFor(t, downstream)

	boot := newSigningDispatch(t, 90*24*time.Hour)
	d = newDispatchClientCert(downstream, rejectingDispatch(t), boot)
	if err := d.ensure(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	after, _ := clientCertFor(t, downstream)
	if boot.requests != 1 || bytes.Equal(before.Data["tls.crt"], after.Data["tls.crt"]) {
		t.Fatalf("a rejected certificate must be replaced through the bootstrap credential (%d CSRs)", boot.requests)
	}
}

// With no usable certificate and no bootstrap credential there is nothing to enroll with.
func TestDispatchClientCert_NeedsABootstrapCredentialToEnroll(t *testing.T) {
	downstream := fake.NewClientBuilder().WithScheme(clientScheme(t)).Build()
	d := newDispatchClientCert(downstream, rejectingDispatch(t), nil)
	if err := d.ensure(context.Background()); err == nil || !errors.Is(err, errNoBootstrap) {
		t.Fatalf("want errNoBootstrap, got %v", err)
	}
}

// The signer re-signs for the same key (its own rules changed, or its CA rotated): adopt it.
func TestDispatchClientCert_AdoptsAReSignedCertificateForItsKey(t *testing.T) {
	downstream := fake.NewClientBuilder().WithScheme(clientScheme(t)).Build()
	dispatch := newSigningDispatch(t, 90*24*time.Hour)
	d := newDispatchClientCert(downstream, dispatch, nil)
	if _, err := d.Enroll(context.Background(), dispatch); err != nil {
		t.Fatal(err)
	}
	sec, _ := clientCertFor(t, downstream)
	resigned := selfSignedFor(t, sec.Data["tls.key"], time.Now().Add(89*24*time.Hour))
	var id platformv1.RouteBusIdentity
	if err := dispatch.Get(context.Background(), client.ObjectKey{Name: "k02"}, &id); err != nil {
		t.Fatal(err)
	}
	id.Status.ClientCertificate = resigned
	if err := dispatch.Status().Update(context.Background(), &id); err != nil {
		t.Fatal(err)
	}
	if err := d.ensure(context.Background()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if after, _ := clientCertFor(t, downstream); !bytes.Equal(after.Data["tls.crt"], resigned) {
		t.Fatal("the re-signed certificate for the broker's key was not adopted")
	}
}

// testCA is a throwaway self-signed CA.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}
