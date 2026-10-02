// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
)

// The dispatch client certificate is a broker's credential to the dispatch apiserver. The apiserver
// takes the username from the subject CN and a group from each O, and O=system:masters skips
// authorization, so none of the subject may come from the requester.
const (
	// BrokerUserPrefix is the username prefix of a pool broker; the per-pool RBAC binds
	// BrokerUserPrefix+<pool>.
	BrokerUserPrefix = "ectobase:cluster:"
	// BrokerGroup is the one group every broker certificate carries.
	BrokerGroup = "ectobase:brokers"
	// ConditionClientSigned reports on the RouteBusIdentity whether the client certificate is signed.
	ConditionClientSigned = "ClientSigned"
	// clientCertTTL is a broker client certificate's lifetime; the broker renews it at two thirds.
	clientCertTTL = 90 * 24 * time.Hour
)

// SignClientCert signs a broker's dispatch client certificate for pool from the dispatch client CA.
// Only the CSR's public key is used. Subject, usage and extensions are the signer's: CN
// ectobase:cluster:<pool>, O ectobase:brokers, client-auth usage only, not a CA, and no SANs,
// whatever the CSR asks for. Pure.
func SignClientCert(caCert *x509.Certificate, caKey crypto.Signer, csrPEM []byte, pool string, notAfter time.Time) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("spec.clientRequest is not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse client CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("client CSR self-signature invalid: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: BrokerUserPrefix + pool, Organization: []string{BrokerGroup}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign client certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// reconcileClient decides id's dispatch client certificate in status, in memory. Only a pool gets
// one: an identity named after an existing ClusterPool and not a fleet identity. It does not depend
// on the route-bus intermediate, so a pool still denied that (no underlayPrefix yet) can reach the
// dispatch, report its state, and show the denial.
func (s *Signer) reconcileClient(ctx context.Context, id *platformv1.RouteBusIdentity) (ctrl.Result, error) {
	if len(id.Spec.ClientRequest) == 0 {
		return ctrl.Result{}, nil
	}
	deny := func(msg string) {
		id.Status.ClientCertificate = nil
		meta.SetStatusCondition(&id.Status.Conditions, metav1.Condition{
			Type: ConditionClientSigned, Status: metav1.ConditionFalse, Reason: "Denied", Message: msg,
		})
	}
	switch {
	case s.ClientCA == nil:
		deny("the dispatch client CA is not configured (--dispatch-client-ca-cert, --dispatch-client-ca-key)")
		return ctrl.Result{}, nil
	case id.Spec.PoolName != id.Name:
		deny(fmt.Sprintf("spec.poolName %q must equal the RouteBusIdentity name %q", id.Spec.PoolName, id.Name))
		return ctrl.Result{}, nil
	case slices.Contains(s.FleetIdentities, id.Name):
		deny(fmt.Sprintf("fleet identity %s gets no dispatch client certificate: only a pool's broker talks to the dispatch apiserver", id.Name))
		return ctrl.Result{}, nil
	}
	reader := s.Reader
	if reader == nil {
		reader = s.Client
	}
	if err := reader.Get(ctx, client.ObjectKey{Name: id.Name}, &platformv1.ClusterPool{}); apierrors.IsNotFound(err) {
		deny(fmt.Sprintf("no ClusterPool %s: a dispatch client certificate is only signed for an enrolled pool", id.Name))
		return ctrl.Result{RequeueAfter: deniedRecheck}, nil
	} else if err != nil {
		return ctrl.Result{}, fmt.Errorf("get ClusterPool %s: %w", id.Name, err)
	}
	if s.clientAlreadySigned(id) {
		return ctrl.Result{RequeueAfter: clientCertTTL / 3}, nil
	}
	cert, err := SignClientCert(s.ClientCA.Cert, s.ClientCA.Key, id.Spec.ClientRequest, id.Name, time.Now().Add(clientCertTTL))
	if err != nil {
		deny(err.Error())
		return ctrl.Result{}, nil
	}
	id.Status.ClientCertificate = cert
	meta.SetStatusCondition(&id.Status.Conditions, metav1.Condition{
		Type: ConditionClientSigned, Status: metav1.ConditionTrue, Reason: "Issued",
		Message: fmt.Sprintf("dispatch client certificate signed for %s%s", BrokerUserPrefix, id.Name),
	})
	return ctrl.Result{RequeueAfter: clientCertTTL / 3}, nil
}

// clientAlreadySigned reports whether status carries a client certificate the client CA signed, for
// the current CSR's key, with exactly the forced subject, comfortably before expiry.
func (s *Signer) clientAlreadySigned(id *platformv1.RouteBusIdentity) bool {
	cb, _ := pem.Decode(id.Status.ClientCertificate)
	if cb == nil {
		return false
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil || cert.CheckSignatureFrom(s.ClientCA.Cert) != nil {
		return false
	}
	if time.Until(cert.NotAfter) < clientCertTTL/2 {
		return false
	}
	if cert.Subject.CommonName != BrokerUserPrefix+id.Name || !slices.Equal(cert.Subject.Organization, []string{BrokerGroup}) {
		return false
	}
	rb, _ := pem.Decode(id.Spec.ClientRequest)
	if rb == nil {
		return false
	}
	csr, err := x509.ParseCertificateRequest(rb.Bytes)
	if err != nil {
		return false
	}
	return publicKeysEqual(cert.PublicKey, csr.PublicKey)
}
