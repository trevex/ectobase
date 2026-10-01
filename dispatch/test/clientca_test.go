// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	platforminstall "github.com/trevex/ectobase/api/platform/install"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/dispatch/pkg/broker"
	"github.com/trevex/ectobase/dispatch/pkg/pki"
)

// TestDispatchClientCA_AggregatedAPIServer runs the REAL dispatch apiserver with --client-ca-file set
// to a dedicated client CA, as the chart does, and connects to it directly, as a broker does.
//
// The finding it pins: every pool intermediate chains to the route-bus root, and an intermediate's
// name constraints bind SANs, not the subject. A pool can therefore mint a client certificate with
// O=system:masters, which the apiserver's authorizer lets through unconditionally. Such a certificate
// must not authenticate at all; a broker certificate the signer issued must authenticate as exactly
// ectobase:cluster:<pool> in group ectobase:brokers.
func TestDispatchClientCA_AggregatedAPIServer(t *testing.T) {
	t.Setenv("GOWORK", "off")

	routeBusRoot := newTestCA(t, "ectobase-ca")
	clientCA := newTestCA(t, "ectobase-dispatch-client-ca")
	caFile := filepath.Join(t.TempDir(), "client-ca.crt")
	if err := os.WriteFile(caFile, clientCA.pem(), 0o600); err != nil {
		t.Fatal(err)
	}

	scheme := runtime.NewScheme()
	platforminstall.Install(scheme)
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	env, err := kitenvtest.NewEnvironment("github.com/trevex/ectobase/dispatch/cmd/apiserver", nil,
		[]string{filepath.Join(".", "fixtures")})
	if err != nil {
		t.Fatalf("NewEnvironment: %v", err)
	}
	env.SetAPIServerExtraArgs(kitenvtest.ProcessArgs{"client-ca-file": {caFile}})
	if _, err := env.Start(scheme, os.Stderr); err != nil {
		t.Fatalf("env.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("env.Stop: %v", err)
		}
	})
	if err := env.WaitUntilReadyWithTimeout(apiServiceTimeout); err != nil {
		t.Fatalf("WaitUntilReadyWithTimeout: %v", err)
	}
	admin, err := client.New(env.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := kitenvtest.Context()

	// Two pools, and the grants that tell the identities apart: ectobase:cluster:c1 may read c1, and
	// the group ectobase:brokers may read c2.
	for _, p := range []string{"c1", "c2"} {
		if err := admin.Create(ctx, &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: p}}); err != nil {
			t.Fatalf("create pool %s: %v", p, err)
		}
	}
	grant := func(name, pool string, subject rbacv1.Subject) {
		t.Helper()
		if err := admin.Create(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name},
			Rules: []rbacv1.PolicyRule{{APIGroups: []string{"platform.ectobase.dev"}, Resources: []string{"clusterpools"},
				ResourceNames: []string{pool}, Verbs: []string{"get"}}}}); err != nil {
			t.Fatal(err)
		}
		if err := admin.Create(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name},
			RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: name},
			Subjects: []rbacv1.Subject{subject}}); err != nil {
			t.Fatal(err)
		}
	}
	grant("read-c1", "c1", rbacv1.Subject{Kind: "User", Name: "ectobase:cluster:c1", APIGroup: "rbac.authorization.k8s.io"})
	grant("brokers-read-c2", "c2", rbacv1.Subject{Kind: "Group", Name: "ectobase:brokers", APIGroup: "rbac.authorization.k8s.io"})

	base := directConfig(t, admin, ctx)
	as := func(certPEM, keyPEM []byte) client.Client {
		t.Helper()
		cfg := rest.CopyConfig(base)
		cfg.CertData, cfg.KeyData = certPEM, keyPEM
		c, err := client.New(cfg, client.Options{Scheme: scheme})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	get := func(c client.Client, pool string) error {
		return c.Get(ctx, client.ObjectKey{Name: pool}, &platformv1.ClusterPool{})
	}

	t.Run("BrokerCertFromTheSignerIsThePoolAndTheBrokerGroup", func(t *testing.T) {
		keyPEM, csrPEM := clientKeyAndCSR(t, pkix.Name{CommonName: "anything", Organization: []string{"system:masters"}})
		certPEM, err := pki.SignClientCert(clientCA.cert, clientCA.key, csrPEM, "c1", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		broker := as(certPEM, keyPEM)
		if err := get(broker, "c1"); err != nil {
			t.Fatalf("the user ectobase:cluster:c1 must read c1: %v", err)
		}
		if err := get(broker, "c2"); err != nil {
			t.Fatalf("the group ectobase:brokers must read c2: %v", err)
		}
		// Nothing else: the CSR asked for system:masters, and the signer did not grant it.
		err = broker.Create(ctx, &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c3"}})
		if !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), `"ectobase:cluster:c1"`) {
			t.Fatalf("want Forbidden for ectobase:cluster:c1 creating a pool, got %v", err)
		}
	})

	// The exploit: a pool's intermediate under the route-bus root mints O=system:masters. It is a
	// valid chain to that root; it must not authenticate here.
	t.Run("PoolIntermediateCannotMintSystemMasters", func(t *testing.T) {
		inter := routeBusRoot.intermediate(t, "routebus-intermediate-c1", "c1.routebus.ectobase.dev", "fd00:cafe:1914::/48")
		keyPEM, leafPEM := inter.leaf(t, pkix.Name{CommonName: "ectobase:cluster:c2", Organization: []string{"system:masters"}})
		forged := as(append(leafPEM, inter.pem()...), keyPEM)
		err := get(forged, "c2")
		if err == nil {
			t.Fatal("a pool-intermediate certificate with O=system:masters authenticated and was allowed")
		}
		// 401, not anonymous: the broker re-enrolls on exactly this answer.
		if !apierrors.IsUnauthorized(err) {
			t.Fatalf("want the certificate rejected with 401, got %v", err)
		}
	})

	// The control: the apiserver does let O=system:masters through unconditionally (its default
	// AlwaysAllowGroups) for a certificate from the CA it trusts. The client CA's key is therefore the
	// whole boundary, which is why only the signer holds it and the signer forces the subject.
	t.Run("ControlTheClientCAIsTheBoundary", func(t *testing.T) {
		keyPEM, leafPEM := clientCA.leaf(t, pkix.Name{CommonName: "nobody", Organization: []string{"system:masters"}})
		if err := get(as(leafPEM, keyPEM), "c2"); err != nil {
			t.Fatalf("expected the client CA's system:masters certificate to be allowed (the control): %v", err)
		}
	})

	// Why emptying the apiserver's AlwaysAllowGroups would not help (the kit exposes no way to do it
	// anyway): the apiserver delegates every other decision to the host kube-apiserver, and the host
	// itself allows system:masters for anything. Only keeping the group out of every certificate
	// does.
	t.Run("TheHostAuthorizerAllowsSystemMastersToo", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "nobody", Groups: []string{"system:masters"},
			ResourceAttributes: &authorizationv1.ResourceAttributes{Group: "platform.ectobase.dev",
				Resource: "clusterpools", Verb: "update", Name: "c2"},
		}}
		if err := admin.Create(ctx, sar); err != nil {
			t.Fatal(err)
		}
		if !sar.Status.Allowed {
			t.Fatalf("expected the host to allow system:masters; got %+v", sar.Status)
		}
	})

	// The broker's own enrollment code, end to end against the real apiserver: it files its CSR,
	// the "signer" answers, and the resulting Secret's certificate authenticates as the pool.
	t.Run("BrokerEnrollmentProducesAWorkingCredential", func(t *testing.T) {
		if err := admin.Create(ctx, &platformv1.RouteBusIdentity{ObjectMeta: metav1.ObjectMeta{Name: "c1"},
			Spec: platformv1.RouteBusIdentitySpec{PoolName: "c1"}}); err != nil {
			t.Fatal(err)
		}
		downstream := newSecretStore(t)
		d := &broker.DispatchClientCert{Downstream: downstream, PoolName: "c1", SecretName: "broker-dispatch-tls",
			SecretNS: "ectobase-system", PollInterval: 50 * time.Millisecond, PollTimeout: 30 * time.Second}
		done := make(chan error, 1)
		go func() { _, err := d.Enroll(ctx, admin); done <- err }()
		signOnce(t, admin, ctx, clientCA, "c1")
		if err := <-done; err != nil {
			t.Fatalf("enroll: %v", err)
		}
		var sec corev1.Secret
		if err := downstream.Get(ctx, client.ObjectKey{Namespace: "ectobase-system", Name: "broker-dispatch-tls"}, &sec); err != nil {
			t.Fatal(err)
		}
		if err := get(as(sec.Data["tls.crt"], sec.Data["tls.key"]), "c1"); err != nil {
			t.Fatalf("the enrolled credential does not authenticate as ectobase:cluster:c1: %v", err)
		}
	})
}

// directConfig is a rest.Config for the aggregated apiserver itself, bypassing the kube-apiserver's
// aggregation proxy (which authenticates as its own front-proxy identity): how a broker connects.
func directConfig(t *testing.T, admin client.Client, ctx context.Context) *rest.Config {
	t.Helper()
	var svc apiregistrationv1.APIService
	if err := admin.Get(ctx, client.ObjectKey{Name: "v1alpha1.platform.ectobase.dev"}, &svc); err != nil {
		t.Fatalf("get APIService: %v", err)
	}
	ref := svc.Spec.Service
	var ext corev1.Service
	if err := admin.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &ext); err != nil {
		t.Fatalf("get Service: %v", err)
	}
	return &rest.Config{
		Host:            fmt.Sprintf("https://%s", net.JoinHostPort(ext.Spec.ExternalName, fmt.Sprint(*ref.Port))),
		TLSClientConfig: rest.TLSClientConfig{CAData: svc.Spec.CABundle},
	}
}

// signOnce plays the dispatch signer for pool once: it waits for a clientRequest and answers it.
func signOnce(t *testing.T, admin client.Client, ctx context.Context, ca *testCA, pool string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var id platformv1.RouteBusIdentity
		if err := admin.Get(ctx, client.ObjectKey{Name: pool}, &id); err == nil && len(id.Spec.ClientRequest) > 0 {
			cert, err := pki.SignClientCert(ca.cert, ca.key, id.Spec.ClientRequest, pool, time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			id.Status.ClientCertificate = cert
			if err := admin.Status().Update(ctx, &id); err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the broker never filed a clientRequest")
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var caSerial int64 = 1000

func (c *testCA) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

func mintCert(t *testing.T, tmpl *x509.Certificate, parent *testCA) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSerial++
	tmpl.SerialNumber = big.NewInt(caSerial)
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	signer, signerCert := key, tmpl
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func newTestCA(t *testing.T, cn string) *testCA {
	c, k := mintCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, nil)
	return &testCA{c, k}
}

// intermediate is a pool intermediate as the route-bus signer issues it: path length 0, DNS- and
// IP-constrained.
func (c *testCA) intermediate(t *testing.T, cn, dns, ipRange string) *testCA {
	_, n, _ := net.ParseCIDR(ipRange)
	ic, ik := mintCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
		MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, PermittedDNSDomains: []string{dns},
		PermittedDNSDomainsCritical: true, PermittedIPRanges: []*net.IPNet{n}}, c)
	return &testCA{ic, ik}
}

// leaf is a client certificate with the given subject (no SANs, so name constraints pass).
func (c *testCA) leaf(t *testing.T, subject pkix.Name) (keyPEM, certPEM []byte) {
	lc, lk := mintCert(t, &x509.Certificate{Subject: subject, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, c)
	return keyPEMOf(t, lk), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: lc.Raw})
}

func keyPEMOf(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func clientKeyAndCSR(t *testing.T, subject pkix.Name) (keyPEM, csrPEM []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, k)
	if err != nil {
		t.Fatal(err)
	}
	return keyPEMOf(t, k), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// newSecretStore stands in for the pool cluster the broker writes its Secret to.
func newSecretStore(t *testing.T) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(s).Build()
}
