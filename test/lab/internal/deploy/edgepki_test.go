// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEdgeIdentityManifest(t *testing.T) {
	_, csrPEM, err := generateIntermediateKeyAndCSR("edge")
	if err != nil {
		t.Fatal(err)
	}
	got := edgeIdentityManifest(csrPEM, []string{"fd00:ffff::/32"})

	for _, want := range []string{
		"apiVersion: platform.ectobase.dev/v1alpha1",
		"kind: RouteBusIdentity",
		"name: edge",
		// The edge fleet is an ORDINARY identity: the signer needs no new kind, and poolName is
		// only ever used for the intermediate's CN and DNS constraint.
		"poolName: edge",
		// The name constraint that bounds local leaf minting: edge underlays live in LoopAggr,
		// outside every pool's fd00:cafe:<h>::/48 by construction.
		`- "fd00:ffff::/32"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("manifest missing %q:\n%s", want, got)
		}
	}

	// spec.request is a []byte field, so it must travel base64-encoded — a raw multi-line PEM
	// would not even parse as YAML here.
	if strings.Contains(got, "BEGIN CERTIFICATE REQUEST") {
		t.Errorf("CSR embedded as raw PEM rather than base64:\n%s", got)
	}
	line, ok := findPrefixedLine(got, "  request: ")
	if !ok {
		t.Fatalf("no request field:\n%s", got)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "  request: "))
	if err != nil {
		t.Fatalf("request is not base64: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("decoded request is not a PEM CSR: %+v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR self-signature invalid (the signer rejects this): %v", err)
	}
	if csr.Subject.CommonName != "routebus-intermediate-edge" {
		t.Errorf("CSR CN = %q, want routebus-intermediate-edge", csr.Subject.CommonName)
	}
}

// A re-run of `lab deploy` must not rotate the fleet CA out from under running edges, so a
// still-fresh trio is left alone — but an incomplete or near-expiry one is re-provisioned.
func TestEdgeMaterialFresh(t *testing.T) {
	for _, tc := range []struct {
		name     string
		write    map[string][]byte
		notAfter time.Duration
		want     bool
	}{
		{name: "complete and fresh", notAfter: 90 * 24 * time.Hour, want: true},
		{name: "near expiry", notAfter: 10 * 24 * time.Hour, want: false},
		{name: "missing key", notAfter: 90 * 24 * time.Hour, write: map[string][]byte{"tls.key": nil}, want: false},
		{name: "missing root", notAfter: 90 * 24 * time.Hour, write: map[string][]byte{"ca.crt": nil}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string][]byte{
				"ca.crt":  []byte("root"),
				"tls.crt": selfSignedPEM(t, tc.notAfter),
				"tls.key": []byte("key"),
			}
			for k, v := range tc.write {
				files[k] = v // nil => written empty, which must read as "not provisioned"
			}
			for name, content := range files {
				if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := edgeMaterialFresh(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("edgeMaterialFresh = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("nothing provisioned yet", func(t *testing.T) {
		got, err := edgeMaterialFresh(t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if got {
			t.Error("an empty directory must not read as provisioned")
		}
	})
}

// The nasty case: a reinstalled dispatch mints a NEW root, and the leftover material still looks
// complete and unexpired. Skipping re-provisioning there leaves every edge unable to authenticate
// with three perfectly healthy-looking files on disk.
func TestEdgeMaterialStaleWhenTheDispatchRootChanged(t *testing.T) {
	dir := t.TempDir()
	ourRoot := selfSignedPEM(t, 365*24*time.Hour)
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.crt", ourRoot)
	write("tls.crt", selfSignedPEM(t, 90*24*time.Hour))
	write("tls.key", []byte("key"))

	// Same root: nothing to do.
	fresh, err := edgeMaterialFresh(dir, ourRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Error("material anchored on the current root must be left alone")
	}

	// A DIFFERENT root now serving on the dispatch: the material must be re-provisioned.
	fresh, err = edgeMaterialFresh(dir, selfSignedPEM(t, 365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if fresh {
		t.Error("material anchored on a superseded root must be re-provisioned")
	}
}

// certMatchesKey is what stops a re-run from pairing a freshly generated key with the PREVIOUS
// intermediate still sitting in status — material that fails at the reflector, not here.
func TestCertMatchesKeyRejectsAStaleStatusCert(t *testing.T) {
	keyA, _, err := generateIntermediateKeyAndCSR("edge")
	if err != nil {
		t.Fatal(err)
	}
	keyB, _, err := generateIntermediateKeyAndCSR("edge")
	if err != nil {
		t.Fatal(err)
	}
	certA := selfSignedFromKeyPEM(t, keyA)

	if !certMatchesKey(certA, keyA) {
		t.Error("a cert must match the key it was issued for")
	}
	if certMatchesKey(certA, keyB) {
		t.Error("a cert from another key must be rejected")
	}
}

func findPrefixedLine(s, prefix string) (string, bool) {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, prefix) {
			return l, true
		}
	}
	return "", false
}
