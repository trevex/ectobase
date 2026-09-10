// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNeedsBootstrap(t *testing.T) {
	dir := t.TempDir()

	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, []byte("cert-bytes"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("key-bytes"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	emptyFile := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyFile, nil, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	missingFile := filepath.Join(dir, "does-not-exist")

	tests := []struct {
		name     string
		certFile string
		keyFile  string
		want     bool
	}{
		{"present non-empty cert+key", certFile, keyFile, false},
		{"missing cert", missingFile, keyFile, true},
		{"missing key", certFile, missingFile, true},
		{"empty cert", emptyFile, keyFile, true},
		{"empty key", certFile, emptyFile, true},
		{"empty cert path", "", keyFile, true},
		{"empty key path", certFile, "", true},
		{"both empty paths", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsBootstrap(tc.certFile, tc.keyFile); got != tc.want {
				t.Fatalf("needsBootstrap(%q, %q) = %v, want %v", tc.certFile, tc.keyFile, got, tc.want)
			}
		})
	}
}
