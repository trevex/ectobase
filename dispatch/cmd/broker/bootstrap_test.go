// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// After enrolling, the broker writes its certificate to the Secret and must wait for the kubelet to
// project THAT certificate into the mounted file before it builds its dispatch client. A file that
// merely exists is not enough: on a cutover it is the old, rejected certificate.
func TestWaitForFile_WaitsForTheWantedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.WriteFile(path, []byte("old certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(path, []byte("new certificate"), 0o600)
	}()
	if err := waitForFile(context.Background(), path, []byte("new certificate"), time.Second, 5*time.Millisecond); err != nil {
		t.Fatalf("waitForFile: %v", err)
	}
}

func TestWaitForFile_TimesOutOnTheOldContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.WriteFile(path, []byte("old certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := waitForFile(context.Background(), path, []byte("new certificate"), 30*time.Millisecond, 5*time.Millisecond); err == nil {
		t.Fatal("an old file must not satisfy the wait")
	}
	if err := waitForFile(context.Background(), filepath.Join(t.TempDir(), "missing"), []byte("x"), 30*time.Millisecond, 5*time.Millisecond); err == nil {
		t.Fatal("a missing file must not satisfy the wait")
	}
}
