// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

// needsBootstrap reports whether the mTLS client cert/key are absent or empty, i.e. this is a
// first boot before cert-manager has minted the broker's steady-state leaf.
func needsBootstrap(certFile, keyFile string) bool {
	return fileEmptyOrMissing(certFile) || fileEmptyOrMissing(keyFile)
}

// fileEmptyOrMissing reports whether p is unset, absent, or a zero-length file.
func fileEmptyOrMissing(p string) bool {
	if p == "" {
		return true
	}
	fi, err := os.Stat(p)
	return err != nil || fi.Size() == 0
}

// waitForLeaf polls until both cert and key files are present and non-empty, or ctx/timeout.
func waitForLeaf(ctx context.Context, certFile, keyFile string, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if !needsBootstrap(certFile, keyFile) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s/%s", certFile, keyFile)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
