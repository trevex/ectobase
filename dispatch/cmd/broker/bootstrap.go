// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// waitForFile polls until path holds exactly want (the kubelet projecting an updated Secret into a
// mounted volume), or ctx/timeout.
func waitForFile(ctx context.Context, path string, want []byte, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if got, err := os.ReadFile(path); err == nil && bytes.Equal(got, want) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s to hold the new certificate", path)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

// bootstrapClient returns a loader for a dispatch client on the bootstrap-token kubeconfig. It reads
// the file on each call: the enrollment tooling may refresh the token Secret while the broker runs.
// nil when no kubeconfig is configured.
func bootstrapClient(path string, scheme *runtime.Scheme) func() (client.Client, error) {
	if path == "" {
		return nil
	}
	return func() (client.Client, error) {
		cfg, err := clientcmd.BuildConfigFromFlags("", path)
		if err != nil {
			return nil, fmt.Errorf("bootstrap kubeconfig %s: %w", path, err)
		}
		return client.New(cfg, client.Options{Scheme: scheme})
	}
}
