// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Tier-2 failover fences a pool and rebinds its VMs to another one. Two controllers acting on the
// same unhealthy pool would each do it — a second rebind of a disk the first already moved — so
// only one manager may run the reconcilers, whatever the replica count or a rolling restart's
// overlap. And a graceful shutdown must hand over at once, not after the lease expires, or every
// rollout stalls failover for the lease duration.
func TestManager_OneLeaderAndFastHandover(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run inside `nix develop` for the envtest apiserver assets")
	}
	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	start := func(name string) (ctrl.Manager, context.CancelFunc, <-chan error) {
		opts := managerOptions(runtime.NewScheme())
		// In a pod the lease lands in the service account's namespace; out of cluster there is
		// none to default to.
		opts.LeaderElectionNamespace = "default"
		mgr, err := ctrl.NewManager(cfg, opts)
		if err != nil {
			t.Fatalf("new manager %s: %v", name, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- mgr.Start(ctx) }()
		return mgr, cancel, done
	}

	a, stopA, doneA := start("a")
	select {
	case <-a.Elected():
	case <-time.After(30 * time.Second):
		stopA()
		t.Fatal("the first manager never became leader")
	}

	b, stopB, doneB := start("b")
	t.Cleanup(func() { stopB(); <-doneB })
	select {
	case <-b.Elected():
		stopA()
		t.Fatal("the second manager became leader while the first holds the lease")
	case <-time.After(5 * time.Second): // more than two lease retry periods
	}

	stopA()
	if err := <-doneA; err != nil {
		t.Fatalf("first manager: %v", err)
	}
	// Well inside the lease duration (15s): only a released lease is taken over this fast.
	const handover = 8 * time.Second
	select {
	case <-b.Elected():
	case <-time.After(handover):
		t.Fatalf("the second manager was not elected within %v of the first shutting down: the lease was not released", handover)
	}
}
