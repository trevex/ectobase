// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

//go:build kine

// Package test's kine build tag proves the aggregated apiserver can run with
// kine (over Postgres) as its ONLY storage backend — no etcd (design M1).
//
// It reuses the envtest harness (front kube-apiserver, certs, client) but
// overrides OUR aggregated apiserver's --etcd-servers to point at the kine
// endpoint via SetAPIServerExtraArgs. The harness merges custom args over its
// defaults (MergeArgs), so this fully replaces the harness's embedded-etcd
// endpoint for our server. Persistence is then proven by querying the kine
// backing table in Postgres directly.
//
// Run:
//
//	bash hack/kine-up.sh
//	KINE_ENDPOINT=http://127.0.0.1:2379 go test -tags kine ./test/ -run TestKineDurability -v
//	bash hack/kine-down.sh
package test

import (
	"context"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kitenvtest "go.opendefense.cloud/kit/envtest"

	"github.com/trevex/ectobase/api/platform/install"
	"github.com/trevex/ectobase/api/platform/v1alpha1"
)

func TestKineDurability(t *testing.T) {
	kineEndpoint := os.Getenv("KINE_ENDPOINT")
	if kineEndpoint == "" {
		kineEndpoint = "http://127.0.0.1:2379"
	}
	// Skip unless kine is actually reachable.
	u, err := url.Parse(kineEndpoint)
	if err != nil {
		t.Fatalf("parse KINE_ENDPOINT %q: %v", kineEndpoint, err)
	}
	conn, err := net.DialTimeout("tcp", u.Host, 2*time.Second)
	if err != nil {
		t.Skipf("kine not reachable at %s (%v); run hack/kine-up.sh first", kineEndpoint, err)
	}
	_ = conn.Close()

	// The envtest harness builds the apiserver binary with `-mod mod`, which
	// conflicts with the repo's go.work workspace mode. Disable workspace mode.
	t.Setenv("GOWORK", "off")

	scheme := runtime.NewScheme()
	install.Install(scheme)
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register apiregistration scheme: %v", err)
	}

	env, err := kitenvtest.NewEnvironment(
		"github.com/trevex/ectobase/hub/cmd/apiserver",
		nil,
		[]string{filepath.Join(".", "fixtures")},
	)
	if err != nil {
		t.Fatalf("NewEnvironment: %v", err)
	}

	// Point OUR aggregated apiserver's storage at kine instead of the harness's
	// embedded etcd. MergeArgs gives these custom args precedence over the
	// harness default --etcd-servers.
	env.SetAPIServerExtraArgs(kitenvtest.ProcessArgs{}.Set("etcd-servers", kineEndpoint))

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

	c, err := client.New(env.GetRESTConfig(), client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	ctx := kitenvtest.Context()

	// --- Create a named ClusterPool served by the kine-backed apiserver. ---
	pool := &v1alpha1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pool-durable",
		},
		Spec: v1alpha1.ClusterPoolSpec{
			Region: "eu",
		},
	}
	if err := c.Create(ctx, pool); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// --- Assert Get round-trips through the kine-backed store. ---
	got := &v1alpha1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pool), got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Spec.Region != "eu" {
		t.Fatalf("Get: expected Region=eu, got %q", got.Spec.Region)
	}

	// --- PROVE Postgres persistence: the object key must exist in the kine
	// backing table. This is the "no etcd for our data" evidence. ---
	count, err := pgRowCount(ctx, "select count(*) from kine where name like '%clusterpools%pool-durable%' and deleted = 0;")
	if err != nil {
		t.Fatalf("query kine backing table: %v", err)
	}
	if count < 1 {
		t.Fatalf("expected >= 1 kine row for pool-durable, got %d — object was NOT persisted to Postgres", count)
	}
	t.Logf("kine/Postgres row count for pool-durable = %d (persisted, no etcd)", count)

	// Cleanup the object (best effort — harness teardown does not touch kine).
	t.Cleanup(func() {
		_ = c.Delete(context.Background(), pool)
	})
}

// pgRowCount runs a scalar count query against the kine Postgres DB via the
// central-pg docker container (matching hack/kine-up.sh).
func pgRowCount(ctx context.Context, query string) (int, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", "central-pg",
		"psql", "-U", "postgres", "-d", "kine", "-tAc", query)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(out))
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return n, nil
}
