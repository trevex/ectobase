//go:build live

// Package livetest is the live connectivity suite for the Talos lab fabric. It
// runs against an already-up fabric (`lab up`) and needs root (all clab / kubectl
// access is root-owned), so every test is gated behind the `live` build tag and
// executed by `lab test` (which shells out to `go test -tags live ./livetest/...`).
//
// The assertions here codify checks the operator has already verified by hand on
// the live fabric; they are NOT run in CI. Each test resolves every address from
// the config package (config.Load + fabric consts) — nothing is hardcoded.
package livetest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// configPath resolves the lab.yaml the fabric was brought up with: $LAB_CONFIG
// (set by the root `lab` command) else ./lab.yaml (the module dir is the config
// dir, since `lab test` runs go test from there).
func configPath() string {
	if v := os.Getenv("LAB_CONFIG"); v != "" {
		return v
	}
	return "lab.yaml"
}

// loadConfig loads + derives the lab config, failing the test on error.
func loadConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(configPath())
	require.NoError(t, err, "load lab config from %s", configPath())
	return cfg
}

// buildDir is build/<name>/, anchored on $LAB_CONFIG's directory (the module dir),
// NOT the CWD: `go test` runs each test binary from the livetest package dir, so a
// CWD-relative path would miss the build tree.
func buildDir(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(configPath()), "build", cfg.Name)
}

// kubeconfigPath is the root-owned per-cluster kubeconfig under build/<name>/.
func kubeconfigPath(cfg *config.Config, cluster string) string {
	return filepath.Join(buildDir(cfg), cluster+".kubeconfig")
}

// requireFabricUp skips the test when the dispatch kubeconfig is missing — i.e.
// the fabric was never brought up, so there is nothing to assert against.
func requireFabricUp(t *testing.T, cfg *config.Config) {
	t.Helper()
	kc := kubeconfigPath(cfg, "dispatch")
	if _, err := os.Stat(kc); err != nil {
		t.Skipf("fabric not up: %s missing (run `lab up`)", kc)
	}
}

// nodeContainer is the docker container name of a cluster node. With the kind
// substrate the node is a kind-created container (<cluster>-control-plane /
// -worker[N]) with NO clab-<lab>- prefix — see DerivedNode.KindContainer.
func nodeContainer(cfg *config.Config, node config.DerivedNode) string {
	return node.KindContainer()
}

// switchContainer is the containerlab container name of a fabric switch (sw1/sw2).
func switchContainer(cfg *config.Config, sw string) string {
	return clab.ContainerName(cfg.Name, sw)
}

// allNodes flattens every cluster's derived nodes in declaration order.
func allNodes(cfg *config.Config) []config.DerivedNode {
	var out []config.DerivedNode
	for _, cl := range cfg.Fabric.Clusters {
		out = append(out, cfg.Derived.Clusters[cl.Name].Nodes...)
	}
	return out
}

// dockerPID resolves a container's host PID via `docker inspect`, for nsenter.
func dockerPID(ctx context.Context, container string) (string, error) {
	out, err := exec.OutputStr(ctx, "docker", "inspect", "-f", "{{.State.Pid}}", container)
	return strings.TrimSpace(out), err
}

// nodeNetnsExec runs a command inside a container's network namespace via
// `sudo nsenter -t <pid> -n <args>`, returning combined stdout. The container's
// host PID is resolved with `docker inspect`.
func nodeNetnsExec(ctx context.Context, container string, args ...string) (string, error) {
	pid, err := dockerPID(ctx, container)
	if err != nil {
		return "", err
	}
	nsArgs := append([]string{"nsenter", "-t", pid, "-n"}, args...)
	out, err := exec.SudoOutput(ctx, nsArgs...)
	return string(out), err
}

// kubectl runs `sudo kubectl --kubeconfig build/<name>/<cluster>.kubeconfig <args>`
// (root-owned kubeconfig), returning combined stdout.
func kubectl(ctx context.Context, cfg *config.Config, cluster string, args ...string) (string, error) {
	full := append([]string{"kubectl", "--kubeconfig", kubeconfigPath(cfg, cluster)}, args...)
	out, err := exec.SudoOutput(ctx, full...)
	return string(out), err
}

// eventually polls fn until it returns nil (success) or the timeout elapses,
// waiting tick between attempts. It fails the test with the last error on
// timeout. testify 1.5.1 lacks EventuallyWithT, so this is the bounded-retry
// primitive the flaky assertions use.
func eventually(t *testing.T, timeout, tick time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for {
		if last = fn(); last == nil {
			return
		}
		if time.Now().After(deadline) {
			require.NoError(t, last, "condition not met within %s", timeout)
			return
		}
		time.Sleep(tick)
	}
}
