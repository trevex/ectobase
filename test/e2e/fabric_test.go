package e2e

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestUnderlayInferenceOnFabric brings up the lean IPv6 BGP-unnumbered containerlab
// fabric (hack/clab/ipv6-fabric.clab.yml) and asserts that a kind node running the
// flowplane dataplane INFERS an underlay /64 matching the /64 the fabric put on its
// dummy0. This is the end-to-end proof that flowplane's underlay inference agrees with
// the fabric's addressing.
//
// It SKIPs (never fails) when containerlab or kind is not installed — this machine
// (and CI without a container runtime) cannot deploy the fabric. The skip-style
// mirrors TestKindClusterLifecycle in kind_test.go.
//
// What it checks: the control-plane kind node (k01-control-plane), whose clab `exec`
// gave dummy0 the address fd00:db8:0:1::1/64, must have flowplane report
// "inferred underlay prefix: fd00:db8:0:1::/64".
func TestUnderlayInferenceOnFabric(t *testing.T) {
	if _, err := exec.LookPath("containerlab"); err != nil {
		t.Skip("containerlab not installed")
	}
	if _, err := exec.LookPath("kind"); err != nil {
		t.Skip("kind not installed")
	}
	// docker exec is how we reach the kind node; without a runtime there is nothing
	// to deploy into, so treat it like missing tooling and skip.
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}

	// The kind node container clab attaches (see ipv6-fabric.clab.yml) and the /64
	// its dummy0 carries. flowplane must infer exactly this /64.
	const (
		kindNode       = "k01-control-plane"
		wantPrefix     = "fd00:db8:0:1::/64"
		xdpImage       = "ghcr.io/trevex/ectobase/flowplane:dev"
		deployTimeout  = 15 * time.Minute
		commandTimeout = 5 * time.Minute
	)

	// Bring the fabric up; always tear it down.
	up := exec.Command("../../hack/clab-up.sh")
	up.Env = testEnv()
	if out, err := runWithTimeout(up, deployTimeout); err != nil {
		t.Fatalf("clab-up failed: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		down := exec.Command("../../hack/clab-down.sh")
		down.Env = testEnv()
		if out, err := runWithTimeout(down, commandTimeout); err != nil {
			t.Logf("clab-down failed (leaked lab may need manual cleanup): %v\n%s", err, out)
		}
	})

	// Sanity: confirm the fabric put the expected /64 on the kind node's dummy0.
	// If this fails the topology `exec` did not run — a fabric problem, not flowplane.
	addr := exec.Command("docker", "exec", kindNode, "ip", "-6", "-o", "addr", "show", "dev", "dummy0")
	if out, err := runWithTimeout(addr, commandTimeout); err != nil {
		t.Fatalf("reading dummy0 on %s failed: %v\n%s", kindNode, err, out)
	} else if !strings.Contains(out, "fd00:db8:0:1::1/64") {
		t.Fatalf("kind node %s dummy0 missing the fabric /64; got:\n%s", kindNode, out)
	}

	// Run `flowplane infer-underlay` in the kind node's netns via the ectobase/flowplane
	// image (network-mode: container:<kind-node> puts it in the same netns, so it
	// sees the same dummy0). This is the observable surface the test asserts on.
	infer := exec.Command("docker", "run", "--rm",
		"--network", "container:"+kindNode,
		xdpImage, "infer-underlay")
	out, err := runWithTimeout(infer, commandTimeout)
	if err != nil {
		t.Fatalf("`flowplane infer-underlay` on %s failed: %v\n%s", kindNode, err, out)
	}
	want := "inferred underlay prefix: " + wantPrefix
	if !strings.Contains(out, want) {
		t.Fatalf("flowplane inferred the wrong underlay /64 on %s\nwant substring: %q\ngot:\n%s",
			kindNode, want, out)
	}
	t.Logf("flowplane on %s inferred underlay %s (matches fabric dummy0)", kindNode, wantPrefix)
}

// runWithTimeout runs cmd, killing it (and returning an error) if it exceeds d.
func runWithTimeout(cmd *exec.Cmd, d time.Duration) (string, error) {
	// Wire combined stdout+stderr into a buffer BEFORE Start (required by os/exec).
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(d):
		_ = cmd.Process.Kill()
		return buf.String(), &timeoutError{d}
	}
}

type timeoutError struct{ d time.Duration }

func (e *timeoutError) Error() string { return "timed out after " + e.d.String() }

// testEnv returns the current process environment; a hook for future overrides
// (e.g. CLAB=... to use a sudo wrapper) without changing call sites.
func testEnv() []string { return nil }
