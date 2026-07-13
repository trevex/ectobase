package e2e

import (
	"os/exec"
	"testing"
)

// TestKindClusterLifecycle proves the harness can create and delete a kind
// cluster. It is the seed the two-VM e2e (later plan) grows from.
func TestKindClusterLifecycle(t *testing.T) {
	if _, err := exec.LookPath("kind"); err != nil {
		t.Skip("kind not installed")
	}
	up := exec.Command("../../hack/kind-up.sh", "xdp-e2e")
	if out, err := up.CombinedOutput(); err != nil {
		t.Fatalf("kind-up failed: %v\n%s", err, out)
	}
	down := exec.Command("../../hack/kind-down.sh", "xdp-e2e")
	if out, err := down.CombinedOutput(); err != nil {
		t.Fatalf("kind-down failed: %v\n%s", err, out)
	}
}
