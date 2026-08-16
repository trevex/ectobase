package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReflectorPortsMatchCharts guards against the class of bug where the lab's helm
// --set ports drift from the chart defaults: the lab hardcodes reflectorAdmin :1339 and
// reflectorAddress :1338, which MUST equal charts/ectobase-{dispatch,pool}/values.yaml.
// A mismatch silently wedges fencing / route distribution at runtime (only caught by a
// full live sweep) — this asserts it at `go test` instead.
func TestReflectorPortsMatchCharts(t *testing.T) {
	root := repoRoot(t)
	for _, tc := range []struct {
		valuesFile, key, wantPort string
	}{
		{"charts/ectobase-dispatch/values.yaml", "reflectorAdmin", reflectorAdminPort},
		{"charts/ectobase-pool/values.yaml", "reflectorAddress", reflectorSessionPort},
	} {
		got := chartValuePort(t, filepath.Join(root, tc.valuesFile), tc.key)
		if got != tc.wantPort {
			t.Errorf("%s: chart %q port = %q but the lab const is %q — they must match "+
				"(update the const in ectobase.go and the chart values together)",
				tc.valuesFile, tc.key, got, tc.wantPort)
		}
	}
}

// repoRoot walks up from the test's working directory to the go.work at the repo root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.work not found walking up from test dir (cannot locate repo root)")
		}
		dir = parent
	}
}

// chartValuePort reads a top-level `key: "[addr]:port"` value from a chart values.yaml and
// returns the trailing port. Line-scan (no yaml dep) — the values are simple scalars.
func chartValuePort(t *testing.T, valuesFile, key string) string {
	t.Helper()
	raw, err := os.ReadFile(valuesFile)
	if err != nil {
		t.Fatalf("read %s: %v", valuesFile, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, key+":") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(trimmed, key+":"))
		val = strings.Trim(val, `"'`) // strip surrounding quotes
		// val is [fd00:db8:0:1::1]:PORT — the port is after the final colon.
		if i := strings.LastIndex(val, ":"); i >= 0 {
			return val[i+1:]
		}
		t.Fatalf("%s: value %q for key %q has no port", valuesFile, val, key)
	}
	t.Fatalf("%s: key %q not found", valuesFile, key)
	return ""
}
