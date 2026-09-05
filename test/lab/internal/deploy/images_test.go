package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeployImagesMatchCharts guards the dispatchImages / poolImages maps against
// drift from the charts' `images:` blocks. The lab retargets every app image at the
// in-fabric registry via `helm --set-string images.<key>=...` (imageSetArgs); if a
// chart gains, renames, or repaths an image and the map is not updated in lockstep,
// that image silently falls back to its ghcr.io default and the (private) :dev pull
// 403s on the fabric-only nodes — only caught by a full live up. This asserts, at
// `go test`, that the map keys exactly cover the chart's images and that each mapped
// repo name matches the chart ref's <name> (the last path segment before ":dev").
func TestDeployImagesMatchCharts(t *testing.T) {
	root := repoRoot(t)
	for _, tc := range []struct {
		valuesFile string
		want       map[string]string
	}{
		{"charts/ectobase-dispatch/values.yaml", dispatchImages},
		{"charts/ectobase-pool/values.yaml", poolImages},
	} {
		got := chartImages(t, filepath.Join(root, tc.valuesFile))
		if len(got) != len(tc.want) {
			t.Errorf("%s: chart has %d images %v but the deploy map has %d %v — keep them in sync",
				tc.valuesFile, len(got), keysOf(got), len(tc.want), keysOf(tc.want))
		}
		for key, chartName := range got {
			mapped, ok := tc.want[key]
			if !ok {
				t.Errorf("%s: image %q is in the chart but missing from the deploy map "+
					"(add it or the lab pulls it from ghcr.io, not the in-fabric registry)", tc.valuesFile, key)
				continue
			}
			if mapped != chartName {
				t.Errorf("%s: image %q maps to repo %q but the chart ref is %q — they must match",
					tc.valuesFile, key, mapped, chartName)
			}
		}
	}
}

// chartImages parses the `images:` block of a chart values.yaml into key -> <name>
// for ONLY the lab's own images (those whose ref is under ghcr.io/trevex/ectobase/);
// <name> is the ref's last path segment before the ":dev" tag (e.g. "dispatchApiserver"
// -> "dispatch-apiserver"). Upstream images (kine, postgres, …) are excluded — they are
// pulled straight from their real registries over the fabric egress, never retargeted at
// the in-fabric registry. Line-scan (no yaml dep): the block is a flat map of scalar refs.
func chartImages(t *testing.T, valuesFile string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(valuesFile)
	if err != nil {
		t.Fatalf("read %s: %v", valuesFile, err)
	}
	const localPrefix = "ghcr.io/trevex/ectobase/"
	out := map[string]string{}
	inBlock := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "images:") {
			inBlock = true
			continue
		}
		if !inBlock {
			continue
		}
		// The block ends at the next non-indented, non-blank line.
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, val, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		ref := strings.TrimSpace(val)
		if !strings.HasPrefix(ref, localPrefix) {
			continue // upstream image — not served by the in-fabric registry
		}
		name := strings.TrimSuffix(strings.TrimPrefix(ref, localPrefix), ":dev")
		out[strings.TrimSpace(key)] = name
	}
	if len(out) == 0 {
		t.Fatalf("%s: no ghcr.io/trevex/ectobase images found in the images: block", valuesFile)
	}
	return out
}

func keysOf(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
