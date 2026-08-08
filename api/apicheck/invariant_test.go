// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package apicheck

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAPIModuleIsApimachineryOnly asserts the shared api module never pulls the
// aggregated-apiserver framework (apiserver-kit) or k8s.io/apiserver into any of
// its packages. Those belong exclusively to the central apiserver binary; the
// api module must stay importable by netplane/cni/broker without them. The
// compile-time resource.Object proof lives at central/cmd/apiserver's
// apiserver.Resource(...) calls, not here.
//
// The check shells out to `go list -deps` over the module import-path pattern
// (not ./..., which would be scoped to this package's directory) so it covers
// every api package regardless of the test's working directory.
func TestAPIModuleIsApimachineryOnly(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/trevex/ectobase/api/...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps github.com/trevex/ectobase/api/...: %v\n%s", err, out)
	}
	for _, banned := range []string{
		"go.opendefense.cloud/kit",
		"k8s.io/apiserver",
	} {
		if strings.Contains(string(out), banned) {
			t.Errorf("api module transitively imports %q — it must stay apimachinery-only (move the offending import into central)", banned)
		}
	}
}
