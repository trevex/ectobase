package cmd

import (
	"github.com/spf13/cobra"

	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// testCmd runs the //go:build live connectivity suite against the already-up
// fabric. It shells out to `go test -tags live ./livetest/...` from the module
// root (root chdir'd to the config dir, which IS the module root, so the relative
// package pattern resolves). The live tests themselves need sudo + the running
// fabric; they skip when the fabric is not up.
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "run the live connectivity suite (go test -tags live) against the up fabric",
	RunE: func(cmd *cobra.Command, _ []string) error {
		// -timeout guards against a single hung live test consuming the whole go-test
		// budget: the suite runs ~8m, so 25m leaves headroom while still failing a wedged
		// test cleanly (with its own diagnostics) instead of as a package-level panic.
		return exec.Run(cmd.Context(), "go", "test",
			"-tags", "live", "-timeout", "25m", "-count=1", "-v", "./livetest/...")
	},
}

func init() { rootCmd.AddCommand(testCmd) }
