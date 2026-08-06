// Package cmd is the `lab` CLI: it stands up a multi-cluster Talos IPv6-BGP
// fabric on containerlab and deploys the ectobase substrate onto it.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/trevex/ectobase/test/lab/internal/log"
)

var (
	cfgPath string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "lab",
	Short: "ectobase Talos fabric lab harness",
	// Every subprocess (render, tests) reads $LAB_CONFIG; set it from --config once here.
	PersistentPreRunE: func(*cobra.Command, []string) error {
		log.InitLogging(verbose)
		abs, err := absConfig(cfgPath)
		if err != nil {
			return err
		}
		return os.Setenv("LAB_CONFIG", abs)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", defaultConfigPath(), "path to lab.yaml (or $LAB_CONFIG)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "debug logging")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
