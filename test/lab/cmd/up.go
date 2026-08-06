package cmd

import (
	"github.com/spf13/cobra"

	"github.com/trevex/ectobase/test/lab/topology"
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "render, deploy the clab fabric, bootstrap clusters + Cilium, deploy ectobase",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return topology.Up(cmd.Context(), cfg)
	},
}

func init() { rootCmd.AddCommand(upCmd) }
