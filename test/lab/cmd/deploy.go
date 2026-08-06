package cmd

import (
	"github.com/spf13/cobra"

	"github.com/trevex/ectobase/test/lab/topology"
)

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "deploy (or re-deploy) the ectobase substrate onto an already-up fabric",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return topology.Deploy(cmd.Context(), cfg)
	},
}

func init() { rootCmd.AddCommand(deployCmd) }
