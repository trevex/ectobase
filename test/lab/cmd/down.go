package cmd

import (
	"github.com/spf13/cobra"

	"github.com/trevex/ectobase/test/lab/topology"
)

var purge bool

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "destroy the clab fabric and remove build/<name>/ (registry cache preserved)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return topology.Down(cmd.Context(), cfg, purge)
	},
}

func init() {
	downCmd.Flags().BoolVar(&purge, "purge", false, "also remove the persistent registry cache")
	rootCmd.AddCommand(downCmd)
}
