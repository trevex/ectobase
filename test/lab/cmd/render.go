package cmd

import (
	"github.com/spf13/cobra"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/topology"
)

// loadConfig loads the lab.yaml resolved by root (via $LAB_CONFIG).
func loadConfig() (*config.Config, error) {
	abs, err := absConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	return config.Load(abs)
}

var renderCmd = &cobra.Command{
	Use:   "render",
	Short: "expand all templates into build/<name>/ (talosctl gen per cluster)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return topology.Render(cmd.Context(), cfg)
	},
}

func init() { rootCmd.AddCommand(renderCmd) }
