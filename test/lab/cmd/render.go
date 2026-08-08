package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/topology"
)

// loadConfig loads the lab.yaml resolved by root. Root's PersistentPreRunE already
// resolved --config to an ABSOLUTE path in $LAB_CONFIG (before chdir'ing into its
// dir), so use that — re-abs'ing the relative --config flag here would double the path
// (the CWD is now the config's own directory).
func loadConfig() (*config.Config, error) {
	p := os.Getenv("LAB_CONFIG")
	if p == "" {
		var err error
		if p, err = absConfig(cfgPath); err != nil {
			return nil, err
		}
	}
	return config.Load(p)
}

var renderCmd = &cobra.Command{
	Use:   "render",
	Short: "expand all templates into build/<name>/ (clab + kind Cluster configs)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return topology.Render(cmd.Context(), cfg)
	},
}

func init() { rootCmd.AddCommand(renderCmd) }
