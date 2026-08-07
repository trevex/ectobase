package cmd

import (
	"github.com/spf13/cobra"

	"github.com/trevex/ectobase/test/lab/topology"
)

var tier2Cmd = &cobra.Command{
	Use:   "tier2",
	Short: "deploy the Tier-2 (VM live-migration + fencing) prerequisites",
	Long: "KubeVirt + CDI + the flowplane network binding on every compute cluster, plus the\n" +
		"ceph fsid wired into the central controller's ceph-csi fence actuator. Requires\n" +
		"fabric.ceph.enabled, an already-up fabric, and that `lab ceph` has already run\n" +
		"(the fsid is read from build/<name>/ceph.env).",
}

var tier2UpCmd = &cobra.Command{
	Use:   "up",
	Short: "install KubeVirt + CDI and wire the central controller fsid",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return topology.Tier2(cmd.Context(), cfg)
	},
}

func init() {
	tier2Cmd.AddCommand(tier2UpCmd)
	rootCmd.AddCommand(tier2Cmd)
}
