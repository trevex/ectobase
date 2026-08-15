package cmd

import (
	"github.com/spf13/cobra"

	"github.com/trevex/ectobase/test/lab/topology"
)

var cephPurge bool

var cephCmd = &cobra.Command{
	Use:   "ceph",
	Short: "deploy Ceph (pool + ceph-csi-rbd + csi-addons) onto an already-up fabric",
	Long: "Create the RBD pool on the shared clab ceph node, install external ceph-csi-rbd on\n" +
		"every cluster, wire the csi-addons controller + sidecar into the dispatch (fence\n" +
		"executor) provisioner, and apply the per-node krbd fixups. Requires\n" +
		"fabric.ceph.enabled and an already-up fabric (all cluster kubeconfigs present).",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return topology.Ceph(cmd.Context(), cfg, cephPurge)
	},
}

func init() {
	cephCmd.Flags().BoolVar(&cephPurge, "purge", false, "uninstall ceph-csi + csi-addons and delete their namespaces")
	rootCmd.AddCommand(cephCmd)
}
