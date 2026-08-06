// Package talos renders per-cluster/per-node Talos machine configs (container
// mode) and drives talosctl gen/bootstrap.
package talos

import (
	"strconv"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

// ClusterCtx is the cluster-patch template data.
type ClusterCtx struct {
	*fabric.View
	ClusterName      string
	PodSubnet        string   // fd00:244:<h>::/56
	SvcSubnet        string   // fd00:96:<h>::/108
	NodeNet64        string   // fd00:cafe:<h>::/64
	APIVipCIDR       string   // fd00:cafe:<h>:1::1/128
	RegistryEndpoint string   // e.g. http://[fd00:29::5]:5000
	Upstreams        []string // machine.registries.mirrors keys
	MgmtV6Gateway    string   // the mgmt default the api-vip pod drops (fabric-only egress)
}

// NodeCtx is the node-patch + bgp-peer template data.
type NodeCtx struct {
	*fabric.View
	Hostname     string // <cluster>-<index>
	Identity     string // fd00:cafe:<h>::<index>/128 (dummy0 address)
	IdentityAddr string // bare (BGPPeerConfig routeSource)
	PortSeq      int    // BGP router-id ordinal (unique across ALL clusters)
}

// NewClusterCtx builds the cluster-patch context from the fabric view.
func NewClusterCtx(v *fabric.View, clusterName string) ClusterCtx {
	dc := v.Cfg.Derived.Clusters[clusterName]
	return ClusterCtx{
		View:             v,
		ClusterName:      clusterName,
		PodSubnet:        dc.PodSubnet,
		SvcSubnet:        dc.SvcSubnet,
		NodeNet64:        dc.NodeNet64,
		APIVipCIDR:       dc.APIVip,
		RegistryEndpoint: fabric.RegistryEndpoint,
		Upstreams:        v.Cfg.Fabric.Registry.Upstreams,
		MgmtV6Gateway:    fabric.MgmtV6Gateway,
	}
}

// NewNodeCtx builds a node's patch/peer context.
func NewNodeCtx(v *fabric.View, n config.DerivedNode) NodeCtx {
	return NodeCtx{
		View:         v,
		Hostname:     n.Cluster + "-" + itoa(n.Index),
		Identity:     n.Identity,
		IdentityAddr: n.IdentityAddr,
		PortSeq:      n.PortSeq,
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
