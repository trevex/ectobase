// Package fabric computes the fixed IPv6-fabric addressing (constants the
// simplified lab.yaml does not expose) plus the flattened multi-cluster node
// list and the WAN masq/return-route set, as one view consumed by every
// topology template (clab, VyOS, Talos, Cilium).
package fabric

import (
	"github.com/trevex/ectobase/test/lab/internal/config"
)

// Fixed fabric constants (from the icn/sandbox fabric defaults). The simplified
// lab.yaml does not expose these; every cluster on the shared fabric uses them.
const (
	TaygaNet      = "fd00:64"              // nat64 edge links: fd00:64:1::/64, fd00:64:2::/64
	WanNet        = "fd00:29"              // WAN segment fd00:29::/64; wan ::1, edge1 ::11, edge2 ::12
	MgmtV6Subnet  = "3fff:172:20:20::/64"  // clab mgmt docker network v6 subnet (host NAT66's it → real uplink)
	MgmtV6Gateway = "3fff:172:20:20::1"    // clab mgmt gateway; nodes drop its default so egress is fabric-only
	EdgeLoopback  = "fd00:ffff"            // edge DNS64 loopbacks: fd00:ffff::e1, fd00:ffff::e2
	DNSUpstream   = "2606:4700:4700::1111" // DNS64 upstream
	WanGwV4       = "172.29.0.1"           // wan bridge v4 gateway
	NodeAggr      = "fd00:cafe::/32"       // aggregate of every cluster's /48 node identities (fd00:cafe:<h>::/48)
	LoopAggr      = "fd00:ffff::/32"       // aggregate of the edge loopbacks
	RegistryAddr  = "fd00:29::5"           // registry node's address on the WAN segment (fd00:29::/64)
	RegistryPort  = "5000"                 // registry:2 default listen port

	JumpHostAddr = "fd00:29::100" // host end of the WAN-segment jump veth (replaces the mgmt route)
	JumpVia      = "fd00:29::1"   // the wan container's WAN-segment addr; it ECMPs NodeAggr → edges
	JumpIface    = "ectojump"     // host-side ifname of the clab host:-endpoint veth
)

// RegistryEndpoint is the in-fabric mirror target the Talos nodes point at.
var RegistryEndpoint = "http://[" + RegistryAddr + "]:" + RegistryPort

// View is the template data for all topology templates.
type View struct {
	Cfg   *config.Config
	Nodes []config.DerivedNode // flattened across clusters, in cluster-declaration order (PortSeq ascending)
	Wan   Wan
}

type Wan struct {
	V4Addr string
	V6Addr string
	MasqV4 []string
	MasqV6 []string
	Routes []Route
}

type Route struct {
	Prefix   string
	NextHops []string
}

// Convenience accessors the templates use.
func (v *View) Name() string              { return v.Cfg.Name }
func (v *View) Images() map[string]string { return v.Cfg.Images }
func (v *View) NAT64Prefix() string       { return v.Cfg.Fabric.NAT64Prefix }

// Const accessors so templates can reference the fixed fabric constants ({{ .TaygaNet }}).
func (v *View) TaygaNet() string     { return TaygaNet }
func (v *View) WanNet() string       { return WanNet }
func (v *View) EdgeLoopback() string { return EdgeLoopback }
func (v *View) DNSUpstream() string  { return DNSUpstream }
func (v *View) WanGwV4() string      { return WanGwV4 }
func (v *View) RegistryAddr() string { return RegistryAddr }

// RegistryHost is the in-fabric registry as host:port (bracketed v6, no scheme) — the
// kind containerd registry-mirror endpoint, the analog of the Talos mirror target.
func (v *View) RegistryHost() string { return "[" + RegistryAddr + "]:" + RegistryPort }

// NodeUplinks is the space-separated fabric uplink ifaces of a cluster node (the clab
// links wire each node's eth1↔sw1 + eth2↔sw2). Written to /etc/fabric/uplinks for the
// kind-node-fabric preboot's FRR eBGP + RA-default acceptance.
func (v *View) NodeUplinks() string { return "eth1 eth2" }

// ClusterNames lists the clusters in declaration order — one clab k8s-kind lifecycle
// node is rendered per cluster (kind cluster name = cluster name), while the per-node
// kind containers are separate ext-container link endpoints.
func (v *View) ClusterNames() []string {
	out := make([]string, 0, len(v.Cfg.Fabric.Clusters))
	for _, cl := range v.Cfg.Fabric.Clusters {
		out = append(out, cl.Name)
	}
	return out
}
func (v *View) MgmtV6Subnet() string  { return MgmtV6Subnet }
func (v *View) MgmtV6Gateway() string { return MgmtV6Gateway }

// Ceph accessors: the optional fabric-attached Ceph/demo storage node. The clab
// + switch templates guard the ceph blocks on CephEnabled; the addresses come
// from the fabric-level derivation (hash48("ceph")).
func (v *View) CephEnabled() bool   { return v.Cfg.Fabric.Ceph.Enabled }
func (v *View) CephNet64() string   { return v.Cfg.Derived.CephNet64 }
func (v *View) CephMonAddr() string { return v.Cfg.Derived.CephMonAddr }

// CephMonEndpoint is the mon's messenger-v2 endpoint (bracketed v6 + port 3300).
func (v *View) CephMonEndpoint() string { return "[" + v.Cfg.Derived.CephMonAddr + "]:3300" }

// CephPortSeq is the switch host-port index for the ceph uplink: it sits after
// every cluster node (total nodes + 1), so the switch eth is eth{{add 2 CephPortSeq}}
// — the next free host port on each ToR, colliding with no node port.
func (v *View) CephPortSeq() int { return v.Cfg.TotalNodes() + 1 }

// AS + aggregate accessors the VyOS templates reference.
func (v *View) ASEdge() int      { return v.Cfg.Fabric.AS.Edge }
func (v *View) ASSwitch() int    { return v.Cfg.Fabric.AS.Switch }
func (v *View) ASHost() int      { return v.Cfg.Fabric.AS.Host }
func (v *View) NodeAggr() string { return NodeAggr }
func (v *View) LoopAggr() string { return LoopAggr }

// Build assembles the view: flatten nodes in declaration order, then compute the
// WAN egress (masquerade the fabric aggregates out the uplink; ECMP return routes
// back via both edges on the WAN segment).
func Build(cfg *config.Config) *View {
	v := &View{Cfg: cfg}
	for _, cl := range cfg.Fabric.Clusters { // ordered slice → deterministic
		v.Nodes = append(v.Nodes, cfg.Derived.Clusters[cl.Name].Nodes...)
	}
	edges := []string{WanNet + "::11", WanNet + "::12"}
	v.Wan = Wan{
		V4Addr: WanGwV4 + "/24",
		V6Addr: WanNet + "::1/64",
		// /16 covers the WAN /24 + the tayga NAT64 pools 172.29.64/65.0/24.
		MasqV4: []string{"172.29.0.0/16"},
		// Pure /128-VTEP model: only node identities (NodeAggr), edge loopbacks
		// (LoopAggr), and the WAN segment need masq/return — no RA /64 aggregate.
		MasqV6: []string{NodeAggr, LoopAggr, WanNet + "::/64"},
		Routes: []Route{
			{Prefix: NodeAggr, NextHops: edges},
			{Prefix: LoopAggr, NextHops: edges},
		},
	}
	return v
}
