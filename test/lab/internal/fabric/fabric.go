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
	TaygaNet     = "fd00:64"              // nat64 edge links: fd00:64:1::/64, fd00:64:2::/64
	WanNet       = "fd00:29"              // WAN segment fd00:29::/64; wan ::1, edge1 ::11, edge2 ::12
	RAPrefix     = "fd00:db8"             // switch RA /64s: fd00:db8:0:<portSeq>::/64 (matches DerivedNode.RA64)
	EdgeLoopback = "fd00:ffff"            // edge DNS64 loopbacks: fd00:ffff::e1, fd00:ffff::e2
	DNSUpstream  = "2606:4700:4700::1111" // DNS64 upstream
	WanGwV4      = "172.29.0.1"           // wan bridge v4 gateway
	NodeAggr     = "fd00:cafe::/16"       // aggregate of every cluster's /48 node identities
	RAAggr       = "fd00:db8::/32"        // aggregate of every switch RA /64
	LoopAggr     = "fd00:ffff::/32"       // aggregate of the edge loopbacks
)

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
func (v *View) RAPrefix() string     { return RAPrefix }
func (v *View) EdgeLoopback() string { return EdgeLoopback }
func (v *View) DNSUpstream() string  { return DNSUpstream }
func (v *View) WanGwV4() string      { return WanGwV4 }

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
		MasqV6: []string{NodeAggr, RAAggr, LoopAggr, WanNet + "::/64"},
		Routes: []Route{
			{Prefix: NodeAggr, NextHops: edges},
			{Prefix: RAAggr, NextHops: edges},
			{Prefix: LoopAggr, NextHops: edges},
		},
	}
	return v
}
