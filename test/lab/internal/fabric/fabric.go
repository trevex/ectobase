// Package fabric computes the fixed IPv6-fabric addressing (constants the
// simplified lab.yaml does not expose) plus the flattened multi-cluster node
// list and the WAN masq/return-route set, as one view consumed by every
// topology template (clab, FRR, Cilium).
package fabric

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/trevex/ectobase/test/lab/internal/config"
)

// Fixed fabric constants (from the icn/sandbox fabric defaults). The simplified
// lab.yaml does not expose these; every cluster on the shared fabric uses them.
const (
	TaygaNet     = "fd00:64"        // nat64 edge links: fd00:64:1::/64, fd00:64:2::/64
	WanNet       = "fd00:29"        // WAN segment fd00:29::/64; wan ::1, edge1 ::11, edge2 ::12
	EdgeLoopback = "fd00:ffff"      // edge loopbacks: fd00:ffff::e1, fd00:ffff::e2
	WanGwV4      = "172.29.0.1"     // wan bridge v4 gateway
	NodeAggr     = "fd00:cafe::/32" // aggregate of every cluster's /48 node identities (fd00:cafe:<h>::/48)
	PodAggr      = "fd00:244::/32"  // aggregate of every cluster's Cilium pod pool (fd00:244:<h>::/56)
	LoopAggr     = "fd00:ffff::/32" // aggregate of the edge loopbacks
	RegistryAddr = "fd00:29::5"     // registry node's address on the WAN segment (fd00:29::/64)
	RegistryPort = "5000"           // registry:2 default listen port

	JumpHostAddr = "fd00:29::100" // host end of the WAN-segment jump veth (replaces the mgmt route)
	JumpVia      = "fd00:29::1"   // the wan container's WAN-segment addr; it ECMPs NodeAggr → edges
	JumpIface    = "ectojump"     // host-side ifname of the clab host:-endpoint veth
)

// RegistryHost is the in-fabric registry's routable [host]:port authority, as it
// appears in an image reference ([fd00:29::5]:5000/trevex/ectobase/<name>:dev). The
// nodes pull the locally-built :dev app images from here directly (no ghcr.io mirror
// redirection); the cluster-patch marks this host plain-HTTP so containerd speaks h2c.
var RegistryHost = "[" + RegistryAddr + "]:" + RegistryPort

// RegistryEndpoint is the plain-HTTP endpoint URL for RegistryHost (the hosts.toml
// endpoint the Talos nodes talk to registry:2 over).
var RegistryEndpoint = "http://" + RegistryHost

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
func (v *View) WanGwV4() string      { return WanGwV4 }
func (v *View) RegistryAddr() string { return RegistryAddr }

// ClusterNames lists the clusters in declaration order — each cluster's nodes render
// as directly-wired, container-mode Talos clab nodes (P6 substrate); there is no
// separate per-cluster lifecycle node or intermediate node-creation step.
func (v *View) ClusterNames() []string {
	out := make([]string, 0, len(v.Cfg.Fabric.Clusters))
	for _, cl := range v.Cfg.Fabric.Clusters {
		out = append(out, cl.Name)
	}
	return out
}

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

// AS + aggregate accessors the FRR templates reference.
func (v *View) ASEdge() int      { return v.Cfg.Fabric.AS.Edge }
func (v *View) ASSwitch() int    { return v.Cfg.Fabric.AS.Switch }
func (v *View) ASHost() int      { return v.Cfg.Fabric.AS.Host }
func (v *View) NodeAggr() string { return NodeAggr }
func (v *View) LoopAggr() string { return LoopAggr }

// ClabView wraps the View with the render-time host paths the clab topology template
// needs (kept OFF View so View stays pure/deterministic for the golden tests — the
// modules dir is host-dependent). The View methods promote through the embed, so the
// clab template still reaches .Name/.Nodes/.Images/... unchanged.
type ClabView struct {
	*View
	// ModulesDir is the host kernel-modules dir bound read-only into each Talos node
	// for the kubelet (container-mode Talos ships no modules of its own).
	ModulesDir string
}

// ModulesDir returns the host kernel-modules directory for the running kernel. It
// probes the standard location and the NixOS booted-system path; if neither holds the
// running kernel's modules it falls back to an empty per-lab dir under build/<name> so
// the clab bind won't fail (a degraded mode with no real modules — a live A4 concern).
func ModulesDir(labName string) string {
	rel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		slog.Debug("read kernel osrelease failed", "err", err)
	}
	kver := strings.TrimRight(string(rel), "\n ")
	for _, cand := range []string{"/lib/modules", "/run/booted-system/kernel-modules/lib/modules"} {
		if st, err := os.Stat(filepath.Join(cand, kver)); err == nil && st.IsDir() {
			return cand
		}
	}
	fallback := filepath.Join("build", labName, "modules")
	if abs, err := filepath.Abs(fallback); err == nil {
		fallback = abs
	}
	if err := os.MkdirAll(fallback, 0o755); err != nil {
		slog.Warn("create fallback modules dir failed", "dir", fallback, "err", err)
	}
	return fallback
}

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
