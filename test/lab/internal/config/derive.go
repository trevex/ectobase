package config

import (
	"fmt"
	"hash/fnv"
)

type Derived struct {
	Clusters map[string]DerivedCluster
}

type DerivedCluster struct {
	Hash       uint16 // FNV-1a group of the cluster name (the <h> in fd00:cafe:<h>)
	Prefix48   string // fd00:cafe:<h>::/48
	NodeNet64  string // fd00:cafe:<h>::/64 (nodeIP validSubnets + etcd advertisedSubnets)
	APIVip     string // fd00:cafe:<h>:1::1/128
	APIVipAddr string // fd00:cafe:<h>:1::1 (bare, for the https://[vip]:6443 endpoint)
	PodSubnet  string // fd00:244:<h>::/56 (per-cluster Cilium pod pool)
	SvcSubnet  string // fd00:96:<h>::/108 (per-cluster service CIDR)
	Nodes      []DerivedNode
}

type DerivedNode struct {
	Cluster      string
	Index        int    // 1-based within cluster
	PortSeq      int    // 1-based across ALL clusters (switch host-port index + BGP router-id)
	Identity     string // fd00:cafe:<h>::<index>/128 (dummy0, GoBGP-advertised)
	IdentityAddr string // fd00:cafe:<h>::<index> (bare, for BGPPeerConfig routeSource)
	NodeNet64    string // fd00:cafe:<h>::/64 (the node's underlay pool; the ToR originates it into
	// BGP with a recursive nexthop = IdentityAddr so guest-endpoint underlays in its upper half are
	// fabric-routable — Talos native GoBGP can only advertise host routes, so the /64 is switch-side)
	RA64 string // fd00:db8:0:<portSeq>::/64 (switch RA on this node's ports)
}

// hash48 maps a cluster name to a stable 16-bit group in fd00:cafe:<h>::/48.
func hash48(name string) uint16 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	v := uint16(h.Sum32())
	if v == 0 {
		v = 1
	}
	return v
}

func (c *Config) derive() {
	c.Derived.Clusters = map[string]DerivedCluster{}
	port := 0
	for _, cl := range c.Fabric.Clusters {
		h := hash48(cl.Name)
		dc := DerivedCluster{
			Hash:       h,
			Prefix48:   fmt.Sprintf("fd00:cafe:%x::/48", h),
			NodeNet64:  fmt.Sprintf("fd00:cafe:%x::/64", h),
			APIVip:     fmt.Sprintf("fd00:cafe:%x:1::1/128", h),
			APIVipAddr: fmt.Sprintf("fd00:cafe:%x:1::1", h),
			PodSubnet:  fmt.Sprintf("fd00:244:%x::/56", h),
			SvcSubnet:  fmt.Sprintf("fd00:96:%x::/108", h),
		}
		for i := 1; i <= cl.Nodes; i++ {
			port++
			dc.Nodes = append(dc.Nodes, DerivedNode{
				Cluster:      cl.Name,
				Index:        i,
				PortSeq:      port,
				Identity:     fmt.Sprintf("fd00:cafe:%x::%d/128", h, i),
				IdentityAddr: fmt.Sprintf("fd00:cafe:%x::%d", h, i),
				NodeNet64:    fmt.Sprintf("fd00:cafe:%x::/64", h),
				RA64:         fmt.Sprintf("fd00:db8:0:%d::/64", port),
			})
		}
		c.Derived.Clusters[cl.Name] = dc
	}
}
