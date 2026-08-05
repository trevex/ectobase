package config

import (
	"fmt"
	"hash/fnv"
)

type Derived struct {
	Clusters map[string]DerivedCluster
}

type DerivedCluster struct {
	Prefix48 string // fd00:cafe:<h>::/48
	APIVip   string // fd00:cafe:<h>:1::1/128
	Nodes    []DerivedNode
}

type DerivedNode struct {
	Cluster  string
	Index    int    // 1-based within cluster
	PortSeq  int    // 1-based across ALL clusters (switch host-port index)
	Identity string // fd00:cafe:<h>::<index>/128 (dummy0, GoBGP-advertised)
	RA64     string // fd00:db8:0:<portSeq>::/64 (switch RA on this node's ports)
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
			Prefix48: fmt.Sprintf("fd00:cafe:%x::/48", h),
			APIVip:   fmt.Sprintf("fd00:cafe:%x:1::1/128", h),
		}
		for i := 1; i <= cl.Nodes; i++ {
			port++
			dc.Nodes = append(dc.Nodes, DerivedNode{
				Cluster:  cl.Name,
				Index:    i,
				PortSeq:  port,
				Identity: fmt.Sprintf("fd00:cafe:%x::%d/128", h, i),
				RA64:     fmt.Sprintf("fd00:db8:0:%d::/64", port),
			})
		}
		c.Derived.Clusters[cl.Name] = dc
	}
}
