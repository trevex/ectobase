package config

import (
	"fmt"
	"hash/fnv"
)

type Derived struct {
	Clusters map[string]DerivedCluster

	// Fabric-level Ceph addressing (computed from hash48("ceph"), a fixed literal,
	// so it is deterministic and never collides with a cluster /48). The ceph node
	// lives on its OWN fabric /64 = the Tier-2 storage-fence coordinate (each client
	// is seen FROM its own node /64), announced into the fabric via unnumbered eBGP.
	CephNet64   string // fd00:cafe:<h>::/64 (the ceph node's underlay pool, on dummy0; also the announced public_network)
	CephMonAddr string // fd00:cafe:<h>::1 (the mon address; the demo binds MON_IP here)
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
	NodeNet64    string // fd00:cafe:<h>::/64 (the node's underlay /64; NOT originated into BGP — the
	// node advertises only its /128 VTEP identity. NodeNet64 is retained as the per-node underlay
	// pool that flowplane allocates guest-endpoint /128s from, written to /etc/fabric/prefix)
}

// KindRole is the kind node role: the first node in a cluster is the control-plane,
// the rest are workers.
func (n DerivedNode) KindRole() string {
	if n.Index == 1 {
		return "control-plane"
	}
	return "worker"
}

// KindContainer is the docker container name kind gives this node. The kind cluster
// is named after the clab k8s-kind lifecycle node (= the cluster name), and kind
// names its containers <cluster>-control-plane and <cluster>-worker, <cluster>-worker2, …
// This is the single source of truth used by both the clab render (ext-container
// link endpoints) and the live test suite (nodeContainer).
func (n DerivedNode) KindContainer() string {
	switch n.Index {
	case 1:
		return n.Cluster + "-control-plane"
	case 2:
		return n.Cluster + "-worker"
	default:
		return fmt.Sprintf("%s-worker%d", n.Cluster, n.Index-1)
	}
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
			})
		}
		c.Derived.Clusters[cl.Name] = dc
	}

	// Fabric-level Ceph addressing. "ceph" is a fixed literal so hash48 is stable
	// and distinct from any cluster name's group.
	h := hash48("ceph")
	c.Derived.CephNet64 = fmt.Sprintf("fd00:cafe:%x::/64", h)
	c.Derived.CephMonAddr = fmt.Sprintf("fd00:cafe:%x::1", h)
}
