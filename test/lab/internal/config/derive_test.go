package config

import (
	"strings"
	"testing"
)

// TestDeriveCeph asserts the fabric-level Ceph derivation is stable and its
// mon address is distinct from every cluster's node /64 (so the ceph /64 never
// collides with a cluster underlay on the shared fabric).
func TestDeriveCeph(t *testing.T) {
	c, err := LoadBytes([]byte(`
name: ectobase
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  ceph: {enabled: true}
  clusters: [{name: central, nodes: 1}, {name: k02, nodes: 2}]
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Derived.CephNet64 == "" || c.Derived.CephMonAddr == "" {
		t.Fatalf("ceph derived fields empty: %+v", c.Derived)
	}
	// The mon addr must sit inside the /64 and end in ::1.
	if !strings.HasSuffix(c.Derived.CephMonAddr, "::1") {
		t.Fatalf("ceph mon addr %q should end in ::1", c.Derived.CephMonAddr)
	}
	if !strings.HasPrefix(c.Derived.CephNet64, "fd00:cafe:") || !strings.HasSuffix(c.Derived.CephNet64, "::/64") {
		t.Fatalf("ceph net64 %q not in fd00:cafe:<h>::/64 form", c.Derived.CephNet64)
	}

	// Distinct from every cluster prefix / node /64.
	for name, dc := range c.Derived.Clusters {
		if c.Derived.CephNet64 == dc.NodeNet64 {
			t.Fatalf("ceph /64 %q collides with cluster %q node /64", c.Derived.CephNet64, name)
		}
		if strings.HasPrefix(c.Derived.CephMonAddr, strings.TrimSuffix(dc.NodeNet64, "::/64")+"::") {
			t.Fatalf("ceph mon addr %q lives in cluster %q /64 %q", c.Derived.CephMonAddr, name, dc.NodeNet64)
		}
	}

	// Deterministic: a second load yields the same mon addr (fixed literal "ceph").
	c2, err := LoadBytes([]byte(`
name: ectobase
fabric: {as: {edge: 65000, switch: 65010, host: 65100}, ceph: {enabled: true}, clusters: [{name: central, nodes: 1}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if c2.Derived.CephMonAddr != c.Derived.CephMonAddr {
		t.Fatalf("ceph derivation not deterministic: %q != %q", c2.Derived.CephMonAddr, c.Derived.CephMonAddr)
	}
}

func TestDeriveStableAndDistinct(t *testing.T) {
	c, _ := LoadBytes([]byte(`
name: ectobase
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  clusters: [{name: central, nodes: 1}, {name: k02, nodes: 1}]
`))
	if c.Derived.Clusters["central"].Prefix48 == c.Derived.Clusters["k02"].Prefix48 {
		t.Fatal("cluster /48s must differ")
	}
	n := c.Derived.Clusters["central"].Nodes[0]
	if n.Identity == "" || n.RA64 == "" || c.Derived.Clusters["central"].APIVip == "" {
		t.Fatalf("derived fields empty: %+v", n)
	}
	// Deterministic: a second load yields the same /48.
	c2, _ := LoadBytes([]byte(`name: ectobase
fabric: {as: {edge: 65000, switch: 65010, host: 65100}, clusters: [{name: central, nodes: 1}]}`))
	if c2.Derived.Clusters["central"].Prefix48 != c.Derived.Clusters["central"].Prefix48 {
		t.Fatal("derivation not deterministic")
	}
}
