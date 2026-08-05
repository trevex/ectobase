package config

import "testing"

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
