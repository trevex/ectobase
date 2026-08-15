package config

import "testing"

func TestLoadValid(t *testing.T) {
	c, err := LoadBytes([]byte(`
name: ectobase
images: {talos: t, vyos: v, tayga: g, registry: registry:2}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  registry: {upstreams: [docker.io], push: [flowplane]}
  clusters:
    - {name: dispatch, nodes: 1}
    - {name: k02, nodes: 2}
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Name != "ectobase" || len(c.Fabric.Clusters) != 2 || c.Fabric.Clusters[1].Nodes != 2 {
		t.Fatalf("parsed wrong: %+v", c)
	}
	if c.TotalNodes() != 3 {
		t.Fatalf("total nodes = %d, want 3", c.TotalNodes())
	}
}

func TestValidateRejects(t *testing.T) {
	for _, tc := range []string{
		`name: x` + "\n" + `fabric: {as: {edge: 0, switch: 1, host: 2}, clusters: [{name: a, nodes: 1}]}`,       // edge ASN 0
		`name: x` + "\n" + `fabric: {as: {edge: 1, switch: 1, host: 1}, clusters: [{name: a, nodes: 99}]}`,      // nodes > 15
		`name: x` + "\n" + `fabric: {as: {edge: 1, switch: 1, host: 1}, clusters: [{name: a, nodes: 1},{name: a, nodes: 1}]}`, // dup name
	} {
		if _, err := LoadBytes([]byte(tc)); err == nil {
			t.Fatalf("expected error for %q", tc)
		}
	}
}
