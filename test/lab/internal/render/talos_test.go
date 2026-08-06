package render

import (
	"os"
	"strings"
	"testing"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
	"github.com/trevex/ectobase/test/lab/internal/talos"
)

func TestTalosGolden(t *testing.T) {
	c, err := config.LoadBytes([]byte(`
name: ectobase
images: {talos: img/talos, vyos: img/vyos, tayga: img/tayga, wan: img/wan, registry: registry:2}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  registry: {upstreams: [docker.io, ghcr.io], push: [flowplane]}
  clusters: [{name: central, nodes: 1}, {name: k02, nodes: 2}]
`))
	if err != nil {
		t.Fatal(err)
	}
	v := fabric.Build(c)

	clusterTmpl, err := os.ReadFile("../../templates/talos/cluster-patch.yaml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	nodeTmpl, err := os.ReadFile("../../templates/talos/node-patch.yaml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	peerTmpl, err := os.ReadFile("../../templates/talos/bgp-peer.yaml.tmpl")
	if err != nil {
		t.Fatal(err)
	}

	// Pick node central-1 and k02-2 out of the flattened list.
	node := func(cluster string, index int) config.DerivedNode {
		for _, n := range v.Cfg.Derived.Clusters[cluster].Nodes {
			if n.Index == index {
				return n
			}
		}
		t.Fatalf("node %s-%d not found", cluster, index)
		return config.DerivedNode{}
	}
	central1 := node("central", 1)
	k02n2 := node("k02", 2)

	cases := []struct {
		name   string
		tmpl   []byte
		ctx    any
		golden string
	}{
		{"cluster-central", clusterTmpl, talos.NewClusterCtx(v, "central"), "testdata/golden/cluster-central.yaml"},
		{"cluster-k02", clusterTmpl, talos.NewClusterCtx(v, "k02"), "testdata/golden/cluster-k02.yaml"},
		{"node-central-1", nodeTmpl, talos.NewNodeCtx(v, central1), "testdata/golden/node-central-1.yaml"},
		{"node-k02-2", nodeTmpl, talos.NewNodeCtx(v, k02n2), "testdata/golden/node-k02-2.yaml"},
		{"bgp-central-1", peerTmpl, talos.NewNodeCtx(v, central1), "testdata/golden/bgp-central-1.yaml"},
		{"bgp-k02-2", peerTmpl, talos.NewNodeCtx(v, k02n2), "testdata/golden/bgp-k02-2.yaml"},
	}

	out := map[string]string{}
	for _, tc := range cases {
		s, err := String(string(tc.tmpl), tc.ctx)
		if err != nil {
			t.Fatalf("%s: render: %v", tc.name, err)
		}
		out[tc.name] = s
		if *update {
			if err := os.MkdirAll("testdata/golden", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tc.golden, []byte(s), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(tc.golden)
		if err != nil {
			t.Fatalf("%s: read golden (run with -update to create): %v", tc.name, err)
		}
		if s != string(want) {
			t.Errorf("%s: rendered output differs from golden %s (run with -update to regenerate)", tc.name, tc.golden)
		}
	}

	// Structural assertions (independent of the byte-for-byte golden).
	if !strings.Contains(out["cluster-central"], "fd00:244:") {
		t.Errorf("cluster-central: expected its pod subnet fd00:244:")
	}
	for _, want := range []string{"docker.io:", "ghcr.io:", "http://[fd00:29::5]:5000"} {
		if !strings.Contains(out["cluster-central"], want) {
			t.Errorf("cluster-central: expected mirror %q", want)
		}
	}
	// Per-cluster pod subnets must differ so parallel clusters don't collide.
	cp := talos.NewClusterCtx(v, "central").PodSubnet
	kp := talos.NewClusterCtx(v, "k02").PodSubnet
	if cp == kp {
		t.Errorf("central and k02 pod subnets must differ, both = %s", cp)
	}
	if !strings.Contains(out["bgp-central-1"], "routerID: 10.0.100.1") {
		t.Errorf("bgp-central-1: expected routerID 10.0.100.1")
	}
	if !strings.Contains(out["bgp-k02-2"], "routerID: 10.0.100.3") {
		t.Errorf("bgp-k02-2: expected routerID 10.0.100.3 (PortSeq 3)")
	}
}
