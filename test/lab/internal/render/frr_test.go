package render

import (
	"os"
	"strings"
	"testing"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
	"github.com/trevex/ectobase/test/lab/internal/frr"
)

func TestFRRGolden(t *testing.T) {
	c, err := config.LoadBytes([]byte(`
name: ectobase
images: {kindNode: img/kn, frr: img/frr, tayga: img/tayga, wan: img/wan, registry: registry:2}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  clusters: [{name: dispatch, nodes: 1}, {name: k02, nodes: 2}]
`))
	if err != nil {
		t.Fatal(err)
	}
	v := fabric.Build(c)

	edgeTmpl, err := os.ReadFile("../../templates/frr/edge.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	switchTmpl, err := os.ReadFile("../../templates/frr/switch.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		tmpl   []byte
		ctx    any
		golden string
	}{
		{"edge1", edgeTmpl, frr.EdgeCtx{View: v, Edge: 1}, "testdata/golden/edge1.conf"},
		{"edge2", edgeTmpl, frr.EdgeCtx{View: v, Edge: 2}, "testdata/golden/edge2.conf"},
		{"sw1", switchTmpl, frr.SwitchCtx{View: v, SW: 1}, "testdata/golden/sw1.conf"},
		{"sw2", switchTmpl, frr.SwitchCtx{View: v, SW: 2}, "testdata/golden/sw2.conf"},
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
			t.Errorf("%s: differs from golden %s (run with -update)", tc.name, tc.golden)
		}
	}

	for _, sw := range []string{"sw1", "sw2"} {
		for _, bad := range []string{"ipv6 nd prefix", "network fd00:", "ipv6 route fd00:"} {
			if strings.Contains(out[sw], bad) {
				t.Errorf("%s: must not contain %q (pure /128 relay)", sw, bad)
			}
		}
		if !strings.Contains(out[sw], "as-override") {
			t.Errorf("%s: expected as-override on host peers", sw)
		}
	}
	for _, want := range []string{
		"router bgp 65000", "default-originate", "redistribute connected",
		"ipv6 address fd00:29::11/64", "ipv6 address fd00:ffff::e1/128",
		"ipv6 route ::/0 fd00:29::1", "ipv6 route 64:ff9b::/96",
	} {
		if !strings.Contains(out["edge1"], want) {
			t.Errorf("edge1: expected %q", want)
		}
	}
	if !strings.Contains(out["edge2"], "ipv6 address fd00:29::12/64") {
		t.Errorf("edge2: expected fd00:29::12/64")
	}
}
