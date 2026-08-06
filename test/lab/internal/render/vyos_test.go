package render

import (
	"os"
	"strings"
	"testing"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
	"github.com/trevex/ectobase/test/lab/internal/vyos"
)

func TestVyosGolden(t *testing.T) {
	c, err := config.LoadBytes([]byte(`
name: ectobase
images: {talos: img/talos, vyos: img/vyos, tayga: img/tayga, wan: img/wan, registry: registry:2}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  clusters: [{name: central, nodes: 1}, {name: k02, nodes: 2}]
`))
	if err != nil {
		t.Fatal(err)
	}
	v := fabric.Build(c)

	edgeTmpl, err := os.ReadFile("../../templates/vyos/edge.set.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	switchTmpl, err := os.ReadFile("../../templates/vyos/switch.set.tmpl")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		tmpl   []byte
		ctx    any
		golden string
	}{
		{"edge1", edgeTmpl, vyos.EdgeCtx{View: v, Edge: 1}, "testdata/golden/edge1.set"},
		{"edge2", edgeTmpl, vyos.EdgeCtx{View: v, Edge: 2}, "testdata/golden/edge2.set"},
		{"sw1", switchTmpl, vyos.SwitchCtx{View: v, SW: 1}, "testdata/golden/sw1.set"},
		{"sw2", switchTmpl, vyos.SwitchCtx{View: v, SW: 2}, "testdata/golden/sw2.set"},
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
	for _, sw := range []string{"sw1", "sw2"} {
		for _, want := range []string{
			"router-advert interface eth3", "router-advert interface eth4", "router-advert interface eth5",
			"as-override",
		} {
			if !strings.Contains(out[sw], want) {
				t.Errorf("%s: expected %q", sw, want)
			}
		}
	}
	for _, want := range []string{
		"system-as '65000'", "default-originate", "dns64-prefix '64:ff9b::/96'",
		"fd00:29::11/64", "fd00:ffff::e1/128",
	} {
		if !strings.Contains(out["edge1"], want) {
			t.Errorf("edge1: expected %q", want)
		}
	}
	if !strings.Contains(out["edge2"], "fd00:29::12/64") {
		t.Errorf("edge2: expected %q", "fd00:29::12/64")
	}
}
