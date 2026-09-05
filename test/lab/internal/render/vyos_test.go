package render

import (
	"os"
	"strings"
	"testing"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
	"github.com/trevex/ectobase/test/lab/internal/vyos"
)

// TestVyosGolden goldens the rendered VyOS `set` configs for all four fabric
// routers, wrapped exactly as topology/fabric.go writes them to
// build/<name>/vyos/<router>.set (the vbash postconfig-bootup script the VyOS
// clab image executes on every boot).
func TestVyosGolden(t *testing.T) {
	c, err := config.LoadBytes([]byte(`
name: ectobase
images: {vyos: img/vyos, tayga: img/tayga, wan: img/wan, registry: registry:2}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  clusters: [{name: dispatch, nodes: 1}, {name: k02, nodes: 2}]
`))
	if err != nil {
		t.Fatal(err)
	}
	v := fabric.Build(c)

	// Ceph-enabled counterpart, mirroring the cephFixture shape in ceph_test.go, so
	// the switch template's {{ if .CephEnabled }} branch (untested by the plain
	// fixture above) gets golden + structural coverage too.
	cCeph, err := config.LoadBytes([]byte(cephFixture))
	if err != nil {
		t.Fatal(err)
	}
	vCeph := fabric.Build(cCeph)

	edgeTmpl, err := os.ReadFile("../../templates/vyos/edge.set.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	switchTmpl, err := os.ReadFile("../../templates/vyos/switch.set.tmpl")
	if err != nil {
		t.Fatal(err)
	}

	// The two edge-loopback DNS64 resolvers, exactly as topology/fabric.go computes
	// them for both the switch RDNSS RA and the Talos ResolverConfig/cluster-patch.
	res1, res2 := fabric.EdgeLoopback+"::e1", fabric.EdgeLoopback+"::e2"

	cases := []struct {
		name   string
		tmpl   []byte
		ctx    any
		golden string
	}{
		{"edge1", edgeTmpl, vyos.EdgeCtx{View: v, Edge: 1}, "testdata/golden/edge1.set"},
		{"edge2", edgeTmpl, vyos.EdgeCtx{View: v, Edge: 2}, "testdata/golden/edge2.set"},
		{"sw1", switchTmpl, vyos.SwitchCtx{View: v, SW: 1, Resolver1: res1, Resolver2: res2}, "testdata/golden/sw1.set"},
		{"sw2", switchTmpl, vyos.SwitchCtx{View: v, SW: 2, Resolver1: res1, Resolver2: res2}, "testdata/golden/sw2.set"},
		{"sw1-ceph", switchTmpl, vyos.SwitchCtx{View: vCeph, SW: 1, Resolver1: res1, Resolver2: res2}, "testdata/golden/sw1-ceph.set"},
		{"sw2-ceph", switchTmpl, vyos.SwitchCtx{View: vCeph, SW: 2, Resolver1: res1, Resolver2: res2}, "testdata/golden/sw2-ceph.set"},
	}

	out := map[string]string{}
	for _, tc := range cases {
		body, err := String(string(tc.tmpl), tc.ctx)
		if err != nil {
			t.Fatalf("%s: render: %v", tc.name, err)
		}
		s := vyos.Wrap(body)
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

	// Every rendered config is a vbash postconfig-bootup script: shebang, enter
	// config mode, commit, tear the session down.
	for name, s := range out {
		for _, want := range []string{"#!/bin/vbash", "source /opt/vyatta/etc/functions/script-template", "configure\n", "\ncommit\n", "\nexit\n"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: expected %q in the wrapped vbash script", name, want)
			}
		}
	}

	for _, sw := range []string{"sw1", "sw2", "sw1-ceph", "sw2-ceph"} {
		for _, bad := range []string{"router-advert interface eth1 prefix", "network 'fd00:", "static route6 fd00:"} {
			if strings.Contains(out[sw], bad) {
				t.Errorf("%s: must not contain %q (pure /128 relay)", sw, bad)
			}
		}
		if !strings.Contains(out[sw], "as-override") {
			t.Errorf("%s: expected as-override on host peers", sw)
		}
		if !strings.Contains(out[sw], "router-advert interface eth1 default-lifetime") {
			t.Errorf("%s: expected an RA default-lifetime on the node-facing links", sw)
		}
		// eth3 is the first actual node-facing host port (eth1/eth2 are the
		// edge-facing links); RDNSS belongs there, not on the edge-facing RA.
		for _, want := range []string{
			"router-advert interface eth3 name-server 'fd00:ffff::e1'",
			"router-advert interface eth3 name-server 'fd00:ffff::e2'",
		} {
			if !strings.Contains(out[sw], want) {
				t.Errorf("%s: expected %q (RDNSS on the node-facing RA)", sw, want)
			}
		}
		if strings.Contains(out[sw], "router-advert interface eth1 name-server") {
			t.Errorf("%s: RDNSS should not be on the edge-facing link (eth1)", sw)
		}
	}
	// Ceph host port: CephPortSeq = TotalNodes(3)+1 = 4 → switch eth6 (mirrors the
	// cephFixture comment in ceph_test.go). Must be peered (unnumbered, hosts
	// peer-group) and get the same RA default lifetime as every other host port.
	for _, sw := range []string{"sw1-ceph", "sw2-ceph"} {
		for _, want := range []string{
			"neighbor eth6 interface v6only peer-group 'hosts'",
			"router-advert interface eth6 default-lifetime '1800'",
		} {
			if !strings.Contains(out[sw], want) {
				t.Errorf("%s: expected %q (ceph host port)", sw, want)
			}
		}
	}
	for _, want := range []string{
		"system-as '65000'", "default-originate",
		"interfaces ethernet eth3 address 'fd00:29::11/64'",
		"interfaces dummy dum0 address 'fd00:ffff::e1/128'",
		"static route6 ::/0 next-hop 'fd00:29::1'",
		"static route6 64:ff9b::/96 next-hop 'fd00:64:1::2'",
		"network 'fd00:ffff::e1/128'", "network '64:ff9b::/96'",
		"dns64-prefix '64:ff9b::/96'",
		"listen-address 'fd00:ffff::e1'",
		"allow-from 'fd00:cafe::/32'",
		"allow-from 'fd00:ffff::/32'",
		// Pure-hex NAT64-mapped form (8.8.8.8 = 0808:0808): VyOS's name-server
		// value validator rejects the dotted-quad-embedded notation
		// (64:ff9b::8.8.8.8) as "not a valid IP address" (confirmed live, G4).
		"name-server '64:ff9b::808:808'",
	} {
		if !strings.Contains(out["edge1"], want) {
			t.Errorf("edge1: expected %q", want)
		}
	}
	for _, want := range []string{
		"interfaces ethernet eth3 address 'fd00:29::12/64'",
		"interfaces dummy dum0 address 'fd00:ffff::e2/128'",
		"static route6 64:ff9b::/96 next-hop 'fd00:64:2::2'",
		"listen-address 'fd00:ffff::e2'",
	} {
		if !strings.Contains(out["edge2"], want) {
			t.Errorf("edge2: expected %q", want)
		}
	}
}
