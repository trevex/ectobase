package render

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

// cephFixture is the ceph-enabled counterpart of the base clab/vyos fixtures.
// It uses the SAME clusters (dispatch:1, k02:2 → TotalNodes=3) so the ceph host
// port lands at CephPortSeq=4 → switch eth6, just past the node ports (eth3-5).
const cephFixture = `
name: ectobase
images: {talos: img/talos, vyos: img/vyos, tayga: img/tayga, wan: img/wan, registry: registry:2, frr: img/frr, ceph: img/ceph}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  ceph: {enabled: true}
  clusters: [{name: dispatch, nodes: 1}, {name: k02, nodes: 2}]
`

// TestCephClabGolden renders the clab topology with ceph.enabled and asserts the
// ceph node + link + mon addressing appear. It keeps its own golden so the base
// (ceph-off) fabric.clab.yml golden stays byte-unchanged.
func TestCephClabGolden(t *testing.T) {
	c, err := config.LoadBytes([]byte(cephFixture))
	if err != nil {
		t.Fatal(err)
	}
	view := fabric.Build(c)

	b, err := os.ReadFile("../../templates/fabric.clab.yml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	out, err := String(string(b), view)
	if err != nil {
		t.Fatal(err)
	}

	const goldenPath = "testdata/golden/fabric-ceph.clab.yml"
	if *update {
		if err := os.MkdirAll("testdata/golden", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if out != string(want) {
		t.Errorf("rendered output differs from golden %s (run with -update to regenerate)", goldenPath)
	}

	// Structural invariants: the ceph node, sidecar, mon endpoint, and the switch
	// host-port links (CephPortSeq=4 → eth6) must all be present.
	monAddr := c.Derived.CephMonAddr
	for _, want := range []string{
		"ceph-net:", "ceph:",
		"network-mode: container:clab-ectobase-ceph-net",
		`MON_IP: "[` + monAddr + `]"`,
		"CEPH_PUBLIC_NETWORK: " + c.Derived.CephNet64,
		`ceph-net:eth1", "sw1:eth6`,
		`ceph-net:eth2", "sw2:eth6`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in ceph-enabled clab topology", want)
		}
	}
}

// TestCephDisabledUnchanged asserts the base render (ceph absent) carries no ceph
// blocks, so enabling ceph is strictly opt-in.
func TestCephDisabledUnchanged(t *testing.T) {
	c, err := config.LoadBytes([]byte(`
name: ectobase
images: {talos: img/talos, vyos: img/vyos, tayga: img/tayga, wan: img/wan, registry: registry:2}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  clusters: [{name: dispatch, nodes: 1}, {name: k02, nodes: 2}]
`))
	if err != nil {
		t.Fatal(err)
	}
	view := fabric.Build(c)
	b, err := os.ReadFile("../../templates/fabric.clab.yml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	out, err := String(string(b), view)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"ceph-net", "ceph:", "MON_IP", "CEPH_PUBLIC_NETWORK"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("base (ceph-off) topology unexpectedly contains %q", unwanted)
		}
	}
}

// TestCephFRRConf renders the ceph FRR config and asserts the load-bearing lines:
// an explicit `bgp router-id` (this fabric is IPv6-only, so bgpd cannot auto-derive
// one — without it the ceph /64 never propagates and storage is unreachable), plus
// the `router bgp <ASHost>` and `network <CephNet64>` announcement. frr.conf is not
// otherwise goldened, so this guards against a router-id regression.
func TestCephFRRConf(t *testing.T) {
	c, err := config.LoadBytes([]byte(cephFixture))
	if err != nil {
		t.Fatal(err)
	}
	v := fabric.Build(c)

	b, err := os.ReadFile("../../templates/ceph/frr.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	out, err := String(string(b), v)
	if err != nil {
		t.Fatal(err)
	}

	// CephPortSeq = TotalNodes(3) + 1 = 4 → router-id 10.0.100.4 (distinct from the
	// node router-ids 10.0.100.1-3).
	for _, want := range []string{
		"bgp router-id 10.0.100.4",
		"router bgp " + strconv.Itoa(c.Fabric.AS.Host),
		"network " + c.Derived.CephNet64,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in rendered ceph frr.conf", want)
		}
	}
}

// The ceph-enabled switch golden coverage (host port eth6 peered + as-override +
// activated) now lives in frr_test.go's TestFRRGolden (sw1-ceph.conf/sw2-ceph.conf),
// which supersedes the old VyOS-syntax TestCephSwitchGolden removed here.
