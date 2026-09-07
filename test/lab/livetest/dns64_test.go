//go:build live

package livetest

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

// TestDNS64Synthesis asserts the fabric's DNS64 forwarder (VyOS `service dns
// forwarding dns64-prefix`, on the edge loopback) synthesizes AAAA answers in
// the NAT64 prefix for A-only names. This is the resolve half of the fabric's
// v6-only egress story (TestNAT64Egress covers the reach half): a node's own
// image pulls of v4-only registries depend on it.
//
// The probe is `ipv4only.arpa` (RFC 7050): a well-known name with ONLY A
// records (192.0.0.170 / 192.0.0.171) and no AAAA, so a correct DNS64 resolver
// MUST return a synthesized 64:ff9b::c000:aa / ::c000:ab. A dual-stacked name
// would get its real AAAA back and prove nothing, hence the RFC-7050 probe.
//
// We query the edge-loopback resolver explicitly (`dig @<edge>::e1`, host dig
// run inside the compute node's netns) rather than trusting the node's
// resolv.conf, so the assertion is about the fabric forwarder specifically.
func TestDNS64Synthesis(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("no compute nodes")
	}
	container := nodeContainer(cfg, nodes[0])

	nat64, err := netip.ParsePrefix(cfg.Fabric.NAT64Prefix)
	if err != nil {
		t.Fatalf("parse nat64 prefix %q: %v", cfg.Fabric.NAT64Prefix, err)
	}
	resolver := fabric.EdgeLoopback + "::e1" // edge1 DNS64 forwarder listen-address

	eventually(t, 90*time.Second, 5*time.Second, func() error {
		// +short prints one address per line; the forwarder reaches its upstream
		// (8.8.8.8 via its own NAT64) so first-query latency can spike — retry.
		out, err := nodeNetnsExec(ctx, container,
			"dig", "@"+resolver, "AAAA", "ipv4only.arpa", "+short", "+time=3", "+tries=1")
		if err != nil {
			return fmt.Errorf("dig @%s ipv4only.arpa AAAA from %s: %w\n%s", resolver, container, err, out)
		}
		var synthesized []string
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			addr, perr := netip.ParseAddr(line)
			if perr != nil {
				continue // dig can emit CNAME/SOA lines; skip non-addresses
			}
			if nat64.Contains(addr) {
				synthesized = append(synthesized, line)
			}
		}
		if len(synthesized) == 0 {
			return fmt.Errorf("no DNS64-synthesized AAAA in %s for ipv4only.arpa:\n%s", nat64, out)
		}
		t.Logf("DNS64 PASS: %s synthesized ipv4only.arpa -> %s (in %s)", resolver, strings.Join(synthesized, ","), nat64)
		return nil
	})
}
