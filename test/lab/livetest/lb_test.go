//go:build live

package livetest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	"github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

const (
	// The VIP is IPv6: the kind fabric's WAN-edge segment (fd00:29::/64) is v6-only, so a WAN client
	// can only reach a v6 VIP. Documentation prefix — not in any overlay/underlay/fabric range.
	lbVIP        = "2001:db8:2b::1"
	lbBackendIP4 = "10.0.0.181"
	lbBackendIP6 = "2001:db8:1::181"
	lbBackendMAC = "52:54:00:00:2b:01"
)

// TestLbDistributeSmoke drives the N/S IPv6 LoadBalancer datapath end-to-end on the kind fabric:
// a WAN client curls an IPv6 VIP -> the flowplane wan_rx EDGE (a sidecar in the VyOS edge1 netns)
// Maglev-selects a backend and encaps to it -> the backend node's uplink_rx (distributed-LB,
// registered with the guest VNI) decaps + delivers to the backend with the DSR firewall-skip -> the
// backend HTTP server replies DSR (src=VIP) -> the backend encaps the reply to the edge's
// local-deliver underlay -> the edge's uplink_rx v6 local-deliver hands the inner IPv6 to VyOS ->
// the WAN client.
//
// LB service programming is direct gRPC and the workload is a raw guest (not a CNI Pod): there is no
// LB CRD -> edge/distributed-LB control path yet, and the edge Maglev / DSR path is the thing under
// test — this is the user-approved shape from docs/superpowers/plans/2026-08-08-ns-lb-pseudo-edge-kind.md.
func TestLbDistributeSmoke(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	require.NotEmpty(t, nodes, "need a compute node for the LB backend")
	backend := nodes[0]
	beContainer := nodeContainer(cfg, backend)
	edge := clab.ContainerName(cfg.Name, "edge1")
	wan := clab.ContainerName(cfg.Name, "wan")
	edgeUnderlay := fabric.EdgeLoopback + "::e1"  // the edge's BGP-advertised local-deliver underlay
	edge1WanAddr := fabric.WanNet + "::11"        // edge1 on the WAN segment

	// 1. Backend guest, dual-stack (the v6 overlay IP wires the v6 firewall meta the DSR path needs).
	//    Returns the guest's underlay /128 — the LB backend target.
	bul := attachGuest(t, ctx, cfg, backend, "lbbe", []string{lbBackendIP4, lbBackendIP6}, lbBackendMAC)
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, beContainer, "DetachInterface", `{"interface_id":"lbbe"}`)
	})

	// 2. Guest netns: the VIP on lo (DSR reply src=VIP) + a v6 default route toward the overlay
	//    gateway. The node runs no --gateway6, so gateway ND isn't answered — install a static neigh
	//    to the datapath's gateway MAC (guestGWMAC) so the DSR reply egresses into tc_guest_egress.
	for _, cmd := range [][]string{
		{"ip", "-6", "addr", "replace", lbVIP + "/128", "dev", "lo"},
		{"ip", "-6", "neigh", "replace", "fe80::1", "lladdr", guestGWMAC, "dev", "lbbe"},
		{"ip", "-6", "route", "replace", "default", "via", "fe80::1", "dev", "lbbe"},
	} {
		if out, err := nodeNetnsProbe(ctx, beContainer, "lbbe", cmd...); err != nil {
			t.Fatalf("guest setup %v: %v\n%s", cmd, err, out)
		}
	}
	startLbBackendHTTPD(t, ctx, beContainer, "lbbe", lbVIP)

	// 3. Firewall: v6 ingress-allow for the VIP (DSR keeps inner dst=VIP), v6 egress-allow for the reply.
	mustGRPC(t, ctx, beContainer, "AddFwRule", fmt.Sprintf(
		`{"interface_id":"lbbe","rule_id":"lb-in","dst_cidr":%q,"proto":6,"dst_port_min":80,"dst_port_max":80,"allow":true,"egress":false}`, lbVIP+"/128"))
	mustGRPC(t, ctx, beContainer, "AddFwRule",
		`{"interface_id":"lbbe","rule_id":"lb-eg","src_cidr":"::/0","proto":0,"allow":true,"egress":true}`)
	// DSR return route: the WAN-client prefix -> the edge underlay. Guest egress encaps the reply to
	// the edge, which local-delivers it to VyOS -> WAN.
	mustGRPC(t, ctx, beContainer, "AddRoute", fmt.Sprintf(
		`{"vni":%d,"prefix":%q,"nexthop_underlay":%q}`, overlayVNI, fabric.WanNet+"::/64", edgeUnderlay))

	// 4. Distributed-LB: register the VIP on the EDGE (vni=0, wan_rx) AND the BACKEND node
	//    (vni=overlayVNI — v6_uplink_rx derives the LB lookup vni from the guest's underlay entry).
	//    The backend's lb_underlay is its node identity /128 (distinct from any guest /128, so
	//    create_lb's UNDERLAY[lb_underlay] write can't clobber the guest).
	for _, r := range []struct {
		container string
		vni       int
		lbUnder   string
	}{
		{edge, 0, edgeUnderlay},
		{beContainer, overlayVNI, backend.IdentityAddr},
	} {
		mustGRPC(t, ctx, r.container, "AddLbVip", fmt.Sprintf(
			`{"id":"lb","vni":%d,"vip":%q,"lb_underlay":%q,"ports":[{"port":80,"proto":6}]}`, r.vni, lbVIP, r.lbUnder))
		mustGRPC(t, ctx, r.container, "AddLbBackend", fmt.Sprintf(`{"id":"lb","backend_underlay":%q}`, bul))
		c := r.container
		t.Cleanup(func() { _, _ = dataplaneGRPC(t, ctx, c, "DelLbVip", `{"id":"lb"}`) })
	}

	// 5. WAN client route to the VIP via edge1, then curl (retry to absorb neighbour/route settle).
	if out, err := nodeExec(ctx, wan, "ip", "-6", "route", "replace", lbVIP+"/128", "via", edge1WanAddr); err != nil {
		t.Fatalf("wan VIP route: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = nodeExec(ctx, wan, "ip", "-6", "route", "del", lbVIP+"/128") })

	eventually(t, waitDeadline, 5*time.Second, func() error {
		out := curlFromWan(ctx, wan, lbVIP)
		if !strings.Contains(out, "hello-lb") {
			return fmt.Errorf("curl of VIP [%s]:80 did not return hello-lb:\n%s", lbVIP, out)
		}
		return nil
	})
	t.Logf("N/S IPv6 LB smoke PASS: WAN client curled VIP %s -> backend on %s (edge Maglev + DSR)", lbVIP, backend.Cluster)
}

// mustGRPC invokes a DataplaneNode method and fails the test on error.
func mustGRPC(t *testing.T, ctx context.Context, container, method, data string) {
	t.Helper()
	out, err := dataplaneGRPC(t, ctx, container, method, data)
	require.NoError(t, err, "%s on %s: %s", method, container, out)
}

// startLbBackendHTTPD starts a detached IPv6 HTTP server bound to [vip]:80 inside the guest netns
// (the kind node has python3, no busybox/curl) that returns "hello-lb", and registers a cleanup that
// kills it. The DSR reply it emits has src=vip.
func startLbBackendHTTPD(t *testing.T, ctx context.Context, container, netns, vip string) {
	t.Helper()
	py := fmt.Sprintf(`import http.server,socket
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(b'hello-lb\n')
 def log_message(s,*a): pass
http.server.HTTPServer.address_family=socket.AF_INET6
http.server.HTTPServer((%q,80),H).serve_forever()`, vip)
	err := exec.Sudo(ctx, "docker", "exec", "-d", container, "ip", "netns", "exec", netns, "python3", "-c", py)
	require.NoError(t, err, "start httpd in %s netns %s", container, netns)
	t.Cleanup(func() {
		_ = exec.Sudo(ctx, "docker", "exec", container, "sh", "-c", "pkill -f http.server || true")
	})
}

// curlFromWan curls http://[vip]:80/ from inside the wan container's netns via a curl image (the wan
// node ships no HTTP client), returning the combined output.
func curlFromWan(ctx context.Context, wan, vip string) string {
	out, _ := exec.SudoOutput(ctx, "docker", "run", "--rm", "--network", "container:"+wan,
		"curlimages/curl:latest", "-6", "-s", "--max-time", "8", fmt.Sprintf("http://[%s]:80/", vip))
	return string(out)
}
