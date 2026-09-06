//go:build live

package livetest

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	"github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

const (
	// The VIP is IPv6: the fabric's WAN-edge segment (fd00:29::/64) is v6-only, so a WAN client
	// can only reach a v6 VIP. Documentation prefix — not in any overlay/underlay/fabric range.
	lbVIP        = "2001:db8:2b::1"
	lbBackendIP4 = "10.0.0.181"
	lbBackendIP6 = "2001:db8:1::181"
	lbBackendMAC = "52:54:00:00:2b:01"

	// lbVIP4 is TestLbDistributeSmokeV4's VIP: a v4 documentation prefix (RFC 5737
	// TEST-NET-1, fabric.WanVipV4Test) — the WAN segment is dual-stack as of B10, so a v4
	// WAN client (the `wan` node itself) can reach it the same way the v6 client reaches
	// lbVIP above.
	lbVIP4 = "192.0.2.1"
	// overlayGwV4 is the dpservice-style on-link v4 overlay gateway every guest uses
	// (charts/ectobase-pool/templates/dataplane-ebpf.yaml's `--gateway 169.254.0.1`; the
	// same literal overlay_test.go's attachEndpoint routes guest netns default traffic
	// through). Unlike the v6 gateway (fe80::1, unanswered — no --gateway6 configured, see
	// guestGWMAC's static-ND workaround below), the datapath DOES answer ARP for this
	// address, so it resolves live without a static neigh; TestLbDistributeSmokeV4 still
	// pre-seeds one as a belt-and-suspenders measure against ARP-resolution flakiness.
	overlayGwV4 = "169.254.0.1"
)

// TestLbDistributeSmoke drives the N/S IPv6 LoadBalancer datapath end-to-end on the fabric:
// a WAN client curls an IPv6 VIP -> the flowplane wan_rx EDGE (a sidecar in the VyOS edge1 netns)
// Maglev-selects a backend and encaps to it -> the backend node's uplink_rx (distributed-LB,
// registered with the guest VNI) decaps + delivers to the backend with the DSR firewall-skip -> the
// backend HTTP server replies DSR (src=VIP) -> the backend encaps the reply to the edge's
// local-deliver underlay -> the edge's uplink_rx v6 local-deliver hands the inner IPv6 to VyOS ->
// the WAN client.
//
// LB service programming is direct gRPC and the workload is a raw guest (not a CNI Pod): there is no
// LB CRD -> edge/distributed-LB control path yet, and the edge Maglev / DSR path is the thing under
// test.
func TestLbDistributeSmoke(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	require.NotEmpty(t, nodes, "need a compute node for the LB backend")
	backend := nodes[0]
	beContainer := nodeContainer(cfg, backend)
	// The edge flowplane runs in the flowplane-edge1 sidecar (shares edge1's netns); its
	// dataplane.sock lives in the sidecar's fs, so gRPC targets that container, not edge1.
	edge := clab.ContainerName(cfg.Name, "flowplane-edge1")
	wan := clab.ContainerName(cfg.Name, "wan")
	edgeUnderlay := fabric.EdgeLoopback + "::e1" // the edge's BGP-advertised local-deliver underlay
	edge1WanAddr := fabric.WanNet + "::11"       // edge1 on the WAN segment

	// 1. Backend guest, dual-stack (the v6 overlay IP wires the v6 firewall meta the DSR path needs).
	//    Returns the guest's underlay /128 — the LB backend target.
	bul := attachGuest(t, ctx, cfg, backend, "lbbe", []string{lbBackendIP4, lbBackendIP6}, lbBackendMAC)
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, beContainer, "DetachInterface", `{"interface_id":"lbbe"}`)
	})

	// 2. Guest netns: UNMODIFIED per the spec's Geneve-TLV DSR (§4.3) — the edge rewrites the inner
	//    dst to the backend's OWN overlay IP (no VIP-on-loopback); the httpd binds that overlay IP.
	//    Just a v6 default route toward the overlay gateway so the reply egresses into tc_guest_tx
	//    (the node runs no --gateway6, so ND isn't answered — install a static neigh to guestGWMAC).
	for _, cmd := range [][]string{
		{"ip", "-6", "neigh", "replace", "fe80::1", "lladdr", guestGWMAC, "dev", "lbbe"},
		{"ip", "-6", "route", "replace", "default", "via", "fe80::1", "dev", "lbbe"},
	} {
		if out, err := nodeNetnsProbe(ctx, beContainer, "lbbe", cmd...); err != nil {
			t.Fatalf("guest setup %v: %v\n%s", cmd, err, out)
		}
	}
	// httpd binds the backend's OVERLAY IP (what the DSR forward's rewritten inner dst is); the reply
	// leaves src=overlay and the backend egress reverse-SNATs src -> VIP so the WAN client sees the VIP.
	startLbBackendHTTPD(t, ctx, beContainer, "lbbe", lbBackendIP6)

	// 3. Firewall: v6 ingress-allow for the backend overlay IP (the DSR-rewritten inner dst), v6
	//    egress-allow for the reply.
	mustGRPC(t, ctx, beContainer, "AddFwRule", fmt.Sprintf(
		`{"interface_id":"lbbe","rule_id":"lb-in","dst_cidr":%q,"proto":6,"dst_port_min":80,"dst_port_max":80,"allow":true,"egress":false}`, lbBackendIP6+"/128"))
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
		mustGRPC(t, ctx, r.container, "AddLbBackend", fmt.Sprintf(
			`{"id":"lb","backend_underlay":%q,"backend_overlay_ip":%q,"backend_vni":%d}`, bul, lbBackendIP6, overlayVNI))
		c := r.container
		t.Cleanup(func() { _, _ = dataplaneGRPC(t, ctx, c, "DelLbVip", `{"id":"lb"}`) })
	}

	// 5. WAN client route to the VIP via edge1, then curl (retry to absorb neighbour/route settle).
	if out, err := nodeExec(ctx, wan, "ip", "-6", "route", "replace", lbVIP+"/128", "via", edge1WanAddr); err != nil {
		t.Fatalf("wan VIP route: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = nodeExec(ctx, wan, "ip", "-6", "route", "del", lbVIP+"/128") })

	// LB_HOLD: keep the full LB config + guest up and curl in a loop for 15m so the datapath
	// can be traced externally (debugging aid; env-gated, no effect on normal CI runs).
	if os.Getenv("LB_HOLD") != "" {
		t.Logf("LB_HOLD set: holding setup up, curling VIP %s in a loop for 15m", lbVIP)
		deadline := time.Now().Add(15 * time.Minute)
		for time.Now().Before(deadline) {
			_ = curlFromWan(ctx, wan, lbVIP)
			time.Sleep(1 * time.Second)
		}
		return
	}

	eventually(t, waitDeadline, 5*time.Second, func() error {
		out := curlFromWan(ctx, wan, lbVIP)
		if !strings.Contains(out, "hello-lb") {
			return fmt.Errorf("curl of VIP [%s]:80 did not return hello-lb:\n%s", lbVIP, out)
		}
		return nil
	})
	t.Logf("N/S IPv6 LB smoke PASS: WAN client curled VIP %s -> backend on %s (edge Maglev + DSR)", lbVIP, backend.Cluster)
}

// TestLbDistributeSmokeV4 is TestLbDistributeSmoke's IPv4 sibling: since B10 the WAN
// segment (edge1/edge2 eth3, and the `wan` node's br0) is dual-stack, so a v4 WAN client
// can reach a v4 VIP over the exact same edge Maglev + distributed-LB + DSR path — see
// TestLbDistributeSmoke's doc comment for the full datapath walk. The `wan` node doubles
// as the v4 client here (it already holds fabric.WanGwV4 = 172.29.0.1/24 on its WAN
// bridge; there is no separate v4-only client node).
//
// The two differences from the v6 flow: (1) the guest's default route resolves the
// overlay gateway via ARP, not the v6 test's unanswered-ND workaround (see overlayGwV4's
// doc comment); (2) the DSR return route covers the WAN v4 client's /24, not the v6 WAN
// segment.
func TestLbDistributeSmokeV4(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	require.NotEmpty(t, nodes, "need a compute node for the LB backend")
	backend := nodes[0]
	beContainer := nodeContainer(cfg, backend)
	// The edge flowplane runs in the flowplane-edge1 sidecar (shares edge1's netns); its
	// dataplane.sock lives in the sidecar's fs, so gRPC targets that container, not edge1.
	edge := clab.ContainerName(cfg.Name, "flowplane-edge1")
	wan := clab.ContainerName(cfg.Name, "wan")
	edgeUnderlay := fabric.EdgeLoopback + "::e1"   // the edge's BGP-advertised local-deliver underlay (always v6)
	edge1WanV4Addr := fabric.WanGwV4Base + ".11"   // edge1 on the (now dual-stack) WAN segment
	wanClientV4Net := fabric.WanGwV4Base + ".0/24" // the wan node's own br0 subnet

	// 1. Backend guest, dual-stack (same guest shape as the v6 test; only the v4 overlay
	//    IP + v4 firewall meta are exercised here). Distinct interface/LB ids from the v6
	//    test (lbbe4/lb4) so both tests can run in the same suite invocation without
	//    colliding mid-run.
	bul := attachGuest(t, ctx, cfg, backend, "lbbe4", []string{lbBackendIP4, lbBackendIP6}, lbBackendMAC)
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, beContainer, "DetachInterface", `{"interface_id":"lbbe4"}`)
	})

	// 2. Guest netns: UNMODIFIED per the spec's Geneve-TLV DSR (§4.3) — no VIP-on-lo; the edge
	//    rewrites the inner dst to the backend's OWN overlay IP and the httpd binds that. Just a v4
	//    default route toward the dpservice-style on-link overlay gateway (overlayGwV4) so the reply
	//    egresses into tc_guest_tx (static neigh pre-seeded as belt-and-suspenders).
	for _, cmd := range [][]string{
		{"ip", "route", "replace", overlayGwV4 + "/32", "dev", "lbbe4"},
		{"ip", "neigh", "replace", overlayGwV4, "lladdr", guestGWMAC, "dev", "lbbe4"},
		{"ip", "route", "replace", "default", "via", overlayGwV4, "dev", "lbbe4"},
	} {
		if out, err := nodeNetnsProbe(ctx, beContainer, "lbbe4", cmd...); err != nil {
			t.Fatalf("guest setup %v: %v\n%s", cmd, err, out)
		}
	}
	// httpd binds the backend's OVERLAY IP (the DSR-rewritten inner dst); egress reverse-SNATs src -> VIP.
	startLbBackendHTTPDv4(t, ctx, beContainer, "lbbe4", lbBackendIP4)

	// 3. Firewall: v4 ingress-allow for the backend overlay IP (the DSR-rewritten inner dst), v4
	//    egress-allow for the reply.
	mustGRPC(t, ctx, beContainer, "AddFwRule", fmt.Sprintf(
		`{"interface_id":"lbbe4","rule_id":"lb-in4","dst_cidr":%q,"proto":6,"dst_port_min":80,"dst_port_max":80,"allow":true,"egress":false}`, lbBackendIP4+"/32"))
	mustGRPC(t, ctx, beContainer, "AddFwRule",
		`{"interface_id":"lbbe4","rule_id":"lb-eg4","src_cidr":"0.0.0.0/0","proto":0,"allow":true,"egress":true}`)
	// DSR return route: the WAN v4 client's /24 -> the edge underlay (the underlay nexthop
	// is always v6 regardless of the routed prefix's family — the fabric transport stays
	// v6 end-to-end; only the encapped inner packet is v4 here).
	mustGRPC(t, ctx, beContainer, "AddRoute", fmt.Sprintf(
		`{"vni":%d,"prefix":%q,"nexthop_underlay":%q}`, overlayVNI, wanClientV4Net, edgeUnderlay))

	// 4. Distributed-LB: register the VIP on the EDGE (vni=0, wan_rx) AND the BACKEND node
	//    (vni=overlayVNI). Same lb_underlay convention as the v6 test (the backend's is its
	//    node identity /128, distinct from any guest /128).
	for _, r := range []struct {
		container string
		vni       int
		lbUnder   string
	}{
		{edge, 0, edgeUnderlay},
		{beContainer, overlayVNI, backend.IdentityAddr},
	} {
		mustGRPC(t, ctx, r.container, "AddLbVip", fmt.Sprintf(
			`{"id":"lb4","vni":%d,"vip":%q,"lb_underlay":%q,"ports":[{"port":80,"proto":6}]}`, r.vni, lbVIP4, r.lbUnder))
		mustGRPC(t, ctx, r.container, "AddLbBackend", fmt.Sprintf(
			`{"id":"lb4","backend_underlay":%q,"backend_overlay_ip":%q,"backend_vni":%d}`, bul, lbBackendIP4, overlayVNI))
		c := r.container
		t.Cleanup(func() { _, _ = dataplaneGRPC(t, ctx, c, "DelLbVip", `{"id":"lb4"}`) })
	}
	// TODO(B11-live): assert Maglev distribution across 2 backends.

	// 5. WAN client (the `wan` node, holding fabric.WanGwV4 on its br0) routes to the VIP
	//    via edge1's v4 WAN address, then curl (retry to absorb neighbour/route settle).
	if out, err := nodeExec(ctx, wan, "ip", "route", "replace", lbVIP4+"/32", "via", edge1WanV4Addr); err != nil {
		t.Fatalf("wan VIP4 route: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = nodeExec(ctx, wan, "ip", "route", "del", lbVIP4+"/32") })

	eventually(t, waitDeadline, 5*time.Second, func() error {
		out := curlFromWanV4(ctx, wan, lbVIP4)
		if !strings.Contains(out, "hello-lb") {
			return fmt.Errorf("curl of VIP %s:80 did not return hello-lb:\n%s", lbVIP4, out)
		}
		return nil
	})
	t.Logf("N/S IPv4 LB smoke PASS: WAN client curled VIP %s -> backend on %s (edge Maglev + DSR)", lbVIP4, backend.Cluster)
}

// mustGRPC invokes a DataplaneNode method and fails the test on error.
func mustGRPC(t *testing.T, ctx context.Context, container, method, data string) {
	t.Helper()
	out, err := dataplaneGRPC(t, ctx, container, method, data)
	require.NoError(t, err, "%s on %s: %s", method, container, out)
}

// startLbBackendHTTPD starts a detached IPv6 HTTP server bound to [vip]:80 inside the guest netns
// (via the host python3 nsenter'd into the netns; no busybox/curl in scope) that returns "hello-lb", and registers a cleanup that
// kills it. The DSR reply it emits has src=vip.
func startLbBackendHTTPD(t *testing.T, ctx context.Context, container, netns, vip string) {
	t.Helper()
	startLbBackendHTTPDFamily(t, ctx, container, netns, vip, "AF_INET6")
}

// startLbBackendHTTPDv4 is startLbBackendHTTPD's IPv4 sibling: binds vip:80 AF_INET
// instead of [vip]:80 AF_INET6.
func startLbBackendHTTPDv4(t *testing.T, ctx context.Context, container, netns, vip string) {
	t.Helper()
	startLbBackendHTTPDFamily(t, ctx, container, netns, vip, "AF_INET")
}

// startLbBackendHTTPDFamily is the shared implementation behind startLbBackendHTTPD and
// startLbBackendHTTPDv4 (af is the Python socket.AF_* attribute name to bind with).
func startLbBackendHTTPDFamily(t *testing.T, ctx context.Context, container, netns, vip, af string) {
	t.Helper()
	py := fmt.Sprintf(`import http.server,socket
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(b'hello-lb\n')
 def log_message(s,*a): pass
http.server.HTTPServer.address_family=socket.%s
http.server.HTTPServer((%q,80),H).serve_forever()`, af, vip)
	// The Talos node is shell-less (no `ip`/`python3` in the container), so run the HOST python3
	// nsenter'd into the guest netns — the same mechanism nodeNetnsProbe uses — backgrounded via
	// Start() so it serves until Cleanup kills it.
	pid, err := dockerPID(ctx, container)
	require.NoError(t, err, "resolve pid for %s", container)
	ns := fmt.Sprintf("/proc/%s/root/run/netns/%s", pid, netns)
	cmd := exec.SudoCmd(ctx, "nsenter", "--net="+ns, "python3", "-c", py)
	require.NoError(t, cmd.Start(), "start httpd in %s netns %s", container, netns)
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = exec.Sudo(ctx, "pkill", "-f", "http.server")
	})
}

// curlFromWan curls http://[vip]:80/ from inside the wan container's netns via a curl image (the wan
// node ships no HTTP client), returning the combined output.
func curlFromWan(ctx context.Context, wan, vip string) string {
	return curlFromWanFamily(ctx, wan, vip, true)
}

// curlFromWanV4 is curlFromWan's IPv4 sibling: curls http://vip:80/ (no brackets, -4)
// instead of http://[vip]:80/ (-6).
func curlFromWanV4(ctx context.Context, wan, vip string) string {
	return curlFromWanFamily(ctx, wan, vip, false)
}

// curlFromWanFamily is the shared implementation behind curlFromWan and curlFromWanV4.
func curlFromWanFamily(ctx context.Context, wan, vip string, v6 bool) string {
	url, flag := fmt.Sprintf("http://%s:80/", vip), "-4"
	if v6 {
		url, flag = fmt.Sprintf("http://[%s]:80/", vip), "-6"
	}
	out, _ := exec.SudoOutput(ctx, "docker", "run", "--rm", "--network", "container:"+wan,
		"curlimages/curl:latest", flag, "-s", "--max-time", "8", url)
	return string(out)
}
