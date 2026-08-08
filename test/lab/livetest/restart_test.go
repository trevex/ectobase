//go:build live

package livetest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	labexec "github.com/trevex/ectobase/test/lab/internal/exec"
)

// TestRestartContinuity is the Go port of test/scenario-restart-continuity.sh: it
// proves the flowplane graceful-restart ZERO-GAP guarantee on the kind fabric. A
// continuous flow runs THROUGH the datapath of one compute node (k02) while that
// node's flowplane container is crictl-stopped and kubelet-restarted, and the test
// asserts three things (the unique fingerprint of adopt-and-repoint):
//
//	[7a] packet loss across the restart boundary <= restartLossThresh (SKB fabric),
//	[7b] the pinned uplink bpf-link (/sys/fs/bpf/flowplane/links/uplink-eth1) is
//	     present BEFORE and AFTER the restart (held by bpffs, not the process),
//	[7c] the eth1 XDP prog-id CHANGED (pre != post), proving the pinned link was
//	     atomically re-pointed at the freshly-loaded program (bpf_link_update), NOT
//	     a detach + re-attach (which would open a forwarding gap).
//
// TRAFFIC SOURCE (choice + why): the bash pings the datapath virtual gateway
// 169.254.0.1, on the premise that "the datapath ICMP-replies" to it. On THIS
// datapath that premise is false — the guest tc egress program (tc_guest_tx) answers
// ARP/ND/RA/DHCP for the gateway but has no IPv4 gateway echo responder, so an ICMP
// echo to 169.254.0.1 is treated as an overlay packet to an unroutable dst and
// dropped (verified live: 100% loss). Instead we use the REAL, proven cross-cluster
// overlay flow: an endpoint on k02 pings an endpoint on k03. The REPLY traffic
// returns to k02 encapsulated over eth1 and is decapped by k02's uplink XDP — the
// exact pinned link this test exercises across the restart. k03's flowplane is NOT
// restarted, so it keeps replying throughout. This gives a continuous flow whose
// return path traverses the pinned uplink link (loss is a faithful measure of the
// restart gap). We attach both endpoints directly over the dataplane gRPC (the
// assertions are node-level either way, and a tight continuous ping through a
// gRPC-attached endpoint is more reliable than the CNI-pod path for a ~12 s window).
func TestRestartContinuity(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) < 2 {
		t.Skip("need >=2 compute nodes across clusters for a cross-cluster overlay flow")
	}
	// Distinct clusters: the return path must traverse the restarting node's uplink.
	src, dst := nodes[0], nodes[1]
	if src.Cluster == dst.Cluster {
		t.Skip("need the two endpoints in different clusters")
	}
	srcNode := nodeContainer(cfg, src)

	const (
		srcID = "rcont"       // endpoint on the restarting node (k02)
		dstID = "rcont-peer"  // peer endpoint on the other node (k03)
		srcIP = "10.0.0.60"   // distinct from other tests
		dstIP = "10.0.0.61"   // distinct from other tests
		srcMAC = "52:54:00:00:00:60"
		dstMAC = "52:54:00:00:00:61"
		uplinkIface   = "eth1"
		uplinkPinPath = "/sys/fs/bpf/flowplane/links/uplink-eth1"
		pingCount     = 60  // 60 * 0.2s = ~12 s window
		pingInterval  = "0.2"
		// SKB fabric threshold: kept at the bash value (kind veths are SKB/MTU-1500,
		// same as clab). The restart gap is bounded by the container stop+adopt window.
		restartLossThresh = 15
	)

	// --- attach both endpoints (dpservice-style: /32 + 169.254.0.1 gateway) ---
	ulSrc := attachEndpoint(t, ctx, cfg, src, srcID, srcIP, srcMAC)
	ulDst := attachEndpoint(t, ctx, cfg, dst, dstID, dstIP, dstMAC)
	require.NotEmpty(t, ulSrc, "src endpoint underlay")
	require.NotEmpty(t, ulDst, "dst endpoint underlay")

	// These endpoints are attached directly over the dataplane gRPC (not compiled
	// from a central NIC), so they inherit the deny-by-default firewall posture and
	// would drop all overlay traffic. Program an any/any Allow on both directions of
	// both endpoints so the request egresses the src, ingresses the dst, and the
	// reply returns through the restarting node's uplink. (Verified: without these,
	// 100% loss; with them, 0% loss.)
	allowAny(t, ctx, srcNode, srcID)
	allowAny(t, ctx, nodeContainer(cfg, dst), dstID)
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, srcNode, "DetachInterface", fmt.Sprintf(`{"interface_id":%q}`, srcID))
		_, _ = dataplaneGRPC(t, ctx, nodeContainer(cfg, dst), "DetachInterface", fmt.Sprintf(`{"interface_id":%q}`, dstID))
	})

	// The reflector needs a beat to propagate both /128s + program the peer routes.
	// Assert the flow works BEFORE we touch anything (else a 100%-loss run would
	// falsely "pass" 7a's threshold with sent==received==0 — guard against that).
	eventually(t, 90*time.Second, 5*time.Second, func() error {
		return endpointPing(ctx, cfg, src, srcID, dstIP)
	})

	// --- [PRE] record uplink prog-id + pin presence on the restarting node ---
	progPre, err := uplinkProgID(ctx, srcNode, uplinkIface)
	require.NoError(t, err, "read pre-restart uplink prog-id")
	require.NotZero(t, progPre, "no XDP program on %s before restart — datapath not loaded?", uplinkIface)
	pinPre := pinExists(ctx, srcNode, uplinkPinPath)
	require.True(t, pinPre, "uplink link pin %s missing PRE — link-pinning not enabled on the DS?", uplinkPinPath)

	cidOld, err := flowplaneContainerID(ctx, srcNode)
	require.NoError(t, err)
	require.NotEmpty(t, cidOld, "no running flowplane container on %s", srcNode)
	t.Logf("PRE: uplink %s prog-id=%d pin=%v flowplane=%s", uplinkIface, progPre, pinPre, cidOld)

	// --- [3] start the continuous flow in the background (src -> dst overlay) ---
	pid, err := dockerPID(ctx, srcNode)
	require.NoError(t, err)
	ns := fmt.Sprintf("/proc/%s/root/run/netns/%s", pid, srcID)
	pingCmd := labexec.SudoCmd(ctx, "nsenter", "--net="+ns,
		"ping", "-i", pingInterval, "-c", strconv.Itoa(pingCount), "-W", "1", dstIP)
	var pingOut bytes.Buffer
	pingCmd.Stdout = &pingOut
	pingCmd.Stderr = &pingOut
	require.NoError(t, pingCmd.Start(), "start continuous ping")

	// Head-start: let a few probes complete before killing the container.
	time.Sleep(1 * time.Second)

	// --- [4] crictl stop the flowplane container mid-flow ---
	t.Logf("crictl stop %s (mid-flow) — kubelet restarts + adopts the pinned link", cidOld)
	_, err = nodeExec(ctx, srcNode, "crictl", "stop", cidOld)
	require.NoError(t, err, "crictl stop %s", cidOld)

	// --- [5] wait for a NEW container that logged the atomic adopt re-point ---
	var cidNew string
	eventually(t, 100*time.Second, 2*time.Second, func() error {
		cid, err := flowplaneContainerID(ctx, srcNode)
		if err != nil || cid == "" || cid == cidOld {
			return fmt.Errorf("new flowplane container not up yet (cur=%q old=%q)", cid, cidOld)
		}
		logs, _ := nodeExec(ctx, srcNode, "crictl", "logs", cid)
		if !strings.Contains(logs, "adopt: re-pointed pinned link") {
			return fmt.Errorf("new container %s has not logged the adopt re-point yet", cid)
		}
		cidNew = cid
		return nil
	})
	t.Logf("restarted: %s -> %s (logged adopt re-point)", cidOld, cidNew)

	// --- [5b] wait for the ping to finish; parse sent/received ---
	waitErr := pingCmd.Wait() // ping exits non-zero on any loss — expected, not fatal
	sent, recv := parsePingStats(pingOut.String())
	lost := sent - recv
	t.Logf("ping: sent=%d received=%d lost=%d (threshold=%d) waitErr=%v", sent, recv, lost, restartLossThresh, waitErr)
	if last := lastPingLines(pingOut.String(), 3); last != "" {
		t.Logf("ping tail:\n%s", last)
	}

	// --- [6] record POST state ---
	progPost, err := uplinkProgID(ctx, srcNode, uplinkIface)
	require.NoError(t, err, "read post-restart uplink prog-id")
	pinPost := pinExists(ctx, srcNode, uplinkPinPath)
	t.Logf("POST: uplink %s prog-id=%d pin=%v flowplane=%s", uplinkIface, progPost, pinPost, cidNew)

	// --- [7] assertions ---
	// 7a. loss within threshold (and non-degenerate: sent>0).
	require.Greater(t, sent, 0, "ping sent 0 packets — endpoint or routing setup failed")
	require.LessOrEqualf(t, lost, restartLossThresh,
		"packet loss %d/%d exceeds threshold %d (%d%%) — a REAL forwarding gap across the restart",
		lost, sent, restartLossThresh, lost*100/sent)
	// 7b. pinned link survived the crictl stop.
	require.Truef(t, pinPost, "bpf-link pin %s VANISHED across the restart — link was not persisted", uplinkPinPath)
	// 7c. prog-id changed => atomic re-point, not the same program (and not a drop).
	require.NotZero(t, progPost, "no XDP program on %s after restart — datapath dropped entirely", uplinkIface)
	require.NotEqualf(t, progPre, progPost,
		"uplink prog-id did NOT change (%d) — the link was not re-pointed (detach/re-attach or stale)", progPre)

	t.Logf("graceful-restart zero-drop continuity: loss=%d/%d pin=survived(%v->%v) prog-id=%d->%d (atomic re-point)",
		lost, sent, pinPre, pinPost, progPre, progPost)
}

// allowAny programs an any/any Allow rule in BOTH directions on an interface,
// busting the deny-by-default firewall for a raw (non-compiled) gRPC endpoint.
func allowAny(t *testing.T, ctx context.Context, container, id string) {
	t.Helper()
	for _, egress := range []bool{true, false} {
		dir := "in"
		if egress {
			dir = "eg"
		}
		body := fmt.Sprintf(`{"interface_id":%q,"rule_id":%q,"proto":0,"allow":true,"egress":%t}`, id, dir, egress)
		out, err := dataplaneGRPC(t, ctx, container, "AddFwRule", body)
		require.NoError(t, err, "AddFwRule %s-allow on %s: %s", dir, id, out)
	}
}

// uplinkProgID returns the XDP prog-id attached to iface in the node's network
// namespace, via the nix bpftool (v7.6.0) run under nsenter — the AUTHORITATIVE
// check (the in-container bpftool is too old to render XDP prog-ids reliably).
// Returns 0 if no XDP program is attached.
func uplinkProgID(ctx context.Context, container, iface string) (int, error) {
	out, err := nodeNetnsExec(ctx, container, "bpftool", "-j", "net", "show", "dev", iface)
	if err != nil {
		return 0, fmt.Errorf("bpftool net show dev %s: %w\n%s", iface, err, out)
	}
	// bpftool -j net show dev <iface> => [{"xdp":[{"devname":..,"id":N}], ...}]
	var arr []struct {
		XDP []struct {
			ID int `json:"id"`
		} `json:"xdp"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &arr); err != nil {
		return 0, fmt.Errorf("parse bpftool json %q: %w", out, err)
	}
	for _, e := range arr {
		for _, x := range e.XDP {
			if x.ID != 0 {
				return x.ID, nil
			}
		}
	}
	return 0, nil
}

// pinExists reports whether a bpffs path is present inside the node container.
func pinExists(ctx context.Context, container, path string) bool {
	_, err := nodeExec(ctx, container, "ls", path)
	return err == nil
}

// flowplaneContainerID resolves the running flowplane crictl container id on the
// node (empty if none). Uses `crictl ps --name flowplane -q`, filtered to the
// running state (crictl -q emits one id per line).
func flowplaneContainerID(ctx context.Context, container string) (string, error) {
	out, err := nodeExec(ctx, container, "crictl", "ps", "--name", "flowplane", "--state", "Running", "-q")
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l, nil
		}
	}
	return "", nil
}

var pingSentRe = regexp.MustCompile(`(\d+) packets transmitted, (\d+) received`)

// parsePingStats extracts (sent, received) from Linux ping summary output.
func parsePingStats(out string) (sent, recv int) {
	m := pingSentRe.FindStringSubmatch(out)
	if m == nil {
		return 0, 0
	}
	sent, _ = strconv.Atoi(m[1])
	recv, _ = strconv.Atoi(m[2])
	return sent, recv
}

// lastPingLines returns the last n non-empty lines of the ping output for logging.
func lastPingLines(out string, n int) string {
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
