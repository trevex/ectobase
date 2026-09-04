//go:build live

package livetest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	labexec "github.com/trevex/ectobase/test/lab/internal/exec"

	"github.com/stretchr/testify/require"
)

// TestRestartContinuity proves the flowplane graceful-restart ZERO-GAP guarantee for a NETKIT (L3)
// guest link — the P4/P6 datapath — on the Talos substrate. A continuous cross-cluster overlay flow
// runs THROUGH one compute node (k02) while that node's flowplane DaemonSet pod is deleted and
// rescheduled by the kubelet, and the test asserts the fingerprint of adopt-and-re-point:
//
//	[7a] packet loss across the restart boundary <= restartLossThresh (SKB/clab fabric),
//	[7b] the pinned guest netkit link (/sys/fs/bpf/flowplane/links/guest-<hex(id)>) is present BEFORE
//	     and AFTER the restart — held by the node's hostPath bpffs, not the flowplane process,
//	[7c] the link's prog-id CHANGED (pre != post), proving `readopt_netkit_link` atomically re-pointed
//	     the pinned netkit link at the freshly-loaded `tc_guest_tx` via bpf(BPF_LINK_UPDATE) — NOT a
//	     detach + re-attach (which would open a forwarding gap, and on a live netkit link is unsafe).
//
// TRAFFIC: an endpoint on k02 pings an endpoint on k03 over the overlay. The k02 endpoint is a netkit
// L3 guest (Auto device-type resolves to netkit on the Talos kernel), so its egress rides the pinned
// netkit link this test exercises across the restart. k03's flowplane is NOT restarted, so it keeps
// replying throughout — a continuous flow whose loss is a faithful measure of the restart gap. Both
// endpoints are attached directly over the dataplane gRPC (a tight continuous ping through a
// gRPC-attached endpoint is more reliable than the CNI-pod path for a ~12 s window).
func TestRestartContinuity(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) < 2 {
		t.Skip("need >=2 compute nodes across clusters for a cross-cluster overlay flow")
	}
	// Distinct clusters: the return path must traverse the restarting node, and k03 must keep replying.
	src, dst := nodes[0], nodes[1]
	if src.Cluster == dst.Cluster {
		t.Skip("need the two endpoints in different clusters")
	}
	srcNode := nodeContainer(cfg, src)

	const (
		srcID  = "rcont"      // endpoint on the restarting node (k02)
		dstID  = "rcont-peer" // peer endpoint on the other node (k03)
		srcIP  = "10.0.0.60"
		dstIP  = "10.0.0.61"
		srcMAC = "52:54:00:00:00:60"
		dstMAC = "52:54:00:00:00:61"
		pingCount    = 60 // 60 * 0.2s = ~12 s window
		pingInterval = "0.2"
		// SKB fabric threshold: the clab uplinks are SKB/MTU-1500. The restart gap is bounded by the
		// pod stop+reschedule+adopt window; the pinned link keeps the datapath live across it.
		restartLossThresh = 15
	)
	// The pinned guest link on the restarting node — `guest-<hex(interface_id)>` under the DS bpffs
	// (a hostPath mount, so the pin survives the pod restart). Matches loader::link_pin_path naming.
	guestPin := "/sys/fs/bpf/flowplane/links/guest-" + hex.EncodeToString([]byte(srcID))

	// --- attach both endpoints (dpservice-style: /32 + 169.254.0.1 gateway) ---
	ulSrc := attachEndpoint(t, ctx, cfg, src, srcID, srcIP, srcMAC)
	ulDst := attachEndpoint(t, ctx, cfg, dst, dstID, dstIP, dstMAC)
	require.NotEmpty(t, ulSrc, "src endpoint underlay")
	require.NotEmpty(t, ulDst, "dst endpoint underlay")

	// gRPC-attached endpoints inherit the deny-by-default firewall; open any/any both directions on
	// both so the request egresses src, ingresses dst, and the reply returns through the restarting
	// node. (Verified in P4: without these, 100% loss; with them, 0%.)
	allowAny(t, ctx, srcNode, srcID)
	allowAny(t, ctx, nodeContainer(cfg, dst), dstID)
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, srcNode, "DetachInterface", fmt.Sprintf(`{"interface_id":%q}`, srcID))
		_, _ = dataplaneGRPC(t, ctx, nodeContainer(cfg, dst), "DetachInterface", fmt.Sprintf(`{"interface_id":%q}`, dstID))
	})

	// The reflector needs a beat to propagate both /128s + program the peer routes. Assert the flow
	// works BEFORE we touch anything (else a 100%-loss run would falsely "pass" 7a with sent==recv==0).
	eventually(t, 90*time.Second, 5*time.Second, func() error {
		return endpointPing(ctx, cfg, src, srcID, dstIP)
	})

	// The clab node container does NOT restart (only the flowplane POD inside it does), so its host
	// PID is stable — the guest netns and the node bpffs pins are reachable through /proc/<pid>/root
	// throughout.
	nodePID, err := dockerPID(ctx, srcNode)
	require.NoError(t, err)

	// --- [PRE] record the guest netkit link's prog-id + pin presence on the restarting node ---
	progPre, err := linkProgID(ctx, nodePID, guestPin)
	require.NoError(t, err, "read pre-restart guest link prog-id")
	require.NotZero(t, progPre, "no prog on the pinned guest netkit link %s before restart — datapath not loaded?", guestPin)
	pinPre := hostPinExists(nodePID, guestPin)
	require.True(t, pinPre, "guest link pin %s missing PRE — link-pinning not enabled on the DS?", guestPin)

	oldPod, err := flowplanePod(ctx, cfg, src.Cluster)
	require.NoError(t, err)
	require.NotEmpty(t, oldPod, "no flowplane pod on %s", src.Cluster)
	t.Logf("PRE: guest link %s prog-id=%d pin=%v flowplane pod=%s", guestPin, progPre, pinPre, oldPod)

	// --- [3] start the continuous flow in the background (src -> dst overlay) ---
	ns := fmt.Sprintf("/proc/%s/root/run/netns/%s", nodePID, srcID)
	pingCmd := labexec.SudoCmd(ctx, "nsenter", "--net="+ns,
		"ping", "-i", pingInterval, "-c", strconv.Itoa(pingCount), "-W", "1", dstIP)
	var pingOut bytes.Buffer
	pingCmd.Stdout = &pingOut
	pingCmd.Stderr = &pingOut
	require.NoError(t, pingCmd.Start(), "start continuous ping")

	// Head-start: let a few probes complete before the restart. Deliberate fixed lead-in, not a
	// readiness wait (pingOut is written concurrently, so polling it here would race the writer).
	time.Sleep(1 * time.Second)

	// --- [4] delete the flowplane DS pod mid-flow. The DaemonSet immediately reschedules a new pod on
	//     the SAME node (Talos-compatible restart; crictl is unavailable on the shell-less node). The
	//     pinned link keeps the netkit datapath live across the gap; the new pod adopts + re-points it.
	t.Logf("delete flowplane pod %s (mid-flow) — DS reschedules + adopts the pinned netkit link", oldPod)
	_, err = kubectl(ctx, cfg, src.Cluster, "-n", "ectobase-system", "delete", "pod", oldPod, "--wait=false")
	require.NoError(t, err, "delete flowplane pod %s", oldPod)

	// --- [5] wait for a NEW flowplane pod that logged the netkit adopt re-point ---
	var newPod string
	eventually(t, 120*time.Second, 3*time.Second, func() error {
		p, err := flowplanePod(ctx, cfg, src.Cluster)
		if err != nil || p == "" || p == oldPod {
			return fmt.Errorf("new flowplane pod not up yet (cur=%q old=%q)", p, oldPod)
		}
		logs, _ := kubectl(ctx, cfg, src.Cluster, "-n", "ectobase-system", "logs", p)
		if !strings.Contains(logs, "adopt: re-pointed pinned link") {
			return fmt.Errorf("new pod %s has not logged the adopt re-point yet", p)
		}
		newPod = p
		return nil
	})
	t.Logf("restarted: %s -> %s (logged adopt re-point)", oldPod, newPod)

	// --- [5b] wait for the ping to finish; parse sent/received ---
	waitErr := pingCmd.Wait() // ping exits non-zero on any loss — expected, not fatal
	sent, recv := parsePingStats(pingOut.String())
	lost := sent - recv
	t.Logf("ping: sent=%d received=%d lost=%d (threshold=%d) waitErr=%v", sent, recv, lost, restartLossThresh, waitErr)
	if last := lastPingLines(pingOut.String(), 3); last != "" {
		t.Logf("ping tail:\n%s", last)
	}

	// --- [6] record POST state ---
	progPost, err := linkProgID(ctx, nodePID, guestPin)
	require.NoError(t, err, "read post-restart guest link prog-id")
	pinPost := hostPinExists(nodePID, guestPin)
	t.Logf("POST: guest link %s prog-id=%d pin=%v flowplane pod=%s", guestPin, progPost, pinPost, newPod)

	// --- [7] assertions ---
	// 7a. loss within threshold (and non-degenerate: sent>0).
	require.Greater(t, sent, 0, "ping sent 0 packets — endpoint or routing setup failed")
	require.LessOrEqualf(t, lost, restartLossThresh,
		"packet loss %d/%d exceeds threshold %d (%d%%) — a REAL forwarding gap across the netkit restart",
		lost, sent, restartLossThresh, lost*100/sent)
	// 7b. pinned netkit link survived the pod delete.
	require.Truef(t, pinPost, "guest netkit link pin %s VANISHED across the restart — link was not persisted", guestPin)
	// 7c. prog-id changed => atomic BPF_LINK_UPDATE re-point (readopt_netkit_link), not the same
	//     program (and not a drop / detach+reattach).
	require.NotZero(t, progPost, "no prog on the guest netkit link after restart — datapath dropped entirely")
	require.NotEqualf(t, progPre, progPost,
		"guest netkit link prog-id did NOT change (%d) — the pinned link was not re-pointed (readopt_netkit_link didn't run, or a detach+reattach happened)", progPre)

	t.Logf("netkit graceful-restart zero-drop continuity: loss=%d/%d pin=survived(%v->%v) prog-id=%d->%d (atomic BPF_LINK_UPDATE re-point)",
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

// linkProgID returns the prog-id bound to the pinned bpf link at `pin` on the node's bpffs, read with
// the HOST bpftool against the pin reached through /proc/<nodePID>/root (bpf links are kernel-global;
// the pin is a node hostPath). A bpf_link_update re-point changes this prog-id. Returns 0 on absent pin.
func linkProgID(ctx context.Context, nodePID, pin string) (int, error) {
	hostPin := fmt.Sprintf("/proc/%s/root%s", nodePID, pin)
	out, err := labexec.SudoOutput(ctx, "bpftool", "-j", "link", "show", "pinned", hostPin)
	// bpftool reliably emits the link JSON on stdout but can still exit non-zero (255) when the pin is
	// opened through a /proc/<pid>/root path (a libbpf teardown/feature-probe quirk), so parse the
	// output regardless and only surface the exec error if no prog_id could be extracted. Output is a
	// bare object `{"prog_id":N,...}` on current bpftool; tolerate an array form too.
	trimmed := bytes.TrimSpace(out)
	var obj struct {
		ProgID int `json:"prog_id"`
	}
	if json.Unmarshal(trimmed, &obj) == nil && obj.ProgID != 0 {
		return obj.ProgID, nil
	}
	var arr []struct {
		ProgID int `json:"prog_id"`
	}
	if json.Unmarshal(trimmed, &arr) == nil {
		for _, e := range arr {
			if e.ProgID != 0 {
				return e.ProgID, nil
			}
		}
	}
	if err != nil {
		return 0, fmt.Errorf("bpftool link show pinned %s: %w\n%s", hostPin, err, out)
	}
	return 0, fmt.Errorf("no prog_id in bpftool json %q", out)
}

// hostPinExists reports whether a node bpffs pin is present, via /proc/<nodePID>/root (the test runs
// as root, so it can stat the root-owned node bpffs).
func hostPinExists(nodePID, pin string) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%s/root%s", nodePID, pin))
	return err == nil
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
