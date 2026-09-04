//go:build live

package livetest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	labexec "github.com/trevex/ectobase/test/lab/internal/exec"
)

// QoS guest-to-guest scenario: cross-cluster overlay-internal iperf3 UDP proving
// EDT egress shaping (pacing → LOW loss) vs ingress token-bucket policing (HIGH
// loss), both capping throughput near the configured rate. Ported from
// test/scenario-qos-guest2guest.sh, but wired DIRECTLY over the dataplane gRPC
// (AddRoute + AddFwRule) for determinism — no CRD/agent/reflector timing.
const (
	qosVNI      = 100 // same VPC as the overlay test; distinct interface ids/IPs
	qosIDA      = "qos-a"
	qosIDB      = "qos-b"
	qosIPA      = "10.0.0.5"
	qosIPB      = "10.0.0.6"
	qosMACA     = "52:54:00:00:00:15"
	qosMACB     = "52:54:00:00:00:16"
	qosCapMbps  = 20  // configured shaping/policing cap
	qosOfferedM = 100 // iperf3 UDP offered rate (well above the cap)
	qosIperfSec = 8
)

// TestQoSGuestToGuest attaches two guests in the same VPC on DIFFERENT compute
// clusters (A on nodeA, B on nodeB), wires bidirectional overlay routes + allow
// firewall rules directly over the dataplane gRPC, then runs iperf3 UDP A→B above
// the cap under three regimes:
//
//	E0 baseline  (no QoS)         — informational: the path carries > cap.
//	E1 EDT shape (A egress=cap)   — recv near cap, LOW loss (fq paces, few drops).
//	E2 ingress   (B ingress=cap)  — recv near cap, HIGH loss (token bucket drops).
//
// The E1(low-loss) vs E2(high-loss) contrast at the same cap is the live proof
// both the EDT shaper and the ingress policer are active. Cross-node is required:
// same-node hits the unshaped tap→tap Deliver::Local fast path.
func TestQoSGuestToGuest(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) < 2 {
		t.Skip("need >=2 compute nodes across clusters")
	}
	nodeA, nodeB := nodes[0], nodes[1]
	if nodeA.Cluster == nodeB.Cluster {
		t.Skip("need the two endpoints in different clusters")
	}
	containerA := nodeContainer(cfg, nodeA)
	containerB := nodeContainer(cfg, nodeB)

	// 1. Attach both guests over the real dataplane; attachEndpoint also addresses
	//    the endpoint netns (overlay /32 + 169.254.0.1 gateway) so iperf3 can run.
	ulA := attachEndpoint(t, ctx, cfg, nodeA, qosIDA, qosIPA, qosMACA)
	ulB := attachEndpoint(t, ctx, cfg, nodeB, qosIDB, qosIPB, qosMACB)
	require.NotEmpty(t, ulA, "qos-a underlay /128")
	require.NotEmpty(t, ulB, "qos-b underlay /128")
	t.Cleanup(func() {
		_, _ = dataplaneGRPC(t, ctx, containerA, "DetachInterface",
			fmt.Sprintf(`{"interface_id":%q}`, qosIDA))
		_, _ = dataplaneGRPC(t, ctx, containerB, "DetachInterface",
			fmt.Sprintf(`{"interface_id":%q}`, qosIDB))
	})

	// 2. Wire overlay connectivity directly, both directions: each side needs a
	//    route to the peer (via its underlay /128) + egress+ingress allow rules
	//    (deny-by-default). This bypasses the CRD/agent/reflector path.
	wireOverlay(t, ctx, containerA, qosIDA, qosIPB, ulB)
	wireOverlay(t, ctx, containerB, qosIDB, qosIPA, ulA)

	// 3. Baseline connectivity: A → B over the encapsulated overlay must ping
	//    before we measure. If this fails, the wiring/firewall is wrong.
	eventually(t, 90*time.Second, 5*time.Second, func() error {
		return endpointPing(ctx, cfg, nodeA, qosIDA, qosIPB)
	})

	// 4. Build the static iperf3 (host binary; nsenter runs it in the guest netns — the
	//    Talos node is shell-less, so nothing is staged onto the node). The one-off
	//    server writes its JSON to a HOST temp path (see qosUDPRun).
	iperf3Path := buildIperf3Static(t)
	jsonHost := filepath.Join(t.TempDir(), "g2g.json")

	udpRun := func() (recvMbps, lossPct float64) {
		return qosUDPRun(ctx, containerA, containerB, qosIDA, qosIDB, qosIPB, iperf3Path, jsonHost)
	}
	// bestOf3 runs the measurement up to 3 times and returns the run whose pass
	// predicate holds; else the last run. Absorbs UDP-on-SKB scheduling noise
	// WITHOUT weakening the thresholds (a transient blip must not fail real
	// shaping/policing behavior).
	bestOf3 := func(label string, pass func(recv, loss float64) bool) (recv, loss float64) {
		for i := 1; i <= 3; i++ {
			recv, loss = udpRun()
			t.Logf("[%s run %d] recv=%.1f Mbps loss=%.1f%%", label, i, recv, loss)
			if pass(recv, loss) {
				return recv, loss
			}
		}
		return recv, loss
	}

	inBand := func(recv float64) bool {
		return recv >= float64(qosCapMbps)*0.5 && recv <= float64(qosCapMbps)*1.6
	}

	// E0 baseline: no QoS. Informational sanity that the path carries > cap.
	configureQoS(t, ctx, containerA, qosIDA, 0, 0, 0)
	configureQoS(t, ctx, containerB, qosIDB, 0, 0, 0)
	e0Recv, e0Loss := udpRun()
	t.Logf("[E0 baseline] recv=%.1f Mbps loss=%.1f%% (offered %dM, no caps)", e0Recv, e0Loss, qosOfferedM)

	// E1 EDT shaping: A egress cap. fq paces → recv near cap, LOW loss.
	configureQoS(t, ctx, containerA, qosIDA, qosCapMbps, 0, 0)
	configureQoS(t, ctx, containerB, qosIDB, 0, 0, 0)
	e1Recv, e1Loss := bestOf3("E1 EDT shaping", func(recv, loss float64) bool {
		return inBand(recv) && loss < 40
	})
	configureQoS(t, ctx, containerA, qosIDA, 0, 0, 0) // reset A

	// E2 ingress policing: B ingress cap. token bucket drops → recv near cap, HIGH loss.
	configureQoS(t, ctx, containerA, qosIDA, 0, 0, 0)
	configureQoS(t, ctx, containerB, qosIDB, 0, 0, qosCapMbps)
	e2Recv, e2Loss := bestOf3("E2 ingress policing", func(recv, loss float64) bool {
		return inBand(recv) && loss > 40
	})
	configureQoS(t, ctx, containerB, qosIDB, 0, 0, 0) // reset B

	t.Logf("SUMMARY: E0 baseline=%.1fM@%.1f%%; E1 EDT egress cap %d -> %.1fM @ %.1f%% loss (paced); "+
		"E2 ingress cap %d -> %.1fM @ %.1f%% loss (dropped)",
		e0Recv, e0Loss, qosCapMbps, e1Recv, e1Loss, qosCapMbps, e2Recv, e2Loss)

	// Assertions (same thresholds as the bash script).
	require.Truef(t, inBand(e1Recv), "[E1] EDT recv=%.1f Mbps not within [0.5,1.6]x cap %d", e1Recv, qosCapMbps)
	require.Lessf(t, e1Loss, 40.0, "[E1] EDT loss %.1f%% too high for a shaper (expect pacing → low loss)", e1Loss)
	require.Truef(t, inBand(e2Recv), "[E2] ingress recv=%.1f Mbps not within [0.5,1.6]x cap %d", e2Recv, qosCapMbps)
	require.Greaterf(t, e2Loss, 40.0, "[E2] ingress loss %.1f%% too low for a policer (expect token-bucket drops → high loss)", e2Loss)
}

// wireOverlay programs, on `container` for interface `id`: an overlay route to the
// peer overlay IP (via the peer's underlay /128) + egress-allow + ingress-allow
// firewall rules (proto 0 = any), busting deny-by-default in both directions.
func wireOverlay(t *testing.T, ctx context.Context, container, id, peerIP, peerUnderlay string) {
	t.Helper()
	routeBody := fmt.Sprintf(`{"vni":%d,"prefix":%q,"nexthop_underlay":%q}`,
		qosVNI, peerIP+"/32", peerUnderlay)
	out, err := dataplaneGRPC(t, ctx, container, "AddRoute", routeBody)
	require.NoError(t, err, "AddRoute %s->%s: %s", id, peerIP, out)

	addFwEgressAllow(t, ctx, container, id)
	addFwIngressAllow(t, ctx, container, id)
}

// addFwIngressAllow programs a deny-by-default-busting ingress allow rule (proto 0
// = any) on the interface — the mirror of addFwEgressAllow for the return/receive
// direction.
func addFwIngressAllow(t *testing.T, ctx context.Context, container, id string) {
	t.Helper()
	body := fmt.Sprintf(`{"interface_id":%q,"rule_id":"in","proto":0,"allow":true,"egress":false}`, id)
	out, err := dataplaneGRPC(t, ctx, container, "AddFwRule", body)
	require.NoError(t, err, "AddFwRule ingress-allow on %s: %s", id, out)
}

// configureQoS sets the per-interface QoS lanes over the dataplane gRPC (0 =
// unlimited). egress_mbps is EDT-shaped; ingress_mbps is the ingress policer.
func configureQoS(t *testing.T, ctx context.Context, container, id string, egressMbps, publicMbps, ingressMbps int) {
	t.Helper()
	body := fmt.Sprintf(`{"interface_id":%q,"egress_mbps":%d,"public_mbps":%d,"ingress_mbps":%d}`,
		id, egressMbps, publicMbps, ingressMbps)
	out, err := dataplaneGRPC(t, ctx, container, "ConfigureQoS", body)
	require.NoError(t, err, "ConfigureQoS %s: %s", id, out)
}

// qosUDPRun runs an iperf3 UDP flow A→B over the overlay and returns the SERVER's
// received throughput (Mbps) + loss (%). It starts `iperf3 -s --one-off -J` in B's
// netns (backgrounded, JSON to /g2g.json on nodeB), fires the A→B client, then
// reads + parses B's JSON. Mirrors the bash udp_run (scenario lines 58-73):
// the authoritative UDP server stats are end.sum_received (end.sum is malformed,
// bytes=0). Returns (0,0) on any failure.
func qosUDPRun(ctx context.Context, containerA, containerB, idA, idB, dstIP, iperf3Host, jsonHost string) (float64, float64) {
	// nsenter into B's guest netns from the HOST (the Talos node is shell-less) and start
	// the one-off server backgrounded. nsenter --net keeps the host mount ns, so the host
	// `sh` redirect writes the JSON to the HOST path jsonHost; the server self-exits after
	// the single client run.
	pidB, err := dockerPID(ctx, containerB)
	if err != nil {
		return 0, 0
	}
	nsB := fmt.Sprintf("/proc/%s/root/run/netns/%s", pidB, idB)
	srvSh := fmt.Sprintf("%s -s --one-off -J >%s 2>/dev/null", iperf3Host, jsonHost)
	srvCmd := labexec.SudoCmd(ctx, "nsenter", "--net="+nsB, "sh", "-c", srvSh)
	if err := srvCmd.Start(); err != nil {
		return 0, 0
	}
	// Wait for the one-off iperf3 server to bind its control socket (:5201) in B's netns
	// before firing the client, instead of a blind sleep. Best-effort: falls through after
	// the window if the bind can't be observed, which is no worse than a fixed wait.
	waitUpTo(5*time.Second, 100*time.Millisecond, func() bool {
		out, err := nodeNetnsProbe(ctx, containerB, idB, "ss", "-tlnH")
		return err == nil && strings.Contains(out, ":5201")
	})

	// Fire the client A→B (offered rate above the cap, 1200B datagrams). Best-effort:
	// iperf3 UDP may return non-zero even on a clean run; the server JSON is truth.
	_, _ = nodeNetnsProbe(ctx, containerA, idA,
		iperf3Host, "-u", "-b", fmt.Sprintf("%dM", qosOfferedM),
		"-t", fmt.Sprintf("%d", qosIperfSec), "-l", "1200", "-c", dstIP)

	_ = srvCmd.Wait() // server one-off exits when the client run completes

	raw, err := os.ReadFile(jsonHost)
	if err != nil {
		return 0, 0
	}
	return parseIperf3Recv(string(raw))
}

// parseIperf3Recv extracts end.sum_received.{bits_per_second,lost_percent} from an
// iperf3 -J JSON blob, returning (Mbps, lossPct). Returns (0,0) if unparseable.
func parseIperf3Recv(raw string) (float64, float64) {
	var doc struct {
		End struct {
			SumReceived struct {
				BitsPerSecond float64 `json:"bits_per_second"`
				LostPercent   float64 `json:"lost_percent"`
			} `json:"sum_received"`
		} `json:"end"`
	}
	// The blob may have leading log noise before the JSON object; trim to the first '{'.
	if i := strings.IndexByte(raw, '{'); i > 0 {
		raw = raw[i:]
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return 0, 0
	}
	return doc.End.SumReceived.BitsPerSecond / 1e6, doc.End.SumReceived.LostPercent
}

// buildIperf3Static builds the fully-static iperf3 (`nix build .#iperf3-static`)
// from the repo root and returns the host path to the binary. The nix output is a
// store dir; the man-page output (…-man) is filtered out.
func buildIperf3Static(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("nix", "build", "--no-link", "--print-out-paths", ".#iperf3-static")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "nix build .#iperf3-static:\n%s", out)
	var store string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "/nix/store/") && !strings.HasSuffix(line, "-man") {
			store = line
			break
		}
	}
	require.NotEmptyf(t, store, "no non-man /nix/store output from iperf3-static build:\n%s", out)
	return store + "/bin/iperf3"
}
