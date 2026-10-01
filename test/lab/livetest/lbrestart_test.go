//go:build live

package livetest

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// lbRestartTimeout bounds each wait after an edge flowplane restart: the adopt line, the edge's maps,
// and the WAN reaching the LB again.
const lbRestartTimeout = 60 * time.Second

// lbRestart is this test's own load balancer. Its VNI, overlay subnet, pool slice and LB address are
// used by no other test: lbi holds 192.0.2.0/27 and nati 192.0.2.32/27 of the edge-owned prefix,
// and vm_overlay holds 10.0.6.0/24.
var lbRestart = lbIntent{
	prefix:     "lbr",
	vni:        207,
	subnet:     "10.0.8.0/24",
	poolPrefix: "192.0.2.64/27",
	lbIP:       "192.0.2.70",
	backendIP:  "10.0.8.10",
	mac:        "52:54:00:00:08:10",
	body:       "hello-restart-lb",
}

// adoptLbsRe matches the line flowplane logs once ControlCore::adopt_lbs has rebuilt its load
// balancers from the pinned LB and MAGLEV maps (control/bringup.rs).
var adoptLbsRe = regexp.MustCompile(`adopt: recovered (\d+) load balancer\(s\) from pinned maps`)

// TestEdgeLBSurvivesFlowplaneRestart restarts each edge's flowplane under a live N/S load balancer
// from intent, then deletes the load balancer.
//
// The pinned maps always kept the LB rows across a restart. What a restart lost was flowplane's own
// record of them, so a delete after it found no load balancer by that name and left the rows in
// place. This test asserts that each restarted flowplane adopted the LB from its maps, that the WAN
// still reaches it, and that a delete after both restarts empties both edges' maps.
//
// What it does not prove: anything about the restart window itself (no traffic is measured while
// flowplane is down), or that each edge forwards on its own after its restart. The WAN ECMPs each
// flow to either edge, so one curl shows only that some edge answers; each edge's maps are checked
// directly instead. It covers a v4 LB on the edge role only.
func TestEdgeLBSurvivesFlowplaneRestart(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("need at least one compute node")
	}
	wan := clab.ContainerName(cfg.Name, "wan")
	l := lbRestart

	backendVTEP := setUpLbFromIntent(t, ctx, cfg, nodes[0], l)

	// A failure between a stop and a start must not leave an edge without its flowplane. Registered
	// after the setup, so it runs BEFORE the setup's intent deletes (t.Cleanup is LIFO): an edge
	// whose flowplane is down when the LB is withdrawn would keep its rows.
	t.Cleanup(func() {
		for _, edge := range []string{"edge1", "edge2"} {
			_, _ = exec.SudoOutput(ctx, "docker", "start", clab.ContainerName(cfg.Name, "flowplane-"+edge))
		}
	})

	wanReachesLb := func() error {
		out := curlFromWanV4(ctx, wan, l.lbIP)
		if !strings.Contains(out, l.body) {
			return fmt.Errorf("curl http://%s/ from the WAN did not return %q:\n%s\n%s",
				l.lbIP, l.body, out, lbIntentDiagnostics(ctx, cfg))
		}
		return nil
	}

	// 1. Baseline: the WAN reaches the LB before anything is restarted, so a failure below is the
	//    restart's.
	eventually(t, lbIntentTimeout, 5*time.Second, wanReachesLb)

	// 2. Restart each edge's flowplane in turn, the other one serving meanwhile.
	for _, edge := range []string{"edge1", "edge2"} {
		container := clab.ContainerName(cfg.Name, "flowplane-"+edge)
		before, err := containerStartedAt(ctx, container)
		require.NoError(t, err)

		_, err = exec.SudoOutput(ctx, "docker", "restart", container)
		require.NoError(t, err, "docker restart %s", container)
		started, err := containerStartedAt(ctx, container)
		require.NoError(t, err)
		require.NotEqual(t, before, started, "%s did not restart", container)

		// The adopt line from THIS start. The log since the restart only: the previous run's log
		// can hold an adopt line of its own.
		var recovered int
		eventually(t, lbRestartTimeout, 2*time.Second, func() error {
			logs, lerr := containerLogsSince(ctx, container, started)
			if lerr != nil {
				return lerr
			}
			m := adoptLbsRe.FindStringSubmatch(logs)
			if m == nil {
				return fmt.Errorf("%s has not logged the LB adopt since %s:\n%s", container, started, tail(logs, 20))
			}
			recovered, _ = strconv.Atoi(m[1])
			return nil
		})
		require.GreaterOrEqual(t, recovered, 1,
			"%s adopted no load balancer from its pinned maps, but ours was there", container)
		t.Logf("%s: adopt recovered %d load balancer(s)", container, recovered)

		// The rows are still there and still name our backend, then the WAN still gets an answer.
		eventually(t, lbRestartTimeout, 5*time.Second, func() error {
			return edgeHasLb(ctx, cfg, edge, l.lbIP, 80, 6, backendVTEP, l.backendIP, l.vni)
		})
		eventually(t, lbRestartTimeout, 5*time.Second, wanReachesLb)
	}

	// 3. Delete the LoadBalancer. The backend agent stops announcing it, and each edge agent calls
	//    DelLoadBalancer on a flowplane that has restarted since it created the LB.
	_, err := kubectl(ctx, cfg, "dispatch", "delete", "loadbalancer.net.ectobase.dev", l.name("lb"), "--wait=false")
	require.NoError(t, err, "delete LoadBalancer %s", l.name("lb"))

	// The maps first: they are what a delete that silently did nothing would leave behind.
	for _, edge := range []string{"edge1", "edge2"} {
		edge := edge
		eventually(t, 2*time.Minute, 5*time.Second, func() error {
			return edgeLacksLb(ctx, edge, l.lbIP, 80, 6, backendVTEP, l.backendIP, l.vni)
		})
	}
	eventually(t, lbRestartTimeout, 5*time.Second, func() error {
		if out := curlFromWanV4(ctx, wan, l.lbIP); strings.Contains(out, l.body) {
			return fmt.Errorf("the WAN still reaches %s after the delete: %q", l.lbIP, strings.TrimSpace(out))
		}
		return nil
	})
}

// edgeLacksLb is edgeHasLb's negative: the edge's LB map has no key for the LB address and its MAGLEV
// map no slot naming the backend. The backend (its VNI and overlay address) belongs to this test
// alone, so a slot naming it is a table the delete left behind, not another load balancer's.
//
// It reads bpftool's stdout only and requires it to parse as JSON, so a dump that failed or
// printed nothing cannot pass as an empty map.
func edgeLacksLb(ctx context.Context, edge, lbIP string, port, proto int, backendVTEP, overlayIP string, vni int) error {
	dump := func(name string) (string, error) {
		pin := fmt.Sprintf("/sys/fs/bpf/flowplane-%s/%s", edge, name)
		out, err := exec.SudoOutput(ctx, "bpftool", "-j", "map", "dump", "pinned", pin)
		if err != nil {
			return "", fmt.Errorf("dump %s %s map: %w", edge, name, err)
		}
		if !json.Valid(out) {
			return "", fmt.Errorf("dump %s %s map: not JSON:\n%s", edge, name, tail(string(out), 10))
		}
		return normalizeHex(string(out)), nil
	}

	lbHex, err := dump("LB")
	if err != nil {
		return err
	}
	if key := lbKeyBytes(lbIP, port, proto); strings.Contains(lbHex, key) {
		return fmt.Errorf("%s still has an LB entry for %s:%d/proto%d (key %s)", edge, lbIP, port, proto, key)
	}

	mgHex, err := dump("MAGLEV")
	if err != nil {
		return err
	}
	backend := hexBytes(ipBytes(backendVTEP)) + hexBytes(ipBytes(overlayIP)) + hexBytes(le32(uint32(vni)))
	if strings.Contains(mgHex, backend) {
		return fmt.Errorf("%s Maglev map still holds backend %s (overlay %s, vni %d)", edge, backendVTEP, overlayIP, vni)
	}
	return nil
}

// containerStartedAt returns a container's State.StartedAt, an RFC 3339 timestamp `docker logs
// --since` accepts.
func containerStartedAt(ctx context.Context, container string) (string, error) {
	out, err := exec.SudoOutput(ctx, "docker", "inspect", "-f", "{{.State.StartedAt}}", container)
	if err != nil {
		return "", fmt.Errorf("docker inspect %s: %w", container, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// containerLogsSince is containerLogs from a point in time on. The 2>&1 is load-bearing for the same
// reason: flowplane logs to stderr, and `docker logs` replays it on its own stderr.
func containerLogsSince(ctx context.Context, container, since string) (string, error) {
	out, err := exec.SudoOutput(ctx, "sh", "-c",
		fmt.Sprintf("docker logs --since %s %s 2>&1", since, container))
	if err != nil {
		return "", fmt.Errorf("docker logs %s: %w", container, err)
	}
	return string(out), nil
}
