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

	"github.com/trevex/ectobase/test/lab/internal/config"
	labexec "github.com/trevex/ectobase/test/lab/internal/exec"
	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

// edgeNexthop is a fabric-routable /128 in the edge DNS64 loopback range
// (fabric.EdgeLoopback / LoopAggr fd00:ffff::/32, advertised into the fabric). Used
// as the NAT-egress external-route nexthop: the node's route lookup resolves it and
// transmits the IPIP-encapped frame on an uplink, which is all the SNAT sniff needs
// (the edges are FRR NAT64 routers here, not flowplane, so we assert SNAT AT THE
// NODE UPLINK, not end-to-end internet).
const edgeNexthop = fabric.EdgeLoopback + "::e1"

// guestGWMAC is the router MAC the datapath advertises to guests (GW_MAC); probes
// use it as the L2 dst for egress frames. Matches the dataplane's gateway MAC.
const guestGWMAC = "02:00:00:00:00:01"

// attachGuest creates a guest netns on the node (via the flowplane pod, which
// hostPath-mounts the node's /var/run/netns), calls AttachInterface over the real
// dataplane with the given (dual-stack) IPs and MAC, brings the in-netns guest iface
// up (named == id) so AF_PACKET probes can bind, and returns the allocated underlay
// /128. Idempotent: reuses an already-attached endpoint's underlay.
//
// Unlike overlay_test.go's attachEndpoint, this does NOT address the netns (the
// datapath probes speak raw L2 over AF_PACKET) and it accepts multiple requested_ips.
func attachGuest(t *testing.T, ctx context.Context, cfg *config.Config, node config.DerivedNode, id string, ips []string, mac string) string {
	t.Helper()
	container := nodeContainer(cfg, node)
	pod, err := flowplanePod(ctx, cfg, node.Cluster)
	require.NoError(t, err)

	if out, err := dataplaneGRPC(t, ctx, container, "ListInterfaces", ""); err == nil {
		if ul := underlayForID(out, id); ul != "" {
			bringUpGuest(ctx, cfg, node, pod, id)
			return ul
		}
	}

	_, _ = kubectl(ctx, cfg, node.Cluster, "-n", "ectobase-system", "exec", pod, "--",
		"ip", "netns", "add", id)

	quoted := make([]string, len(ips))
	for i, ip := range ips {
		quoted[i] = fmt.Sprintf("%q", ip)
	}
	req := fmt.Sprintf(`{"interface_id":%q,"netns_path":"/var/run/netns/%s","vni":%d,"mac":%q,"requested_ips":[%s]}`,
		id, id, overlayVNI, mac, strings.Join(quoted, ","))
	out, err := dataplaneGRPC(t, ctx, container, "AttachInterface", req)
	require.NoError(t, err, "AttachInterface %s on %s: %s", id, node.Cluster, out)
	underlay := firstUnderlay(out)
	require.NotEmpty(t, underlay, "no underlay in AttachInterface response for %s: %s", id, out)

	bringUpGuest(ctx, cfg, node, pod, id)
	return underlay
}

// bringUpGuest sets the in-netns guest iface up (best-effort, idempotent).
func bringUpGuest(ctx context.Context, cfg *config.Config, node config.DerivedNode, pod, id string) {
	sh := fmt.Sprintf("ip netns exec %s ip link set %s up 2>/dev/null; true", id, id)
	_, _ = kubectl(ctx, cfg, node.Cluster, "-n", "ectobase-system", "exec", pod, "--", "sh", "-c", sh)
}

// addFwEgressAllow programs a deny-by-default-busting egress allow rule (proto 0 =
// any) on the guest interface, required or all guest egress is dropped.
func addFwEgressAllow(t *testing.T, ctx context.Context, container, id string) {
	t.Helper()
	body := fmt.Sprintf(`{"interface_id":%q,"rule_id":"eg","proto":0,"allow":true,"egress":true}`, id)
	out, err := dataplaneGRPC(t, ctx, container, "AddFwRule", body)
	require.NoError(t, err, "AddFwRule egress-allow on %s: %s", id, out)
}

// buildStaticBin compiles a cmd/<pkg> to a CGO_ENABLED=0 static binary in t.TempDir()
// (runs inside the Ubuntu-based kind node after docker cp). Returns the host path.
// The packet-test probes (tap-dhcp-probe, netprobe, ...) live in the sibling
// test/e2e module, so we build ./cmd/<pkg> from there regardless of the test's CWD.
func buildStaticBin(t *testing.T, pkg string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), pkg)
	cmd := exec.Command("go", "build", "-o", out, "./cmd/"+pkg)
	cmd.Dir = filepath.Join(repoRoot(t), "test", "e2e")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/%s: %v\n%s", pkg, err, o)
	}
	return out
}

// nodeExec runs a command inside a container via `sudo docker exec`. It works on the
// SHELL-FUL clab containers (the FRR switches/edges and the wan gateway — e.g. lb_test
// programming a route on `wan`), but NOT on the compute Talos node containers, which are
// shell-less: those are reached via nsenter (node/guest netns, host binaries) and the
// flowplane pod instead. Do not use this against a compute node on the Talos substrate.
func nodeExec(ctx context.Context, container string, args ...string) (string, error) {
	full := append([]string{"docker", "exec", container}, args...)
	out, err := labexec.SudoOutput(ctx, full...)
	return string(out), err
}

// nodeNetnsProbe runs args in the guest netns <id> on the node, via nsenter from the
// HOST into that netns. The Talos node is shell-less, so we run HOST binaries (nsenter
// --net changes only the net namespace, not the mount namespace) in the guest netns —
// the netns file is the node's /run/netns/<id> (created via the flowplane pod, which
// hostPath-mounts the node's /run), reached through the node container's /proc/<pid>/root.
// Binary paths in args must therefore be HOST paths.
func nodeNetnsProbe(ctx context.Context, container, id string, args ...string) (string, error) {
	pid, err := dockerPID(ctx, container)
	if err != nil {
		return "", err
	}
	ns := fmt.Sprintf("/proc/%s/root/run/netns/%s", pid, id)
	full := append([]string{"nsenter", "--net=" + ns}, args...)
	out, err := labexec.SudoOutput(ctx, full...)
	return string(out), err
}

// asJSON is a tiny helper to keep request-building readable in tests.
func asJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// waitDeadline is the default per-datapath-assertion budget.
const waitDeadline = 90 * time.Second
