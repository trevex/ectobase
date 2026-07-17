package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestCrossNodeOverlayPing brings up the IPv6 fabric, runs flowplane on both kind
// nodes with one endpoint each, programs the cross-node routes via AddRoute, and
// asserts ping works over the IP-in-IPv6 overlay — then that WithdrawRoute breaks
// it. SKIPs (never fails) without containerlab/kind/docker, like the sibling tests.
func TestCrossNodeOverlayPing(t *testing.T) {
	for _, bin := range []string{"containerlab", "kind", "docker"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	const (
		cp   = "k01-control-plane"
		wk   = "k01-worker"
		vni  = "100"
		ipA  = "10.0.0.1"
		ipB  = "10.0.0.2"
		nhA  = "fd00:db8:0:1::a" // control-plane endpoint underlay (within cp's /64)
		nhB  = "fd00:db8:0:2::a" // worker endpoint underlay (within wk's /64)
		grpcAddr      = "127.0.0.1:1337"
		deployTimeout = 15 * time.Minute
		cmdTimeout    = 5 * time.Minute
	)

	up := exec.Command("../../hack/clab-up.sh")
	up.Env = testEnv()
	if out, err := runWithTimeout(up, deployTimeout); err != nil {
		t.Fatalf("clab-up failed: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		down := exec.Command("../../hack/clab-down.sh")
		down.Env = testEnv()
		if out, err := runWithTimeout(down, cmdTimeout); err != nil {
			t.Logf("clab-down failed: %v\n%s", err, out)
		}
	})

	// dockerExec runs a command inside a kind node container.
	dockerExec := func(node string, args ...string) (string, error) {
		full := append([]string{"exec", node}, args...)
		out, err := runWithTimeout(exec.Command("docker", full...), cmdTimeout)
		return out, err
	}
	// grpcurlIn runs grpcurl inside a node against its local flowplane.
	grpcurlIn := func(node, method, body string) (string, error) {
		return dockerExec(node, "grpcurl", "-plaintext", "-d", body, grpcAddr, method)
	}

	// Start flowplane on each node (image already loaded by the fabric; serve in background).
	for _, node := range []string{cp, wk} {
		if _, err := dockerExec(node, "sh", "-c",
			"pkill -f 'flowplane serve' 2>/dev/null; (flowplane serve --grpc "+grpcAddr+" >/tmp/xdp.log 2>&1 &) ; sleep 3"); err != nil {
			t.Fatalf("start flowplane on %s: %v", node, err)
		}
	}

	// Create a netns + endpoint on each node via AttachInterface.
	attach := func(node, ip string) {
		ns := "ep"
		if _, err := dockerExec(node, "ip", "netns", "add", ns); err != nil {
			t.Logf("netns add on %s (may exist): %v", node, err)
		}
		body := fmt.Sprintf(`{"interface_id":"ep0","netns_path":"/var/run/netns/%s","vni":%s,"requested_ips":["%s"]}`, ns, vni, ip)
		if out, err := grpcurlIn(node, "dataplane.v1.DataplaneNode/AttachInterface", body); err != nil {
			t.Fatalf("attach on %s: %v\n%s", node, err, out)
		}
	}
	attach(cp, ipA)
	attach(wk, ipB)

	// Program cross-node routes: cp learns B via wk's underlay, wk learns A via cp's underlay.
	addRoute := func(node, prefix, nexthop string) {
		body := fmt.Sprintf(`{"vni":%s,"prefix":"%s","nexthop_underlay":"%s"}`, vni, prefix, nexthop)
		if out, err := grpcurlIn(node, "dataplane.v1.DataplaneNode/AddRoute", body); err != nil {
			t.Fatalf("AddRoute on %s: %v\n%s", node, err, out)
		}
	}
	addRoute(cp, ipB+"/32", nhB)
	addRoute(wk, ipA+"/32", nhA)

	// Ping B from A's netns over the overlay. Retry to allow neighbor/route settle.
	pingOK := func() bool {
		out, err := dockerExec(cp, "ip", "netns", "exec", "ep", "ping", "-c", "2", "-W", "1", ipB)
		if err == nil && strings.Contains(out, " 0% packet loss") {
			return true
		}
		return false
	}
	var pinged bool
	for i := 0; i < 15; i++ {
		if pingOK() {
			pinged = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !pinged {
		log, _ := dockerExec(cp, "cat", "/tmp/xdp.log")
		t.Fatalf("cross-node overlay ping A->B never succeeded\nflowplane log:\n%s", log)
	}

	// Withdraw A's route to B on the cp node; ping must now fail (route gone => Pass, no encap).
	body := fmt.Sprintf(`{"vni":%s,"prefix":"%s/32"}`, vni, ipB)
	if out, err := grpcurlIn(cp, "dataplane.v1.DataplaneNode/WithdrawRoute", body); err != nil {
		t.Fatalf("WithdrawRoute on %s: %v\n%s", cp, err, out)
	}
	stillDown := false
	for i := 0; i < 5; i++ {
		if !pingOK() {
			stillDown = true
			break
		}
		time.Sleep(time.Second)
	}
	if !stillDown {
		t.Fatal("ping still succeeded after WithdrawRoute; route was not removed")
	}
}
