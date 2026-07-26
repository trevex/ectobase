package e2e

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestCrossNodeOverlayPing brings up the IPv6 fabric, deploys the flowplane DaemonSet on the
// k01 cluster (so flowplane runs in BOTH k01 nodes), attaches one overlay endpoint per node,
// programs the cross-node routes via AddRoute, and asserts ping works over the IP-in-IPv6
// overlay — then that WithdrawRoute breaks it. SKIPs (never fails) without the host tooling.
//
// Mechanism (same host). flowplane runs as the DaemonSet pod (hostNetwork, gRPC on
// 127.0.0.1:1337, mounts the node's /var/run/netns), exactly as production. The kind-node
// image bundles NEITHER flowplane NOR grpcurl, but we are on the same host as the node
// containers, so we drive each node's node-local gRPC with the HOST grpcurl entered into that
// node's network namespace via `nsenter -t <node-pid> -n` — no in-node client tooling needed.
// This mirrors hack/multicluster-e2e.sh (the cross-CLUSTER variant); here it is single-cluster
// cross-NODE (k01 control-plane <-> worker) plus the WithdrawRoute negative check.
func TestCrossNodeOverlayPing(t *testing.T) {
	for _, bin := range []string{"containerlab", "kind", "docker", "kubectl", "grpcurl", "nsenter", "sudo"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	grpcurlBin, err := exec.LookPath("grpcurl")
	if err != nil {
		t.Skip("grpcurl not installed")
	}
	nsenterBin, err := exec.LookPath("nsenter")
	if err != nil {
		t.Skip("nsenter not installed")
	}
	protoDir, err := filepath.Abs("../../api/proto/dataplane/v1")
	if err != nil {
		t.Fatalf("resolve proto dir: %v", err)
	}

	// Shared fabric constants come from env.go (mirrors hack/clab/env.sh); ipB has no env.sh
	// equivalent (it is the second, test-local endpoint on the worker).
	var (
		cp       = NodeA                  // k01-control-plane
		wk       = WorkerNode             // k01-worker
		cluster  = KindCentral            // k01
		vni      = fmt.Sprint(FabricVNI)  // "100"
		ipA      = OverlayIPA             // 10.0.0.1
		grpcAddr = DataplaneAddrFromEnv() // 127.0.0.1:1337
		image    = FlowplaneImageFromEnv()
	)
	const (
		ipB = "10.0.0.2"

		deployTimeout = 15 * time.Minute
		cmdTimeout    = 5 * time.Minute
	)

	// 1. Fabric up; always tear it down.
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

	run := func(name string, args ...string) (string, error) {
		return runWithTimeout(exec.Command(name, args...), cmdTimeout)
	}

	// 2. k01 kubeconfig (per-run temp file).
	kubeconfig := filepath.Join(t.TempDir(), "k01.kubeconfig")
	if out, err := run("sh", "-c", fmt.Sprintf("kind get kubeconfig --name %s > %s", cluster, kubeconfig)); err != nil {
		t.Fatalf("kind get kubeconfig: %v\n%s", err, out)
	}
	kubectl := func(args ...string) (string, error) {
		return run("kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...)
	}

	// 3. Load the flowplane image into k01 and deploy the DaemonSet — it runs on BOTH nodes
	//    (tolerations: operator Exists), giving us flowplane on the control-plane and worker.
	//    No CRDs/agent needed: this test programs routes MANUALLY via AddRoute.
	if out, err := run("kind", "load", "docker-image", image, "--name", cluster); err != nil {
		t.Fatalf("kind load flowplane image: %v\n%s", err, out)
	}
	for _, f := range []string{"namespace.yaml", "rbac.yaml", "flowplane.yaml"} {
		if out, err := kubectl("apply", "-f", "../../config/deploy/"+f); err != nil {
			t.Fatalf("apply %s: %v\n%s", f, err, out)
		}
	}
	if out, err := kubectl("-n", "ectobase-system", "rollout", "status", "ds/flowplane", "--timeout=120s"); err != nil {
		t.Fatalf("flowplane DS not ready: %v\n%s", err, out)
	}

	// 4. Node-local gRPC: HOST grpcurl entered into the node's netns (same host, no in-node
	//    grpcurl). `docker inspect` gives the node container's host PID for `nsenter -n`.
	nodePID := func(node string) (string, error) {
		out, err := run("docker", "inspect", "-f", "{{.State.Pid}}", node)
		return strings.TrimSpace(out), err
	}
	grpcIn := func(node, method, body string) (string, error) {
		pid, err := nodePID(node)
		if err != nil {
			return "", fmt.Errorf("node pid for %s: %w", node, err)
		}
		return run("sudo", nsenterBin, "-t", pid, "-n", grpcurlBin,
			"-import-path", protoDir, "-proto", "dataplane.proto",
			"-plaintext", "-d", body, grpcAddr, method)
	}
	dockerExec := func(node string, args ...string) (string, error) {
		return run("docker", append([]string{"exec", node}, args...)...)
	}

	// 5. Attach one endpoint per node; capture the allocated underlay /128 (the AddRoute nexthop).
	ulRe := regexp.MustCompile(`fd00:[0-9a-f:]+`)
	attach := func(node, id, ip string) string {
		if _, err := dockerExec(node, "ip", "netns", "add", id); err != nil {
			t.Logf("netns add %s on %s (may exist): %v", id, node, err)
		}
		body := fmt.Sprintf(`{"interface_id":%q,"netns_path":"/var/run/netns/%s","vni":%s,"requested_ips":[%q]}`,
			id, id, vni, ip)
		out, err := grpcIn(node, "dataplane.v1.DataplaneNode/AttachInterface", body)
		if err != nil {
			t.Fatalf("attach %s on %s: %v\n%s", id, node, err, out)
		}
		ul := ulRe.FindString(out)
		if ul == "" {
			t.Fatalf("attach %s on %s returned no underlay /128\n%s", id, node, out)
		}
		// dpservice-model addressing inside the endpoint netns (guest dev is named = interface_id).
		if _, err := dockerExec(node, "sh", "-c", fmt.Sprintf(
			"ip netns exec %s ip addr add %s/32 dev %s; "+
				"ip netns exec %s ip route add 169.254.0.1/32 dev %s; "+
				"ip netns exec %s ip route add default via 169.254.0.1 dev %s",
			id, ip, id, id, id, id, id)); err != nil {
			t.Fatalf("configure netns %s on %s: %v", id, node, err)
		}
		// The datapath firewall is deny-by-default. This manual path has no agent/CompiledNIC to
		// program allow rules (unlike hack/multicluster-e2e.sh), so open the endpoint both
		// directions ourselves (proto 0 = any, covers the ICMP echo + reply). Without this the
		// cross-node overlay ping is dropped at the firewall even though routing is correct.
		fw := func(ruleID string, egress bool) {
			body := fmt.Sprintf(`{"interface_id":%q,"rule_id":%q,"proto":0,"allow":true,"egress":%t}`,
				id, ruleID, egress)
			if out, err := grpcIn(node, "dataplane.v1.DataplaneNode/AddFwRule", body); err != nil {
				t.Fatalf("AddFwRule %s on %s/%s: %v\n%s", ruleID, node, id, err, out)
			}
		}
		fw("allow-egress", true)
		fw("allow-ingress", false)
		return ul
	}
	ulA := attach(cp, "ep-a", ipA)
	ulB := attach(wk, "ep-b", ipB)
	t.Logf("underlay: %s(%s)=%s  %s(%s)=%s", cp, ipA, ulA, wk, ipB, ulB)

	// 6. Program cross-node routes: cp learns B via wk's underlay; wk learns A via cp's underlay.
	addRoute := func(node, prefix, nexthop string) {
		body := fmt.Sprintf(`{"vni":%s,"prefix":%q,"nexthop_underlay":%q}`, vni, prefix, nexthop)
		if out, err := grpcIn(node, "dataplane.v1.DataplaneNode/AddRoute", body); err != nil {
			t.Fatalf("AddRoute on %s: %v\n%s", node, err, out)
		}
	}
	addRoute(cp, ipB+"/32", ulB)
	addRoute(wk, ipA+"/32", ulA)

	// 7. Stage busybox (the node image has no ping) into cp, then ping B from A's netns.
	busybox := filepath.Join(t.TempDir(), "busybox")
	if out, err := run("sh", "-c", fmt.Sprintf(
		`cid=$(docker create busybox:musl) && docker cp "$cid":/bin/busybox %s && docker rm "$cid" >/dev/null`,
		busybox)); err != nil {
		t.Fatalf("stage busybox: %v\n%s", err, out)
	}
	if out, err := run("docker", "cp", busybox, cp+":/busybox"); err != nil {
		t.Fatalf("copy busybox into %s: %v\n%s", cp, err, out)
	}
	pingOK := func() bool {
		out, err := dockerExec(cp, "ip", "netns", "exec", "ep-a", "/busybox", "ping", "-c", "2", "-W", "1", ipB)
		return err == nil && strings.Contains(out, " 0% packet loss")
	}
	pinged := false
	for range 15 {
		if pingOK() {
			pinged = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !pinged {
		t.Fatal("cross-node overlay ping A->B never succeeded")
	}

	// 8. Withdraw A's route to B; ping must now fail (route gone => Pass, no encap).
	if out, err := grpcIn(cp, "dataplane.v1.DataplaneNode/WithdrawRoute",
		fmt.Sprintf(`{"vni":%s,"prefix":%q}`, vni, ipB+"/32")); err != nil {
		t.Fatalf("WithdrawRoute on %s: %v\n%s", cp, err, out)
	}
	stillDown := false
	for range 5 {
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
