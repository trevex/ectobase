package e2e

// smoke_datapath_test.go — thin Go live-smoke: flowplane DaemonSet on k01 + netprobe
// send-sniff SNAT egress conformance.
//
// What it proves (things the Rust sim structurally cannot catch):
//   - The flowplane DaemonSet loads + attaches eBPF programs on a real kernel veth.
//   - AttachInterface gRPC creates the veth, moves the guest end into a netns,
//     allocates an underlay /128, and programs the INTERFACES eBPF map.
//   - AddNatSource + AddRoute(external) + AddFwRule(egress-allow) cause the datapath
//     to SNAT a guest TCP frame: the outer IPIP encap on eth1 carries a rewritten TCP
//     sport drawn from the NAT port block, proved by netprobe send-sniff.
//
// Gate: skips (never fails) when containerlab/kind/docker/kubectl/grpcurl/nsenter/sudo
// are not installed — mirrors TestCrossNodeOverlayPing and TestDhcpLeaseSmoke exactly.
//
// Mechanism: same proven path as TestDhcpLeaseSmoke — deploy the flowplane DaemonSet
// (kind load + kubectl apply + rollout status), create a netns via docker exec, drive
// gRPC via HOST grpcurl nsenter'd into the node's netns (no in-node grpcurl needed),
// and verify SNAT with the Go netprobe binary (CGO_ENABLED=0, copied to /netprobe on
// the kind node — NOT /tmp, which is tmpfs and loses docker cp).
//
// SNAT assertion: netprobe send-sniff runs sniff-only on eth1 (the fabric uplink) in
// the background, capturing IPIP-encapped TCP frames to 8.8.8.8; a foreground
// "netprobe send" injects the raw TCP frame from the guest netns.  send-sniff exits 0
// and prints "OK: captured N frame(s); inner-tcp-sport=<v>" when it observes a frame
// with inner-tcp-sport in [portMin, portMax] — the SNAT rewrite proof.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// buildNetprobeBinary compiles the netprobe CLI to a STATIC (CGO_ENABLED=0) binary so
// it runs inside the Ubuntu-based kind node after `docker cp`. Returns the host path
// (in t.TempDir()).
func buildNetprobeBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "netprobe")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/netprobe")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if o, err := runWithTimeout(cmd, 2*time.Minute); err != nil {
		t.Fatalf("build netprobe: %v\n%s", err, o)
	}
	return out
}

// TestNatEgressSmoke deploys the flowplane DaemonSet on the k01 cluster, attaches a
// guest interface on the worker node, programs NAT source + external route + egress
// firewall rule, then proves SNAT is active by sniffing the IPIP-encapped TCP frame on
// eth1 with the Go netprobe binary.
//
// The SNAT assertion (send-sniff): netprobe send-sniff runs sniff-only in the background
// on eth1, filtering for outer-IPv6 / inner-TCP / inner-dst=8.8.8.8 frames. A foreground
// "netprobe send" injects a raw TCP frame from the guest netns (guestIP->extDst, sport=
// 12345, dport=80). The SNAT datapath rewrites the src port into [portMin,portMax]; the
// send-sniff asserts the captured inner-tcp-sport falls in that range and prints:
//
//	"OK: captured 1 frame(s); inner-tcp-sport=<v>"
//
// This is FATAL — the test fails if SNAT is not observed on eth1.
func TestNatEgressSmoke(t *testing.T) {
	for _, bin := range []string{"containerlab", "kind", "docker", "kubectl", "grpcurl", "nsenter", "sudo"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("nat-egress smoke requires clab fabric host: %s not installed", bin)
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

	var (
		node     = WorkerNode             // k01-worker
		cluster  = KindCentral            // k01
		grpcAddr = DataplaneAddrFromEnv() // 127.0.0.1:1337
		image    = FlowplaneImageFromEnv()
	)
	const (
		// Overlay/VPC parameters.
		vni     = 200
		guestID = "natsmoke"
		guestIP = "10.1.0.5"
		natIP   = "203.0.113.5"
		portMin = 1024
		portMax = 2047

		// External route nexthop: the WAN-edge underlay (edge1 in the ipv6-fabric
		// topology). AddRoute(external=true) marks the route as NAT-eligible so the
		// datapath fires SNAT on guest egress toward extDst.
		edgeUnderlay = "fd00:db8:0:9::e"
		// External destination for the injected TCP frames.
		extDst = "8.8.8.8"

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
			t.Logf("clab-down failed (lab may need manual cleanup): %v\n%s", err, out)
		}
	})

	run := func(name string, args ...string) (string, error) {
		return runWithTimeout(exec.Command(name, args...), cmdTimeout)
	}
	dockerExec := func(args ...string) (string, error) {
		return run("docker", append([]string{"exec", node}, args...)...)
	}

	// 2. k01 kubeconfig (per-run temp file).
	kubeconfig := filepath.Join(t.TempDir(), "k01.kubeconfig")
	if out, err := run("sh", "-c", fmt.Sprintf("kind get kubeconfig --name %s > %s", cluster, kubeconfig)); err != nil {
		t.Fatalf("kind get kubeconfig: %v\n%s", err, out)
	}
	kubectl := func(args ...string) (string, error) {
		return run("kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...)
	}

	// 3. Load the flowplane image into k01 and deploy the DaemonSet.
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
	t.Logf("flowplane DaemonSet ready on cluster %s", cluster)

	// podLog fetches the flowplane pod log from the worker node for failure diagnostics.
	podLog := func() string {
		out, _ := kubectl("-n", "ectobase-system", "logs",
			"-l", "app=flowplane", "--field-selector", "spec.nodeName="+node,
			"--tail=80")
		return out
	}

	// 4. Node-local gRPC: HOST grpcurl entered into the node's netns via nsenter.
	nodePID := func(n string) (string, error) {
		out, err := run("docker", "inspect", "-f", "{{.State.Pid}}", n)
		return strings.TrimSpace(out), err
	}
	grpcIn := func(n, method, body string) (string, error) {
		pid, err := nodePID(n)
		if err != nil {
			return "", fmt.Errorf("node pid for %s: %w", n, err)
		}
		return run("sudo", nsenterBin, "-t", pid, "-n", grpcurlBin,
			"-import-path", protoDir, "-proto", "dataplane.proto",
			"-plaintext", "-d", body, grpcAddr, method)
	}

	// 5. Create the guest netns on the worker node.
	if out, err := dockerExec("ip", "netns", "add", guestID); err != nil {
		t.Logf("netns add %s on %s (may exist): %v\n%s", guestID, node, err, out)
	}

	// 6. AttachInterface — creates the veth peer inside the guest netns, programs
	//    PORT_META, INTERFACES, UNDERLAY, and attaches tc_guest_tx.
	attachBody := fmt.Sprintf(
		`{"interface_id":%q,"netns_path":"/var/run/netns/%s","vni":%d,"requested_ips":[%q]}`,
		guestID, guestID, vni, guestIP,
	)
	attachOut, attachErr := grpcIn(node, "dataplane.v1.DataplaneNode/AttachInterface", attachBody)
	if attachErr != nil {
		t.Fatalf("AttachInterface failed: %v\nresponse: %s\nflowplane pod log:\n%s",
			attachErr, attachOut, podLog())
	}
	if !strings.Contains(attachOut, "underlayRoute") {
		t.Fatalf("AttachInterface response missing underlayRoute\nresponse: %s", attachOut)
	}
	t.Logf("AttachInterface ok (guestID=%s guestIP=%s): %s", guestID, guestIP, strings.TrimSpace(attachOut))

	// Extract the MAC flowplane allocated so netprobe send can use it as --eth-src.
	guestMAC := "02:00:00:00:00:05" // fallback if regex extraction fails
	macRe := regexp.MustCompile(`"mac":\s*"([0-9a-f:]{17})"`)
	if m := macRe.FindStringSubmatch(attachOut); len(m) == 2 {
		guestMAC = m[1]
	}
	t.Logf("guest MAC: %s", guestMAC)

	// 7. AddNatSource — programs egress SNAT for (vni=200, src=10.1.0.5) onto the
	//    public NAT IP 203.0.113.5 with port block [portMin, portMax].
	natBody := fmt.Sprintf(
		`{"vni":%d,"source_ip":%q,"nat_ip":%q,"port_min":%d,"port_max":%d}`,
		vni, guestIP, natIP, portMin, portMax,
	)
	natOut, natErr := grpcIn(node, "dataplane.v1.DataplaneNode/AddNatSource", natBody)
	if natErr != nil {
		t.Fatalf("AddNatSource failed: %v\n%s\npod log:\n%s", natErr, natOut, podLog())
	}
	t.Logf("AddNatSource ok (vni=%d src=%s nat=%s ports=%d-%d)", vni, guestIP, natIP, portMin, portMax)

	// 8. AddRoute (external=true, specific prefix) — marks the route as NAT-eligible so
	//    SNAT fires on guest egress toward extDst. Using a /32 for 8.8.8.8 so the lookup
	//    matches the injected frame's dst exactly.
	routeBody := fmt.Sprintf(
		`{"vni":%d,"prefix":%q,"nexthop_underlay":%q,"external":true}`,
		vni, extDst+"/32", edgeUnderlay,
	)
	routeOut, routeErr := grpcIn(node, "dataplane.v1.DataplaneNode/AddRoute", routeBody)
	if routeErr != nil {
		t.Fatalf("AddRoute(external) failed: %v\n%s\npod log:\n%s", routeErr, routeOut, podLog())
	}
	t.Logf("AddRoute external ok (prefix=%s/32 nexthop=%s)", extDst, edgeUnderlay)

	// 9. AddFwRule (egress allow proto=0 = all) — datapath is deny-by-default; an
	//    egress rule must be installed or all guest-egress is dropped.
	fwBody := fmt.Sprintf(
		`{"interface_id":%q,"rule_id":"eg","proto":0,"allow":true,"egress":true}`,
		guestID,
	)
	fwOut, fwErr := grpcIn(node, "dataplane.v1.DataplaneNode/AddFwRule", fwBody)
	if fwErr != nil {
		t.Fatalf("AddFwRule(egress-allow) failed: %v\n%s\npod log:\n%s", fwErr, fwOut, podLog())
	}
	t.Logf("AddFwRule egress-allow ok")

	// 10. Build netprobe (CGO_ENABLED=0 static), copy to /netprobe on the kind node
	//     (NOT /tmp — tmpfs, lost after docker cp).
	netprobeBin := buildNetprobeBinary(t)
	if out, err := runWithTimeout(exec.Command("docker", "cp", netprobeBin, node+":/netprobe"), cmdTimeout); err != nil {
		t.Fatalf("docker cp netprobe into %s:/netprobe: %v\n%s", node, err, out)
	}
	t.Logf("netprobe binary copied to %s:/netprobe", node)

	// Bring the in-netns guest iface up so AF_PACKET can bind to it.
	if out, err := dockerExec("ip", "netns", "exec", guestID, "ip", "link", "set", guestID, "up"); err != nil {
		t.Fatalf("bring up %s in netns %s: %v\n%s", guestID, guestID, err, out)
	}
	t.Logf("guest iface %s is up inside netns %s", guestID, guestID)

	// 11. Background sniff on eth1 (the fabric uplink): captures IPIP-encapped TCP
	//     frames destined for 8.8.8.8 and asserts the inner-tcp-sport is in [portMin,portMax].
	//     Runs sniff-only (--count 0) so it just arms the RX filter and waits; send-sniff
	//     exits 0 and prints "OK: captured N frame(s); inner-tcp-sport=<v>" on success.
	sniffCmd := exec.Command("docker", "exec", node, "sh", "-c",
		fmt.Sprintf(
			"/netprobe send-sniff --count 0 --rx-iface eth1 --rx-outer-ipv6 --rx-inner-ip-dst %s --rx-l4 tcp --want-outer-ipv6-nh 4 --extract inner-tcp-sport --sport-range %d-%d --timeout 10 > /snifflog 2>&1",
			extDst, portMin, portMax,
		),
	)
	var sniffOut bytes.Buffer
	sniffCmd.Stdout = &sniffOut
	sniffCmd.Stderr = &sniffOut
	if err := sniffCmd.Start(); err != nil {
		t.Fatalf("start background sniff: %v", err)
	}

	// Give the RX filter time to arm before sending.
	time.Sleep(1500 * time.Millisecond)

	// 12. Foreground SEND from the guest netns: inject a raw TCP frame guest->extDst.
	//     The datapath SNAT rewrites the src port into [portMin,portMax] and encaps in IPIP.
	sendArgs := []string{
		"exec", node, "ip", "netns", "exec", guestID,
		"/netprobe", "send",
		"--iface", guestID,
		"--eth-src", guestMAC,
		"--eth-dst", "02:00:00:00:00:01", // GW_MAC
		"--ip-src", guestIP,
		"--ip-dst", extDst,
		"--l4", "tcp",
		"--sport", "12345",
		"--dport", "80",
		"--count", "6",
		"--interval-ms", "200",
	}
	sendOut, sendErr := run("docker", sendArgs...)
	if sendErr != nil {
		t.Logf("netprobe send (non-fatal if SNAT fires): %v\n%s", sendErr, sendOut)
	} else {
		t.Logf("netprobe send ok: %s", strings.TrimSpace(sendOut))
	}

	// 13. Wait for the background sniff to finish (it exits when it matches or times out).
	_ = sniffCmd.Wait()

	// Read the sniff log written inside the node.
	sniffLog, _ := dockerExec("cat", "/snifflog")
	t.Logf("send-sniff output:\n%s", strings.TrimSpace(sniffLog))

	// FATAL assertion: SNAT must be observed on eth1. send-sniff prints "OK: captured N
	// frame(s); inner-tcp-sport=<v>" and exits 0 only when the filter + sport-range pass.
	if !strings.Contains(sniffLog, "OK:") {
		t.Fatalf("NAT egress SNAT NOT observed on eth1 (no 'OK:' in send-sniff output)\n"+
			"send-sniff log:\n%s\n\nflowplane pod log:\n%s",
			sniffLog, podLog())
	}
	t.Logf("NAT egress SNAT smoke PASS: guest %s -> %s SNAT'd into %s:[%d-%d], IPIP-encapped to the edge",
		guestIP, extDst, natIP, portMin, portMax)

	// Cleanup: DetachInterface best-effort.
	if out, err := grpcIn(node, "dataplane.v1.DataplaneNode/DetachInterface",
		fmt.Sprintf(`{"interface_id":%q}`, guestID)); err != nil {
		t.Logf("DetachInterface cleanup (non-fatal): %v\n%s", err, out)
	}
}
