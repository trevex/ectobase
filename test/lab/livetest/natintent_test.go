//go:build live

package livetest

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trevex/ectobase/test/lab/internal/clab"
	"github.com/trevex/ectobase/test/lab/internal/config"
	"github.com/trevex/ectobase/test/lab/internal/exec"
)

const (
	// natIntentVNI is this test's own VPC, distinct from every other test's so it can run
	// alongside them (100/110/120/201/203/205 are taken).
	natIntentVNI = 206
	// natIntentPublicIP is inside fabric.PublicV4 (192.0.2.0/24), which both edges advertise as
	// anycast and the WAN routes back — a NAT IP outside it could never receive a reply. Clear of
	// 192.0.2.1 (lb_test) and 192.0.2.7 (lbintent). It is a PIN inside natIntentPool, not a
	// literal: the gateway holds it as an IPAllocation.
	natIntentPublicIP = "192.0.2.40"
	// natIntentPool is the public IPPool the gateway draws from, and natIntentAllocation is the
	// deterministic name its claim on natIntentPublicIP lands at (mesh/controllers/ipalloc.go:
	// <pool>-<address with dots as dashes>).
	natIntentPool       = "nati-pool"
	natIntentAllocation = natIntentPool + "-192-0-2-40"
	natIntentNIC        = "nati-nic"
	// 10.0.7.0/24 is this test's own overlay subnet. Overlay addresses are VNI-scoped so an overlap
	// would not actually break the datapath, but every other live test picks a distinct /24 and
	// 10.0.6.0/24 is vm_overlay_test's (down to the same .10 host), which would make any
	// cross-test confusion very hard to read.
	natIntentGuestIP = "10.0.7.10"
	natIntentMAC     = "52:54:00:00:07:10"
	// natIntentPorts is the block size. Small and not the 1024 default so the expected block is
	// exact and short: the first source on an IP gets [1024, 1024+8), which the central allocator
	// writes as portMin 1024 / portMax 1031 INCLUSIVE and the bus/dataplane carry as [1024, 1032).
	natIntentPorts   = 8
	natIntentPortMin = 1024
	// natIntentPortMaxIncl is what the NATGateway status and the CompiledNIC twin report
	// (mesh/allocator/portblock.go: PortMax = portMin + size - 1).
	natIntentPortMaxIncl = 1031
	// natIntentPortMaxExcl is what the route bus and the dataplane carry — the agent converts at
	// mesh/agent/reconcile.go (portMaxExcl = src.PortMax + 1). If the NAT_OWNERS assertion below
	// ever reads 1031 here, that conversion regressed.
	natIntentPortMaxExcl = 1032
	// The WAN-side server the guest dials. 172.29.0.1 is fabric.WanGwV4, the WAN bridge gateway
	// the edges reach directly on eth3.
	natIntentWanAddr   = "172.29.0.1"
	natIntentWanPort   = 8080
	natIntentBody      = "hello-nat-intent"
	natIntentWanServer = "natintent-wan-httpd"
)

// TestNatFromIntent drives egress NAT from INTENT ALONE: a NATGateway and a Container are the
// entire input, and a Pod on the overlay reaches a WAN-side HTTP server and back — with nobody in
// this test calling AddNatSource, AddNeighborNat, AddRoute or AttachInterface.
//
// This is the NAT twin of TestLbFromIntentReachesTheWan, and it covers the half of the NAT stack
// TestNatEgressSmoke / TestNatEgressReturn6 cannot: those hand the dataplane exactly the arguments
// the agent would have produced, so everything above the gRPC boundary is untested. The chain here
// starts at the CRD:
//
//	NATGateway (vpcRef, publicIPs, portsPerSource)
//	  -> NATGatewayReconciler   sources = NIC.status.allocatedIPs, blocks from mesh/allocator
//	                            writes NATGateway.status.allocations
//	  -> CompiledNICReconciler  stamps CompiledNIC.spec.nat[]
//	  -> broker                 syncs the twin into the pool cluster
//	  -> node agent             AddNatSource locally, stages a NatBlock announce
//	  -> reflector              AnnounceNat on the global feed
//	  -> EDGE agent applyNat    AddNeighborNat -> the NAT_OWNERS trie (edges only)
//
// It asserts in stages so a failure localizes: central allocation -> the compiled twin in the pool
// -> both edges' NAT_OWNERS tries -> real bidirectional traffic.
func TestNatFromIntent(t *testing.T) {
	cfg := loadConfig(t)
	requireFabricUp(t, cfg)
	ctx := context.Background()

	nodes := computeNodes(cfg)
	if len(nodes) == 0 {
		t.Skip("need at least one compute node")
	}
	node := nodes[0]
	// The owning node's VTEP: every interface on a node shares the node's one underlay address,
	// which is what the NatBlock announce carries as owner_underlay and the edge stores as the
	// NatOwner's underlay. Same value lbintent_test.go uses as backendVTEP.
	ownerVTEP := node.IdentityAddr
	wan := clab.ContainerName(cfg.Name, "wan")

	// 1. Intent on the dispatch. No FirewallPolicy and no Route: the compiler materializes an
	//    allow-all for every direction no policy governs, and desiredEgressVNIs
	//    (mesh/agent/importreconcile.go) imports the public-VNI default into any VNI whose
	//    CompiledNIC carries NAT. Adding either by hand here would defeat the test.
	applyDispatch(t, ctx, cfg, natIntentFixture(nodeK8sName(node), node.Cluster))
	patchNatIntentVPCReady(t, ctx, cfg)
	t.Cleanup(func() {
		for _, kind := range []string{
			"natgateway.net.ectobase.dev/nati-gw", "ippool.net.ectobase.dev/" + natIntentPool,
			"containers.compute.ectobase.dev/ctr-" + natIntentNIC,
			"networkinterface.net.ectobase.dev/" + natIntentNIC,
			"subnet.net.ectobase.dev/nati-subnet", "vpc.net.ectobase.dev/nati-vpc",
		} {
			_, _ = kubectl(ctx, cfg, "dispatch", "delete", kind, "--ignore-not-found", "--wait=false")
		}
	})

	// 2. The guest ENDPOINT: a real Pod, materialized from the Container above and attached to the
	//    overlay by flowplane-cni. That attach is the ONLY dataplane gRPC in the whole flow, and
	//    nothing in this test issues it. It is also what makes the NIC's NAT allocation live: the
	//    agent decides a CompiledNIC is local by matching its (VNI, overlay IP) against the
	//    dataplane's attached interfaces.
	var pod string
	eventually(t, 3*time.Minute, 5*time.Second, func() error {
		p, err := podForContainer(ctx, cfg, node.Cluster, "default-ctr-"+natIntentNIC)
		if err != nil {
			return err
		}
		phase, err := kubectl(ctx, cfg, node.Cluster, "get", "pod", p, "-o", "jsonpath={.status.phase}")
		if err != nil {
			return err
		}
		if strings.TrimSpace(phase) != "Running" {
			desc, _ := kubectl(ctx, cfg, node.Cluster, "describe", "pod", p)
			return fmt.Errorf("guest pod %s phase=%q:\n%s", p, strings.TrimSpace(phase), tail(desc, 25))
		}
		pod = p
		return nil
	})

	// 3a. The public address is genuinely ALLOCATED from the pool, not a literal the gateway
	//     copied out of its own spec. Without this the rest of the test would pass just as well
	//     if spec.publicIPs were still the pre-pool literal list — which is the whole increment.
	//     The claim is the IPAllocation object at its deterministic (pool, address) name; its
	//     controller ownerReference is what Kubernetes garbage-collects it by when the gateway
	//     goes, and the pool label is what every allocator's used-set query selects on.
	eventually(t, 2*time.Minute, 3*time.Second, func() error {
		return natIntentAddressIsAllocated(ctx, cfg)
	})
	t.Logf("public address %s is held by IPAllocation %s, owned by NATGateway/nati-gw out of pool %s",
		natIntentPublicIP, natIntentAllocation, natIntentPool)

	// 3. Central allocation landed. Everything downstream is gated on this: no allocation means no
	//    CompiledNIC.spec.nat, which means no local SNAT and no NatBlock on the bus.
	//
	//    portMax is 1031 here — the ALLOCATOR's bound is inclusive.
	wantAlloc := fmt.Sprintf("%s|%s|%d|%d;",
		natIntentGuestIP, natIntentPublicIP, natIntentPortMin, natIntentPortMaxIncl)
	eventually(t, 2*time.Minute, 3*time.Second, func() error {
		out, err := kubectl(ctx, cfg, "dispatch", "get", "natgateways.net.ectobase.dev", "nati-gw",
			"-o", "jsonpath={range .status.allocations[*]}{.source}|{.publicIP}|{.portMin}|{.portMax};{end}")
		if err != nil {
			return fmt.Errorf("get NATGateway status: %w", err)
		}
		state, _ := kubectl(ctx, cfg, "dispatch", "get", "natgateways.net.ectobase.dev", "nati-gw",
			"-o", "jsonpath={.status.state}")
		if strings.TrimSpace(state) == "Exhausted" {
			return fmt.Errorf("NATGateway state=Exhausted — the public-IP pool ran out of blocks; allocations: %q", out)
		}
		if !strings.Contains(out, wantAlloc) {
			return fmt.Errorf("NATGateway allocations = %q (state %q), want an entry %q",
				strings.TrimSpace(out), strings.TrimSpace(state), wantAlloc)
		}
		return nil
	})

	// 4. The compiled twin reached the POOL — the node agent's only source for the SNAT block.
	wantCompiled := fmt.Sprintf("%s %s %d %d",
		natIntentGuestIP, natIntentPublicIP, natIntentPortMin, natIntentPortMaxIncl)
	eventually(t, 2*time.Minute, 5*time.Second, func() error {
		out, err := kubectl(ctx, cfg, node.Cluster, "get", "compilednics.compiled.ectobase.dev",
			"default-"+natIntentNIC, "-o",
			"jsonpath={.spec.nat[0].sourceIP} {.spec.nat[0].natIP} {.spec.nat[0].portMin} {.spec.nat[0].portMax}")
		if err != nil {
			return fmt.Errorf("get CompiledNIC on %s: %w", node.Cluster, err)
		}
		if got := strings.TrimSpace(out); got != wantCompiled {
			return fmt.Errorf("CompiledNIC spec.nat[0] = %q, want %q", got, wantCompiled)
		}
		return nil
	})

	// 5. BOTH edges learned the block over the route bus, with nobody in this test calling
	//    AddNeighborNat. Asserted before any traffic and on both edges, because the public prefix
	//    is anycast: the WAN ECMPs the reply to either, so a block programmed on only one of them
	//    is a coin-flip failure the traffic leg would catch only sometimes.
	//
	//    This is also where the inclusive->exclusive conversion is pinned: port_max must read 1032.
	for _, edge := range []string{"edge1", "edge2"} {
		edge := edge
		eventually(t, 3*time.Minute, 5*time.Second, func() error {
			return edgeHasNatOwner(ctx, cfg, edge, natIntentPublicIP,
				natIntentPortMin, natIntentPortMaxExcl, ownerVTEP, natIntentVNI)
		})
		t.Logf("edge %s carries NAT_OWNERS %s:[%d,%d) -> %s vni=%d",
			edge, natIntentPublicIP, natIntentPortMin, natIntentPortMaxExcl, ownerVTEP, natIntentVNI)
	}

	// 6. THE POINT. The guest dials a WAN-side server and gets the body back. A genuine
	//    bidirectional flow: the reply returns to the NAT IP, lands on whichever edge the WAN's
	//    ECMP picks, and is relayed to the owning node from the block that edge learned over the
	//    bus — then reverse-DNAT'd back to the guest.
	natIntentServeWan(t, ctx, wan)
	url := fmt.Sprintf("http://%s:%d/", natIntentWanAddr, natIntentWanPort)
	// Hand-rolled rather than eventually(): natIntentDiagnostics shells out six times, so
	// collecting it on every failed attempt would dominate the retry budget. Gather it once, when
	// the deadline is actually up.
	deadline := time.Now().Add(4 * time.Minute)
	for {
		out, err := kubectl(ctx, cfg, node.Cluster, "exec", pod, "--",
			"wget", "-q", "-O", "-", "-T", "5", url)
		if err == nil && strings.Contains(out, natIntentBody) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("guest wget %s through NAT did not return %q: %v\n%s\n%s",
				url, natIntentBody, err, out, natIntentDiagnostics(ctx, cfg, node))
		}
		time.Sleep(5 * time.Second)
	}
	t.Logf("NAT FROM INTENT PASS: pod %s (%s, vni %d) reached %s and back, SNAT'd to %s:[%d,%d) on node %s",
		pod, natIntentGuestIP, natIntentVNI, url, natIntentPublicIP,
		natIntentPortMin, natIntentPortMaxExcl, ownerVTEP)
}

// natIntentFixture renders the whole intent: VPC, Subnet, IPPool, NATGateway and the guest NIC +
// Container.
//
// The gateway's public address comes from the IPPool, not from a literal list: spec.publicIPs is
// a PIN inside spec.poolRef (the NAT analogue of LoadBalancer.spec.ip), so the address stays
// 192.0.2.40 and every downstream assertion is exact — while the address itself is genuinely
// allocated, as the IPAllocation assertion in stage 3 proves. The port block is centrally
// allocated on top of it (mesh/allocator/portblock.go hands each source IP a disjoint block), and
// a gateway that runs out of blocks claims one more address from this same pool.
func natIntentFixture(node, cluster string) string {
	return fmt.Sprintf(`apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: {name: nati-vpc}
spec: {vni: %[1]d, defaultPolicy: Allow}
---
apiVersion: net.ectobase.dev/v1alpha1
kind: Subnet
metadata: {name: nati-subnet}
spec: {vpcRef: {name: nati-vpc}, v4Prefix: 10.0.7.0/24}
---
# The edge-owned public v4 prefix (fabric.PublicV4): both edges advertise it as our ASN and the WAN
# routes it back via either, so any NAT address inside it is anycast across the edge fleet.
apiVersion: net.ectobase.dev/v1alpha1
kind: IPPool
metadata: {name: %[9]s}
spec: {type: public, v4Prefix: 192.0.2.0/24}
---
# Egress NAT for the whole VPC: every NIC in nati-vpc gets a deterministic (public IP, port block).
apiVersion: net.ectobase.dev/v1alpha1
kind: NATGateway
metadata: {name: nati-gw}
spec:
  vpcRef: {name: nati-vpc}
  poolRef: {name: %[9]s}
  publicIPs: [%[2]q]
  portsPerSource: %[3]d
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata: {name: %[4]s}
spec: {vpcRef: {name: nati-vpc}, ips: [%[5]q], mac: %[6]q}
---
# The Container owns the NIC and is the PLACEMENT AUTHORITY: it stamps CompiledNIC.clusterName (the
# pool the twin is emitted into) and nodeName. It just idles — the traffic leg is an OUTBOUND dial
# driven by kubectl exec, so unlike the LB fixture it serves nothing.
apiVersion: compute.ectobase.dev/v1alpha1
kind: Container
metadata: {name: ctr-%[4]s, namespace: default}
spec:
  clusterName: %[8]q
  nodeName: %[7]q
  interfaceRefs: [{name: %[4]s}]
  image: busybox:1.36
  command: ["sh", "-c", "exec sleep 3600"]
`, natIntentVNI, natIntentPublicIP, natIntentPorts, natIntentNIC,
		natIntentGuestIP, natIntentMAC, node, cluster, natIntentPool)
}

// natIntentAddressIsAllocated checks the gateway's claim on natIntentPublicIP: an IPAllocation at
// the deterministic name, naming the pool and the address, labelled with the pool, and carrying a
// CONTROLLER ownerReference to the NATGateway — the last being what reclaims it on deletion.
//
// One jsonpath, five fields, because a partial claim is the interesting failure: an allocation
// with no ownerRef leaks the address forever, and one with no pool label is invisible to the very
// used-set query the next allocator runs.
func natIntentAddressIsAllocated(ctx context.Context, cfg *config.Config) error {
	const jp = `{.spec.poolRef.name}|{.spec.address}|{.metadata.labels.net\.ectobase\.dev/pool}` +
		`|{.metadata.ownerReferences[0].kind}|{.metadata.ownerReferences[0].name}` +
		`|{.metadata.ownerReferences[0].controller}`
	out, err := kubectl(ctx, cfg, "dispatch", "get", "ipallocations.net.ectobase.dev",
		natIntentAllocation, "-o", "jsonpath="+jp)
	if err != nil {
		state, _ := kubectl(ctx, cfg, "dispatch", "get", "natgateways.net.ectobase.dev", "nati-gw",
			"-o", "jsonpath={.status.state}")
		pool, _ := kubectl(ctx, cfg, "dispatch", "get", "ippools.net.ectobase.dev", natIntentPool,
			"-o", "jsonpath={.status.state}")
		return fmt.Errorf("no IPAllocation %s (NATGateway state %q, IPPool state %q): %w",
			natIntentAllocation, strings.TrimSpace(state), strings.TrimSpace(pool), err)
	}
	want := fmt.Sprintf("%s|%s|%s|NATGateway|nati-gw|true", natIntentPool, natIntentPublicIP, natIntentPool)
	if got := strings.TrimSpace(out); got != want {
		return fmt.Errorf("IPAllocation %s = %q, want %q "+
			"(poolRef|address|pool label|owner kind|owner name|controller)",
			natIntentAllocation, got, want)
	}
	return nil
}

func patchNatIntentVPCReady(t *testing.T, ctx context.Context, cfg *config.Config) {
	t.Helper()
	_, err := kubectl(ctx, cfg, "dispatch", "patch", "vpcs.net.ectobase.dev", "nati-vpc",
		"--subresource=status", "--type=merge",
		"-p", fmt.Sprintf(`{"status":{"vni":%d,"state":"Ready"}}`, natIntentVNI))
	require.NoError(t, err, "patch nati-vpc status Ready")
}

// natIntentServeWan starts a throwaway HTTP server inside the WAN container's network namespace —
// the same trick curlFromWanFamily uses to run curl there — and waits until it actually serves. The
// guest dials this, so the reply comes back to the guest's NAT IP and has to traverse the whole
// return path: WAN -> (BGP, anycast) an edge -> NAT_OWNERS lookup -> Geneve to the owning node ->
// reverse-DNAT.
func natIntentServeWan(t *testing.T, ctx context.Context, wan string) {
	t.Helper()
	_, _ = exec.SudoOutput(ctx, "docker", "rm", "-f", natIntentWanServer)
	out, err := exec.SudoOutput(ctx, "docker", "run", "-d", "--rm", "--name", natIntentWanServer,
		"--network", "container:"+wan, "busybox:latest", "sh", "-c",
		fmt.Sprintf("mkdir -p /www && echo %s > /www/index.html && exec httpd -f -p %d -h /www",
			natIntentBody, natIntentWanPort))
	require.NoError(t, err, "start the WAN-side server: %s", string(out))
	t.Cleanup(func() {
		_, _ = exec.SudoOutput(context.Background(), "docker", "rm", "-f", natIntentWanServer)
	})
	// It must be serving before the guest dials, or the first attempts fail for a reason that has
	// nothing to do with NAT.
	eventually(t, 60*time.Second, 2*time.Second, func() error {
		o, _ := exec.SudoOutput(ctx, "docker", "run", "--rm", "--network", "container:"+wan,
			"curlimages/curl:latest", "-4", "-s", "--max-time", "5",
			fmt.Sprintf("http://%s:%d/", natIntentWanAddr, natIntentWanPort))
		if !strings.Contains(string(o), natIntentBody) {
			logs, _ := exec.SudoOutput(ctx, "sh", "-c",
				fmt.Sprintf("docker logs --tail 20 %s 2>&1", natIntentWanServer))
			return fmt.Errorf("WAN-side server not serving yet: %q\n%s", string(o), string(logs))
		}
		return nil
	})
}

// natOwnerKeyLen / natOwnerValLen are the NAT_OWNERS trie's on-wire sizes, matching
// `bpftool map show`: key 10B, value 24B.
const (
	natOwnerKeyLen = 10
	natOwnerValLen = 24
)

// natOwnerRow is one decoded NAT_OWNERS entry.
//
// The key is aya's packed LpmTrie Key: prefix_len u32 LITTLE-endian, then flowplane_common's
// NatOwnerKey { nat_ip: [u8;4], port: [u8;2] } with the port BIG-endian (network order) so an LPM
// prefix masks the port's high bits — a block [port_min, port_max) is stored as the fewest aligned
// port prefixes covering it (flowplane-control/src/natowner.rs).
//
// The value is NatOwner { underlay: [u8;16], vni: u32, port_min: u16, port_max: u16 } — 24 bytes,
// no padding, the three scalars LITTLE-endian (host order) and port_max EXCLUSIVE.
type natOwnerRow struct {
	prefixLen uint32
	natIP     []byte // 4
	port      uint16
	underlay  []byte // 16
	vni       uint32
	portMin   uint16
	portMax   uint16 // exclusive
}

func (r natOwnerRow) String() string {
	return fmt.Sprintf("%s/port %d (prefix_len %d) -> underlay %s vni %d ports [%d,%d)",
		net.IP(r.natIP).String(), r.port, r.prefixLen,
		net.IP(r.underlay).String(), r.vni, r.portMin, r.portMax)
}

// edgeHasNatOwner checks that an edge's NAT_OWNERS trie carries the block, decoded from the map
// rather than from a log line: a half-programmed edge can only blackhole the reply, and only the
// map says which block, which owner and which bound it actually holds.
func edgeHasNatOwner(ctx context.Context, cfg *config.Config, edge, natIP string,
	portMin, portMaxExcl int, ownerVTEP string, vni int) error {
	pinDir := "/sys/fs/bpf/flowplane-" + edge
	dump, err := exec.SudoOutput(ctx, "sh", "-c",
		fmt.Sprintf("bpftool -j map dump pinned %s/NAT_OWNERS 2>&1", pinDir))
	if err != nil {
		return fmt.Errorf("dump %s NAT_OWNERS map: %w\n%s", edge, err, tail(string(dump), 5))
	}
	rows, err := parseNatOwners(dump)
	if err != nil {
		return fmt.Errorf("%s: %w", edge, err)
	}

	if natOwnerMatch(rows, natIP, portMin, portMaxExcl, ownerVTEP, vni) {
		return nil
	}

	// A bare "not found" makes a live failure very slow to diagnose, so say what IS there.
	var have strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&have, "\n  %s", r)
	}
	if len(rows) == 0 {
		have.WriteString("\n  (trie is empty)")
	}
	return fmt.Errorf("%s NAT_OWNERS has no entry for %s ports [%d,%d) owner %s vni %d; it holds:%s",
		edge, natIP, portMin, portMaxExcl, ownerVTEP, vni, have.String())
}

// natOwnerMatch reports whether any decoded row is exactly the block we expect: the right NAT IP,
// owned by the right node's VTEP, in the right VNI, over the right EXCLUSIVE port range. The port
// bound is the point — an entry that is right in every other way but carries an inclusive port_max
// means the conversion in mesh/agent/reconcile.go regressed and the block's top port is unowned.
func natOwnerMatch(rows []natOwnerRow, natIP string, portMin, portMaxExcl int, ownerVTEP string, vni int) bool {
	wantNatIP, wantUnderlay := ipBytes(natIP)[:4], ipBytes(ownerVTEP)
	for _, r := range rows {
		if !bytes.Equal(r.natIP, wantNatIP) || !bytes.Equal(r.underlay, wantUnderlay) {
			continue
		}
		if r.vni == uint32(vni) && r.portMin == uint16(portMin) && r.portMax == uint16(portMaxExcl) {
			return true
		}
	}
	return false
}

// parseNatOwners decodes a `bpftool -j map dump` of a NAT_OWNERS trie.
//
// bpftool emits a BTF-less map as [{"key":["0x2d",...],"value":["0xfd",...]}, ...] — the same byte
// arrays for an lpm_trie as for a hash — so normalizeHex flattens each field straight from its raw
// JSON.
func parseNatOwners(dump []byte) ([]natOwnerRow, error) {
	var entries []struct {
		Key   json.RawMessage `json:"key"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(dump, &entries); err != nil {
		return nil, fmt.Errorf("parse NAT_OWNERS dump: %w\n%s", err, tail(string(dump), 5))
	}
	rows := make([]natOwnerRow, 0, len(entries))
	for i, e := range entries {
		k, err := hex.DecodeString(normalizeHex(string(e.Key)))
		if err != nil {
			return nil, fmt.Errorf("entry %d key: %w", i, err)
		}
		v, err := hex.DecodeString(normalizeHex(string(e.Value)))
		if err != nil {
			return nil, fmt.Errorf("entry %d value: %w", i, err)
		}
		if len(k) != natOwnerKeyLen || len(v) != natOwnerValLen {
			return nil, fmt.Errorf("entry %d: key %dB value %dB, want %dB/%dB — the NAT_OWNERS ABI moved",
				i, len(k), len(v), natOwnerKeyLen, natOwnerValLen)
		}
		rows = append(rows, natOwnerRow{
			prefixLen: binary.LittleEndian.Uint32(k[0:4]),
			natIP:     k[4:8],
			port:      binary.BigEndian.Uint16(k[8:10]),
			underlay:  v[0:16],
			vni:       binary.LittleEndian.Uint32(v[16:20]),
			portMin:   binary.LittleEndian.Uint16(v[20:22]),
			portMax:   binary.LittleEndian.Uint16(v[22:24]),
		})
	}
	return rows, nil
}

// natIntentDiagnostics collects what actually distinguishes the failure modes when the guest's dial
// does not come back: whether the owning node programmed the local SNAT at all, whether the edges
// still hold the block, and what both agent tiers logged. Best-effort — it only ever appears inside
// a failure message.
func natIntentDiagnostics(ctx context.Context, cfg *config.Config, node config.DerivedNode) string {
	var b strings.Builder

	// The owning node: its dataplane and its agent. Selected by the chart's real label
	// (app.kubernetes.io/name), not the `app=` the older NAT tests use — that selector matches
	// nothing and silently yields an empty log.
	for _, app := range []string{"flowplane", "mesh-agent"} {
		out, err := kubectl(ctx, cfg, node.Cluster, "-n", "ectobase-system", "logs",
			"-l", "app.kubernetes.io/name="+app,
			"--field-selector", "spec.nodeName="+nodeK8sName(node), "--tail=60")
		fmt.Fprintf(&b, "\n--- %s/%s %s log ---\n%s\n", node.Cluster, nodeK8sName(node), app,
			firstNonEmpty(strings.TrimSpace(out), errText(err)))
	}

	for _, edge := range []string{"edge1", "edge2"} {
		dump, _ := exec.SudoOutput(ctx, "sh", "-c",
			fmt.Sprintf("bpftool -j map dump pinned /sys/fs/bpf/flowplane-%s/NAT_OWNERS 2>&1", edge))
		rows, err := parseNatOwners(dump)
		if err != nil {
			fmt.Fprintf(&b, "\n--- %s NAT_OWNERS ---\n%s\n", edge, tail(string(dump), 5))
		} else {
			fmt.Fprintf(&b, "\n--- %s NAT_OWNERS (%d entries) ---\n", edge, len(rows))
			for _, r := range rows {
				fmt.Fprintf(&b, "  %s\n", r)
			}
		}
		logs, lerr := containerLogs(ctx, clab.ContainerName(cfg.Name, "mesh-agent-"+edge))
		fmt.Fprintf(&b, "--- mesh-agent-%s (last 20 lines) ---\n%s\n", edge,
			firstNonEmpty(tail(logs, 20), errText(lerr)))
	}
	return b.String()
}

// firstNonEmpty returns s, or alt when s is empty — so a diagnostic section says why it is blank
// instead of just being blank.
func firstNonEmpty(s, alt string) string {
	if strings.TrimSpace(s) != "" {
		return s
	}
	return alt
}

func errText(err error) string {
	if err == nil {
		return "(no output)"
	}
	return err.Error()
}

// natOwnersGoldenDump is a real `bpftool -j map dump` of a 10B-key/24B-value lpm_trie populated by
// hand with two entries — captured from bpftool itself, so it pins the JSON shape (a BTF-less
// lpm_trie dumps as the same {"key":[bytes],"value":[bytes]} form as a hash map) as well as the
// byte layout.
//
// Entry 1: prefix_len 45 (32 address bits + 13 port bits, i.e. the single aligned prefix covering
// ports 1024..1031), nat_ip 192.0.2.40, port 1024 big-endian; owner fd00:cafe:1234::1, vni 206,
// ports [1024,1032). Entry 2 is a decoy with a different owner, VNI and block.
const natOwnersGoldenDump = `[{"key":["0x30","0x00","0x00","0x00","0xc0","0x00","0x02","0x07","0x08","0x00"],` +
	`"value":["0xfd","0x00","0xca","0xfe","0x56","0x78","0x00","0x00","0x00","0x00","0x00","0x00",` +
	`"0x00","0x00","0x00","0x02","0xc9","0x00","0x00","0x00","0x00","0x08","0x00","0x0c"]},` +
	`{"key":["0x2d","0x00","0x00","0x00","0xc0","0x00","0x02","0x28","0x04","0x00"],` +
	`"value":["0xfd","0x00","0xca","0xfe","0x12","0x34","0x00","0x00","0x00","0x00","0x00","0x00",` +
	`"0x00","0x00","0x00","0x01","0xce","0x00","0x00","0x00","0x00","0x04","0x08","0x04"]}]`

// TestNatOwnersDecode pins the NAT_OWNERS decoder against a captured bpftool dump. It needs no
// fabric: it exists so that when TestNatFromIntent's stage 5 fails, the failure is known to be the
// edge's state and not this file's byte arithmetic — and so an ABI change to NatOwnerKey/NatOwner
// (field order, endianness, padding) fails here with a clear message instead of as a mystery
// timeout on a live edge.
func TestNatOwnersDecode(t *testing.T) {
	rows, err := parseNatOwners([]byte(natOwnersGoldenDump))
	require.NoError(t, err)
	require.Len(t, rows, 2)

	// bpftool iterates the trie in its own order, so find the entry rather than indexing.
	var got *natOwnerRow
	for i := range rows {
		if rows[i].prefixLen == 45 {
			got = &rows[i]
		}
	}
	require.NotNil(t, got, "no prefix_len 45 row in %v", rows)
	require.Equal(t, "192.0.2.40", net.IP(got.natIP).String())
	require.Equal(t, uint16(1024), got.port, "the key's port is BIG-endian")
	require.Equal(t, "fd00:cafe:1234::1", net.IP(got.underlay).String())
	require.Equal(t, uint32(206), got.vni)
	require.Equal(t, uint16(1024), got.portMin)
	require.Equal(t, uint16(1032), got.portMax, "the value's port_max is EXCLUSIVE and little-endian")

	require.True(t, natOwnerMatch(rows, "192.0.2.40", 1024, 1032, "fd00:cafe:1234::1", 206))
	// The regression this assertion guards: an inclusive port_max on the bus must NOT match.
	require.False(t, natOwnerMatch(rows, "192.0.2.40", 1024, 1031, "fd00:cafe:1234::1", 206))
	// Wrong owner, wrong VNI: both must miss.
	require.False(t, natOwnerMatch(rows, "192.0.2.40", 1024, 1032, "fd00:cafe:5678::2", 206))
	require.False(t, natOwnerMatch(rows, "192.0.2.40", 1024, 1032, "fd00:cafe:1234::1", 205))
}
