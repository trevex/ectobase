# N/S LoadBalancer via a flowplane pseudo-edge on the kind fabric — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Revive the North/South LoadBalancer datapath on the Go `test/lab` kind fabric by running flowplane as a `wan_rx` **edge** sidecar (sharing the VyOS edge1 netns), and prove it end-to-end with a Go live test: a WAN client curls an **IPv6** VIP → edge `wan_rx` Maglev-selects a backend → encap to the backend node → `uplink_rx` decap → ingress firewall → backend HTTP server → **DSR** reply (src=VIP). This is the user-chosen shape for `TestLbDistributeSmoke`/LB coverage in the retire-bash-clab effort (the plan's original guest→VIP shape was impossible — guest egress does no LB lookup; LB lives only in the relay/edge ingress path).

**Architecture:** Add a `flowplane-edge1` clab sidecar node that shares `clab-<name>-edge1`'s network namespace and runs `flowplane serve --role edge --uplink eth1 --extra-uplink eth2 --wan-uplink eth3 --local-underlay fd00:ffff::e1 --gateway-mac <ToR MAC> --pin-dir /sys/fs/bpf/flowplane-edge --pin-links false` (SKB mode — kind veths are MTU 1500). The edge's local-deliver underlay reuses `fd00:ffff::e1`, which the VyOS edge1 already advertises into fabric BGP, so backends can reach the edge and the edge can reach backends. The VIP is IPv6 (kind's WAN edge ifaces are v6-only). The `wan` node is the WAN client.

**Tech Stack:** containerlab (`network-mode: container:` sidecar), the flowplane image (same as the DaemonSet), VyOS/FRR BGP, the `DataplaneNode` gRPC API (`AddLbVip`/`AddLbBackend`/`AddRoute`), Go `//go:build live` test in `test/lab/livetest`.

**Source:** the retire-bash-clab spec `docs/superpowers/specs/2026-08-08-retire-bash-clab-datapath-to-go-design.md` (LB task) + the user decision (2026-08-08) to "Revive N/S via a flowplane pseudo-edge". Reference: `test/scenario-lb-ingress.sh` (bash N/S LB), `hack/clab/edge-xdp-wrapper.sh` (bash edge flowplane wrapper).

---

## Confirmed facts (from recon)

- `flowplane serve` supports `--role edge` + `--wan-uplink` (main.rs:119-126, 462-470: `attach_edge(wan, underlay)` attaches `wan_rx` + registers the local-deliver edge underlay). `--extra-uplink` covers the 2nd fabric uplink (main.rs:129).
- LB Maglev is consulted in the edge WAN ingress (`wan_rx`/`vip_rx`: ingress.rs:389 v6 `lb_select_forward_v6`, :418 v4) and in `uplink_rx` (:147 overlay). Guest egress has NO LB lookup — so a guest→VIP test is impossible; N/S edge is the correct path.
- LB datapath LOGIC is already proven by `flowplane-sim/src/lb_scenario_test.rs` + the byte-parity anchor `flowplane/tests/anchor_lb.rs`. This live test adds: real gRPC map programming on a real edge + a real packet through `wan_rx` Maglev + DSR on a real kernel.
- kind edge1: eth1↔sw1, eth2↔sw2 (fabric, dual-homed), eth3↔wan (fd00:29::/64, edge1 eth3 = fd00:29::11), eth4↔nat64-1. dum0 = fd00:ffff::e1/128 (BGP-advertised). All links MTU 1500 → SKB XDP.
- The `wan` node bridges eth1-5 on the fd00:29::/64 segment and installs ECMP return routes for NodeAggr/RAAggr/LoopAggr → edges (fabric.go Wan.Routes).
- gRPC to the edge: `docker run --network container:clab-<name>-edge1 grpcurl … 127.0.0.1:1337` (the sidecar shares edge1's netns). Use `clab.ContainerName(cfg.Name, "edge1")` for the container name.

## Key risks

1. **SKB `wan_rx` attach in the VyOS netns** — the bash edge forced `FLOWPLANE_PIN_LINKS=false` because generic-XDP silently drops the 1st program when the 2nd attaches with pinned links (the edge attaches uplink_rx + wan_rx). MUST set `--pin-links false`.
2. **ToR gateway MAC resolution** — the wrapper resolves the fabric next-hop MAC from `ip -6 neigh show dev eth1` (needs the neighbor resolved; retry loop). If unresolved, the edge can't encap to backends.
3. **v6 VIP WAN routing + DSR return** — the `wan` client needs a route `VIP/128 → fd00:29::11`; the backend's DSR reply (src=VIP, dst=wan-client) routes back via the fabric `::/0` (edge default-originate) → edge → wan segment. Both directions need verification.
4. **Edge reachability of backend underlay** — the edge learns backend node /64s via BGP (nodes advertise them). Verify `ip -6 route get <backend_ul>` on the edge resolves via the fabric before blaming the datapath.
5. **A new topology node must not break existing green tests** — after the topology change, re-run the full suite (Phase 4 of the parent plan) to confirm no regression.

---

## Task LB.1 — flowplane-edge sidecar in the topology

**Files:**
- Modify: `test/lab/templates/fabric.clab.yml.tmpl` (add the `flowplane-edge1` node)
- Create: `test/lab/templates/flowplane/edge-wrapper.sh` (the edge bring-up wrapper)
- Modify: `test/lab/topology/fabric.go` (render the wrapper into the build tree; the bind path)
- Possibly modify: `test/lab/internal/config`/`fabric` if an image key or const is needed

- [ ] **Step 1: Add the edge wrapper script** `test/lab/templates/flowplane/edge-wrapper.sh`:
```sh
#!/bin/sh
# flowplane WAN-edge bring-up: shares the VyOS edge1 netns, attaches uplink_rx to the
# fabric uplinks (eth1/eth2) and wan_rx to the WAN uplink (eth3). SKB mode (kind veths
# are MTU 1500) => --pin-links false (generic-XDP drops the 1st prog when the 2nd
# attaches with pinned links; the edge attaches two).
set -e
UPLINK=eth1; EXTRA=eth2; WAN=eth3
UL="${EDGE_UNDERLAY:-fd00:ffff::e1}"
PIN_DIR="/sys/fs/bpf/flowplane-edge"

for i in $(seq 1 90); do
  if ip link show "$UPLINK" >/dev/null 2>&1 && ip link show "$WAN" >/dev/null 2>&1; then break; fi
  echo "edge-wrapper: waiting for $UPLINK + $WAN ($i)"; sleep 1
done

GW_MAC=""
for i in $(seq 1 90); do
  GW_MAC=$(ip -6 neigh show dev "$UPLINK" | awk '/router/{for(j=1;j<=NF;j++) if($j=="lladdr"){print $(j+1); exit}}')
  [ -z "$GW_MAC" ] && GW_MAC=$(ip -6 neigh show dev "$UPLINK" | awk '/lladdr/{print $5; exit}')
  [ -n "$GW_MAC" ] && break
  echo "edge-wrapper: waiting for fabric neighbour on $UPLINK ($i)"; sleep 1
done
[ -z "$GW_MAC" ] && { echo "edge-wrapper FATAL: no fabric neighbour MAC on $UPLINK" >&2; exit 1; }
echo "edge-wrapper: uplink=$UPLINK extra=$EXTRA wan=$WAN underlay=$UL gw_mac=$GW_MAC"

exec flowplane serve --addr 127.0.0.1:1337 --role edge \
  --uplink "$UPLINK" --extra-uplink "$EXTRA" --wan-uplink "$WAN" \
  --local-underlay "$UL" --gateway 169.254.0.1 --gateway-mac "$GW_MAC" \
  --pin-dir "$PIN_DIR" --pin-links false
```
(Verify the exact `flowplane serve` flag names against `flowplane/flowplane/src/main.rs` before finalizing — `--extra-uplink`, `--gateway`, `--gateway-mac`, `--pin-links` all exist; confirm `--gateway` is required/optional for edge.)

- [ ] **Step 2: Add the sidecar node** to `test/lab/templates/fabric.clab.yml.tmpl` (after the edge2 node, before nat64-1). It shares edge1's netns and mounts the wrapper + bpffs:
```yaml
    # flowplane WAN-edge sidecar: shares the edge1 VyOS netns and runs wan_rx so the
    # fabric has a real N/S LoadBalancer edge (VyOS alone cannot run the eBPF datapath).
    flowplane-edge1:
      kind: linux
      image: {{ index .Images "flowplane" }}
      network-mode: container:clab-{{ .Name }}-edge1
      cap-add: ["NET_ADMIN", "SYS_ADMIN", "BPF", "PERFMON", "NET_RAW"]
      binds:
        - flowplane/edge-wrapper.sh:/edge-wrapper.sh:ro
        - /sys/fs/bpf:/sys/fs/bpf
      startup-delay: 35
      entrypoint: "/bin/sh /edge-wrapper.sh"
```
Confirm the `flowplane` image key exists in `test/lab/lab.yaml`'s Images map (the DaemonSet uses it). If the key differs (e.g. `flowplane` vs a full ref), match it. If clab requires the sidecar to depend on edge1 being up, `startup-delay: 35` mirrors the bash edge (25-30s) + kind headroom.

- [ ] **Step 3: Render the wrapper into the build tree.** Read `test/lab/topology/fabric.go` `Render`; it already renders `vyos/*.boot`, `ceph/*`, etc. into `build/<name>/`. Add the `flowplane/edge-wrapper.sh` to the rendered set (it's a static file — copy from the embedded templates to `build/<name>/flowplane/edge-wrapper.sh`), mirroring how other static bind files are emitted. Ensure the clab `binds:` relative path (`flowplane/edge-wrapper.sh`) resolves from the clab file's dir (`build/<name>/`).

- [ ] **Step 4: Render + inspect the clab file** (no root needed):
```bash
cd /home/nik/Development/ironcore-net-xdp
make lab-render
sed -n '/flowplane-edge1/,/entrypoint/p' test/lab/build/ectobase/*.clab.yml
ls test/lab/build/ectobase/flowplane/edge-wrapper.sh
```
Expected: the node renders with the correct image + `network-mode: container:clab-ectobase-edge1`, and the wrapper file exists in the build tree.

- [ ] **Step 5: Rebuild the fabric and verify the edge attaches wan_rx** (the current fabric has no sidecar; a rebuild is required):
```bash
cd /home/nik/Development/ironcore-net-xdp
make lab-down || true
make lab-up
# edge flowplane logs:
sudo docker logs flowplane-edge1 2>&1 | tail -40   # or: clab-ectobase-flowplane-edge1 — check `docker ps` for the exact name
```
Expected: the wrapper resolves the ToR MAC, `flowplane serve --role edge` starts, and logs show `wan_rx` attached to eth3 + `uplink_rx` on eth1/eth2 with no verifier/attach error. Verify gRPC is up:
```bash
cd /home/nik/Development/ironcore-net-xdp/test/lab
sudo docker run --rm --network container:clab-ectobase-edge1 -v "$(git -C .. rev-parse --show-toplevel)/api/proto:/proto:ro" \
  fullstorydev/grpcurl:latest -plaintext -import-path /proto/dataplane/v1 -proto dataplane.proto \
  127.0.0.1:1337 dataplane.v1.DataplaneNode/ListInterfaces
```
Expected: a valid (possibly empty) ListInterfaces response — proves the edge flowplane gRPC is reachable in edge1's netns.

- [ ] **Step 6: Confirm no regression** — the existing green datapath tests still pass with the new node present:
```bash
cd /home/nik/Development/ironcore-net-xdp/test/lab
nix develop --command bash -c 'sudo -E env "PATH=$PATH" LAB_CONFIG="$(pwd)/lab.yaml" go test -tags live -run "TestDhcpLeaseSmoke|TestNatEgressSmoke|TestUnderlayInferenceOnFabric|TestCrossClusterOverlayPing" -count=1 -v ./livetest/... -timeout 30m'
```
Expected: all PASS (adding the edge sidecar must not disturb the fabric).

- [ ] **Step 7: Commit** (topology + wrapper + render):
```bash
cd /home/nik/Development/ironcore-net-xdp
git add test/lab/templates/fabric.clab.yml.tmpl test/lab/templates/flowplane/edge-wrapper.sh test/lab/topology/fabric.go
git commit -m "feat(lab): flowplane wan_rx edge sidecar on the kind fabric (N/S LB)

Runs flowplane --role edge sharing the VyOS edge1 netns (wan_rx on eth3, uplink_rx on
eth1/eth2, local-underlay fd00:ffff::e1, SKB/--pin-links false). Gives the kind fabric
a real N/S LoadBalancer edge; VyOS alone cannot run the eBPF datapath.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

## Task LB.2 — the N/S LB Go live test

**Files:**
- Create: `test/lab/livetest/lb_test.go` (`TestLbDistributeSmoke`, `//go:build live`)

Port the DIRECT-gRPC variant of `test/scenario-lb-ingress.sh` (not CRD/agent-driven) to Go, with an **IPv6 VIP**. Reuse `attachGuest`, `dataplaneGRPC`, `nodeExec`, `nodeNetnsProbe`, `kubectl`, `computeNodes`, `nodeContainer`, `loadConfig`, `requireFabricUp`. Add an `edgeContainer(cfg)` helper (`clab.ContainerName(cfg.Name, "edge1")`) and a `wanContainer(cfg)` helper (`clab.ContainerName(cfg.Name, "wan")`).

Sequence (each step live-validated during development):
1. Pick `backend := computeNodes(cfg)[0]`. `bul := attachGuest(backend, "lbbe", []string{overlayBackendIP}, mac)` → backend underlay /128.
2. In the backend netns: add the VIP on `lo` (DSR reply src=VIP): `docker exec <backend> ip netns exec lbbe ip -6 addr add <VIP>/128 dev lo`, and start an HTTP server bound to the VIP: `ip netns exec lbbe sh -c 'echo hello-lb > /idx; busybox httpd -f -p [<VIP>]:80 -h / ' &` (or python3 http.server). Confirm the node image has busybox/python3; if not, docker-cp a static httpd or reuse the netprobe/httpd approach.
3. Ingress firewall allow on the backend for the VIP (DSR keeps inner dst=VIP): `dataplaneGRPC(backend, "AddFwRule", {interface_id:"lbbe", rule_id:"lb-in", dst_cidr:"<VIP>/128", proto:6, dst_port_min:80, dst_port_max:80, allow:true, egress:false})`. (v6 CIDR → v6 rule.)
4. On the edge: `dataplaneGRPC(edgeContainer, "AddLbVip", {id:"lb", vni:0, vip:"<VIP>", lb_underlay:"fd00:ffff::e1", ports:[{port:80,proto:6}]})` then `dataplaneGRPC(edgeContainer, "AddLbBackend", {id:"lb", backend_underlay:bul})`.
5. Edge route to the backend for return/DSR bookkeeping if required (check the bash scenario: it used AddRoute for the VIP→backend). Add `dataplaneGRPC(edgeContainer, "AddRoute", {vni:0, prefix:"<VIP>/128", nexthop_underlay:bul})` if the edge needs it (verify against the datapath; wan_rx Maglev may not need an explicit route).
6. WAN client route + curl: on the `wan` container, `ip -6 route replace <VIP>/128 via fd00:29::11` (edge1), then `docker exec <wan> sh -c 'curl -6 -s --max-time 8 http://[<VIP>]:80/'` (or wget). Assert the body contains `hello-lb`.
7. `t.Cleanup`: DetachInterface backend; `DelLbVip` on the edge; kill the httpd; remove the wan route.

**Assertion:** the curl returns the backend's body — proving WAN→VIP→edge wan_rx Maglev→encap→backend uplink_rx decap→ingress fw→HTTP→DSR reply end-to-end. For **distribution**, optionally add a 2nd backend on `computeNodes(cfg)[1]` and curl repeatedly with varying source ports, asserting both backends serve at least once (Maglev spread). Keep the single-backend E2E as the core FATAL assertion; distribution can be a secondary check.

**DO NOT SKIP** (user directive): if the curl fails, root-cause with `sudo docker logs flowplane-edge1`, `ip -6 route get <VIP>` on the wan node, `ip -6 route get <bul>` on the edge, tcpdump on the edge eth3/eth1 and the backend netns, and the backend flowplane pod log. Fix the real problem (routing, firewall, MAC, MTU). Only if a genuine datapath CODE fix beyond wiring is required, STOP and report BLOCKED with evidence — never `t.Skip` to avoid effort.

- [ ] **Step 1..N:** implement the sequence above, live-validate PASS, then commit:
```bash
cd /home/nik/Development/ironcore-net-xdp
git add test/lab/livetest/lb_test.go
git commit -m "test(lab): TestLbDistributeSmoke — N/S IPv6 LB via the flowplane wan_rx edge

WAN client curls an IPv6 VIP -> edge wan_rx Maglev -> encap to backend -> uplink_rx
decap -> ingress fw -> HTTP server -> DSR reply. Live-validated PASS on the kind fabric.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

## Acceptance
- `flowplane-edge1` comes up on `make lab-up`, attaches `wan_rx`, gRPC reachable; no regression in the existing datapath/overlay tests.
- `TestLbDistributeSmoke` PASSES live (WAN curl of the v6 VIP returns the backend body). No `t.Skip`.
- The parent effort's Phase 4 full sweep stays green with the edge present.
