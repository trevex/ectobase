# Fabric Dual-Homing + ECMP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dual-home every fabric kind node to **two** FRR ToRs (`sw1`, `sw2`) so each node's `/64` is announced on both uplinks and reachable via **ECMP** (equal-cost, `multipath-relax` + `maximum-paths`) with **BFD** sub-second failover — a faithful leaf-spine underlay — while the existing single-uplink xdp-dp datapath keeps working.

**Architecture:** Add a second ToR `sw2` (FRR, AS 65010, no `sw1–sw2` interlink — redundancy *is* the dual-homing, per `icn/sandbox/FABRIC.md`). Each kind node gets a second uplink `eth2 → sw2` alongside `eth1 → sw1`. The in-node `fabric-preboot` FRR config generator already loops over `UPLINKS`; we set `UPLINKS="eth1 eth2"` via an `/etc/fabric/uplinks` mount and add a `fabric-fast` BFD profile to the generated config. The kubelet BGP-convergence gate already covers both uplinks. **No datapath changes** — xdp-dp still egresses on `eth1`; the fabric ECMPs the return path. (Datapath egress ECMP is the separate Phase-3 plan.)

**Tech Stack:** containerlab, kind (custom node image), FRR (unnumbered eBGP + BFD), bash/YAML.

**Prereqs:** Phase 1 shipped (`docs/superpowers/plans/2026-07-14-fabric-node-identity-integration.md`) — custom node image, in-node FRR, per-node `/64` via `extraMounts`, node-IP = fabric addr. Design/context: `docs/superpowers/research/2026-07-14-realistic-bgp-fabric-node-identity.md` + memory `dpservice-dual-homing-egress`.

---

## File Structure

- `hack/clab/frr/sw2.conf` — second ToR config, mirrors `sw1.conf` (Create).
- `hack/kind-fabric-node/fabric-preboot.sh` — add a `fabric-fast` BFD profile + `neighbor <u> bfd` per uplink to the generated node FRR config (Modify).
- `hack/clab/prefixes/uplinks` — shared file `eth1 eth2`, mounted to `/etc/fabric/uplinks` (Create).
- `hack/clab/kind-cluster.yaml`, `hack/clab/kind-cluster-k02.yaml` — add the `/etc/fabric/uplinks` mount to every node (Modify).
- `hack/clab/ipv6-fabric.clab.yml` — add the `sw2` node + the three `eth2 → sw2` links (Modify).

---

### Task 1: Second ToR (`sw2`) FRR config

**Files:**
- Create: `hack/clab/frr/sw2.conf`

- [ ] **Step 1: Create `sw2.conf` mirroring `sw1.conf`**

`sw2` is identical to `sw1` (AS 65010, three host-facing unnumbered eBGP interfaces `eth1/eth2/eth3`, `fabric-fast` BFD, `maximum-paths`) with a distinct router-id. Read `hack/clab/frr/sw1.conf` first, then create `hack/clab/frr/sw2.conf` as a copy with:
- `hostname sw2`
- `bgp router-id 10.0.1.2` (sw1 uses `10.0.1.1`)
- everything else identical (the `interface eth1/2/3`, the `bfd`/`profile fabric-fast` block, `router bgp 65010`, the three `neighbor ethN interface remote-as external` + `neighbor ethN bfd profile fabric-fast`, and the `address-family ipv6 unicast` with `maximum-paths 64` + the three `neighbor ethN activate`).

Quick way (then hand-fix the router-id if sed touched anything unintended):

```bash
sed -e 's/hostname sw1/hostname sw2/' -e 's/bgp router-id 10.0.1.1/bgp router-id 10.0.1.2/' \
    hack/clab/frr/sw1.conf > hack/clab/frr/sw2.conf
```

- [ ] **Step 2: Verify it differs only in hostname + router-id**

Run: `diff hack/clab/frr/sw1.conf hack/clab/frr/sw2.conf`
Expected: exactly two changed lines (`hostname`, `bgp router-id`).

- [ ] **Step 3: Commit**

```bash
git add hack/clab/frr/sw2.conf
git commit -m "feat(fabric): second ToR sw2 (dual-homing)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: BFD in the in-node FRR config

**Files:**
- Modify: `hack/kind-fabric-node/fabric-preboot.sh`

**Context:** The generated node FRR config has ECMP knobs (`multipath-relax`, `maximum-paths 64`) but no BFD. Add the `fabric-fast` profile (150 ms × 3, matching the ToRs) and a `neighbor <u> bfd profile fabric-fast` per uplink so failover is sub-second on either link.

- [ ] **Step 1: Add the BFD profile + per-neighbor BFD to the generator**

In `hack/kind-fabric-node/fabric-preboot.sh`, in the `{ … } > /etc/frr/frr.conf` heredoc-style block, make two edits:

(a) After the `echo "hostname $(hostname)"` line, add the BFD profile block:

```bash
  echo "bfd"
  echo " profile fabric-fast"
  echo "  transmit-interval 150"
  echo "  receive-interval 150"
  echo "  detect-multiplier 3"
  echo " exit"
  echo "exit"
```

(b) In the loop that emits `neighbor $u interface remote-as external`, add a BFD line right after it, so the loop becomes:

```bash
  for u in $UPLINKS; do
    echo " neighbor $u interface remote-as external"
    echo " neighbor $u bfd profile fabric-fast"
  done
```

- [ ] **Step 2: Rebuild the image**

Run: `make image-kindnode 2>&1 | tail -2`
Expected: build succeeds.

- [ ] **Step 3: Commit**

```bash
git add hack/kind-fabric-node/fabric-preboot.sh
git commit -m "feat(fabric): BFD (fabric-fast) on the in-node FRR uplinks

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Uplinks mount (`eth1 eth2`) on every node

**Files:**
- Create: `hack/clab/prefixes/uplinks`
- Modify: `hack/clab/kind-cluster.yaml`, `hack/clab/kind-cluster-k02.yaml`

**Context:** `fabric-preboot` reads `/etc/fabric/uplinks` (space-separated) and defaults to `eth1`. Mounting a file with `eth1 eth2` makes the node peer both ToRs. One shared file works (all nodes use the same uplink names). It lives in the `prefixes/` dir so the existing `clab-up` `PREFIX_DIR` render covers its absolute path.

- [ ] **Step 1: Create the shared uplinks file**

```bash
echo "eth1 eth2" > hack/clab/prefixes/uplinks
```

- [ ] **Step 2: Add the mount to every node in both kind configs**

In `hack/clab/kind-cluster.yaml`, add a SECOND `extraMounts` entry to BOTH nodes (alongside the existing `/etc/fabric/prefix` mount). For each node the `extraMounts` list becomes:

```yaml
    extraMounts:
      - hostPath: PREFIX_DIR/k01-control-plane.prefix   # (or k01-worker.prefix)
        containerPath: /etc/fabric/prefix
        readOnly: true
      - hostPath: PREFIX_DIR/uplinks
        containerPath: /etc/fabric/uplinks
        readOnly: true
```

Do the same in `hack/clab/kind-cluster-k02.yaml` for `k02-control-plane` (its prefix mount + the `PREFIX_DIR/uplinks` mount). `PREFIX_DIR` is rendered to an absolute path by `clab-up` (Phase 1 mechanism) — keep the placeholder.

- [ ] **Step 3: Verify the render produces valid absolute paths**

Run:
```bash
sed "s#PREFIX_DIR#$(pwd)/hack/clab/prefixes#g" hack/clab/kind-cluster.yaml | grep -A1 uplinks
```
Expected: `hostPath: <repo>/hack/clab/prefixes/uplinks` for each node.

- [ ] **Step 4: Commit**

```bash
git add hack/clab/prefixes/uplinks hack/clab/kind-cluster.yaml hack/clab/kind-cluster-k02.yaml
git commit -m "feat(fabric): mount /etc/fabric/uplinks=eth1 eth2 (dual-home the nodes)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Topology — add `sw2` + the `eth2` uplinks

**Files:**
- Modify: `hack/clab/ipv6-fabric.clab.yml`

- [ ] **Step 1: Add the `sw2` node**

In `hack/clab/ipv6-fabric.clab.yml`, next to the `sw1:` node block, add `sw2` (same shape as `sw1`, binding `sw2.conf`):

```yaml
    sw2:
      kind: linux
      binds:
        - frr/daemons:/etc/frr/daemons
        - frr/sw2.conf:/etc/frr/frr.conf
      sysctls:
        net.ipv6.conf.all.forwarding: 1
```

- [ ] **Step 2: Add the three `eth2 → sw2` links**

In the `links:` list, after the existing `eth1 → sw1` links, add:

```yaml
    - endpoints: ["k01-control-plane:eth2", "sw2:eth1"]
    - endpoints: ["k01-worker:eth2", "sw2:eth2"]
    - endpoints: ["k02-control-plane:eth2", "sw2:eth3"]
```

- [ ] **Step 3: Validate the topology parses**

Run: `PATH=$HOME/go/bin:$PATH containerlab inspect -t hack/clab/ipv6-fabric.clab.yml --format json 2>&1 | head -3 || true`
Expected: no parse error; `sw2` present in the node list.

- [ ] **Step 4: Commit**

```bash
git add hack/clab/ipv6-fabric.clab.yml
git commit -m "feat(fabric): dual-home each node to sw2 via eth2

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Deploy + verify dual-homed ECMP end-to-end

**Files:** none (verification; controller drives this live — sudo + containerlab)

- [ ] **Step 1: Redeploy the fabric**

```bash
export PATH="$HOME/go/bin:$PATH"
sudo -E env "PATH=$HOME/go/bin:/usr/bin:/bin:$PATH" containerlab destroy -t hack/clab/ipv6-fabric.clab.yml --cleanup 2>&1 | tail -2
sudo -E env "PATH=$HOME/go/bin:/usr/bin:/bin:$PATH" ./hack/clab-up.sh 2>&1 | tail -6
```
Expected: fabric deploys with `sw1` AND `sw2`; all nodes present.
(If a prior deploy left orphaned containers not in the current topology, `docker rm -f` them + `docker network rm xdp-clab`, per the Phase-1 memory note.)

- [ ] **Step 2: Each node has TWO established BGP sessions (sw1 + sw2)**

```bash
for n in k01-control-plane k01-worker k02-control-plane; do
  echo "== $n =="
  sudo docker exec "$n" vtysh -c "show bgp ipv6 unicast summary" 2>/dev/null | grep -E 'sw1|sw2|eth1|eth2' 
done
```
Expected: two neighbor lines per node (over `eth1` and `eth2`), both Established (numeric `State/PfxRcd`).

- [ ] **Step 3: Peer `/64`s installed with TWO next-hops (ECMP in the FIB)**

```bash
sudo docker exec k01-control-plane ip -6 route show fd00:db8:0:2::/64
sudo docker exec k02-control-plane ip -6 route show fd00:db8:0:1::/64
```
Expected: each route shows **two** `nexthop … dev eth1` / `nexthop … dev eth2` entries (ECMP), e.g. a multipath route (`fd00:db8:0:2::/64 proto bgp metric 20` with `nexthop via … dev eth1 weight 1` + `nexthop via … dev eth2 weight 1`).

- [ ] **Step 4: BFD sessions up on both uplinks**

```bash
sudo docker exec k01-control-plane vtysh -c "show bfd peers brief" 2>/dev/null | tail -5
```
Expected: two BFD peers (one per uplink), state `up`.

- [ ] **Step 5: Failover — down one uplink, `/64` still reachable via the other**

```bash
# drop eth2 on k01-control-plane; the peer /64 must stay reachable (via eth1) and BFD marks eth2 down fast
sudo docker exec k01-control-plane ip link set eth2 down
sleep 2
sudo docker exec k01-control-plane ip -6 route show fd00:db8:0:2::/64
sudo docker exec k01-control-plane ip link set eth2 up
```
Expected: after `eth2 down`, the route to `fd00:db8:0:2::/64` remains (now single next-hop via `eth1`) — sub-second BFD failover, no blackhole. (Bring eth2 back up to restore ECMP.)

- [ ] **Step 6: Regression — xdp-dp overlay still green on the dual-homed fabric**

```bash
export PATH="$HOME/go/bin:$PATH"
for c in k01 k02; do
  sudo kind load docker-image ghcr.io/trevex/dpservice-xdp:dev --name "$c"
  sudo kind load docker-image ghcr.io/trevex/netplane:dev --name "$c"
done
bash hack/multicluster-e2e.sh 2>&1 | tail -12
```
Expected: cross-cluster overlay ping **0% loss** both ways. The datapath still egresses on `eth1` (single uplink); the dual-homed fabric ECMPs the return path — confirms dual-homing didn't regress the dataplane. (Egress-side ECMP is the Phase-3 plan.)

- [ ] **Step 7: Document validation**

Append a one-line status to the research doc noting dual-homing is validated (2 sessions/node, ECMP FIB, BFD failover, overlay green), then commit:

```bash
git add docs/superpowers/research/2026-07-14-realistic-bgp-fabric-node-identity.md
git commit -m "docs(fabric): dual-homing + ECMP validated

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Design coverage:** dual ToR (T1 `sw2`), second uplink per node (T4 links), node peers both + ECMP (existing `UPLINKS` loop + `multipath-relax`/`maximum-paths`, driven by T3 mount), BFD (T2 node config + `sw2`'s inherited BFD), failover proof (T5.5), and the datapath regression (T5.6). No `sw1–sw2` interlink (matches the icn/sandbox reference — redundancy via dual-homing). The kubelet BGP gate is unchanged and already covers two uplinks (waits for the first learned route).

**2. Placeholder scan:** Only `PREFIX_DIR` (the Phase-1 render mechanism, resolved by `clab-up`) — documented, not a gap. No TBD/vague steps.

**3. Consistency:** `UPLINKS="eth1 eth2"` (T3 file) matches the `eth2` links (T4) and `sw2`'s three host-facing interfaces (T1, mirroring `sw1`). Router-ids distinct (`sw1=10.0.1.1`, `sw2=10.0.1.2`; nodes keep `10.0.2.x`). BFD profile name `fabric-fast` identical across `sw1`/`sw2`/node configs (required for the profile to match). Both switches share AS 65010; nodes AS 65100 with `allowas-in 1` (already generated) so a node accepts the other node's `/64` transited via the shared-AS switches.

**Deferred (separate plan):** xdp-dp egress ECMP — grow `LOCAL` to two uplinks + a 50/50 active-active WCMP table + per-port ToR MAC from netlink neigh (mirroring dpservice), so *outbound* traffic uses both uplinks too.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-14-fabric-dual-homing-ecmp.md`. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task for the edits (Tasks 1–4); the controller drives the live redeploy + verification (Task 5) inline (sudo + containerlab).
2. **Inline Execution** — execute here with checkpoints.

Which approach?
