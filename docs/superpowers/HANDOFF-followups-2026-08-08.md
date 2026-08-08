# Fresh-session handoff — 4 follow-ups after the retire-bash-clab effort

Paste the section below into a fresh session to continue. The retire-bash-clab effort is
DONE and merged on `main` (bash `hack/clab` retired; all datapath + control-plane e2e
coverage ported to the Go `test/lab` kind fabric; `make lab-test` = 20/20 green; `lab down`
zero host leftovers). These are the tracked follow-ups it deliberately deferred.

---

## PROMPT (copy from here)

Continue the ectobase follow-ups left by the completed "retire-bash-clab" effort (branch
`main`). Read these first for full context, then work the follow-ups below:
- Memory: `retire-bash-clab-datapath-to-go`, `container-workload-crd-followup`,
  `feedback-tests-through-control-plane`, `feedback-dont-skip-tests`,
  `agent-reads-only-compilednic`, `phase4-kubevirt-vm-lifecycle`, `phase3-scheduler-failover`.
- Specs/plans: `docs/superpowers/plans/2026-08-08-ns-lb-pseudo-edge-kind.md`,
  `docs/superpowers/specs/2026-08-08-container-workload-crd-design.md`.

### Execution conventions (this repo)
- Run Go through the nix devShell: `nix develop --command bash -c '<cmd>'`. central builds
  with `GOWORK=off` (local apiserver-kit replace; build-on-this-machine).
- Live/lab commands need root inside the devShell: `sudo -E env "PATH=$PATH" <cmd>`. The
  Makefile wraps the lab CLI: `make lab-{render,up,down,down-purge,deploy,ceph,tier2-up,test}`.
  Direct `go test -tags live ./livetest/...` from `test/lab` needs `LAB_CONFIG="$(pwd)/lab.yaml"`.
- `test/lab` templates are `go:embed`'d → `go run ./test/lab` always re-embeds (no rebuild dance).
- App images are `:dev`, built locally + pushed to the in-fabric mirror; `lab up` pushes but
  does NOT build them. Rebuild an app image + push to `127.0.0.1:5000/trevex/ectobase/<name>:dev`
  + `crictl rmi` the stale image on the node(s) + `rollout restart` to pick it up (the pattern
  used all through the effort). central images: build via `central/hack/smoke.sh`'s
  `GOWORK=off go build ./cmd/{apiserver,controller,broker}` + `docker build -f central/Dockerfile.*`.
- NEVER `git add -A` (untracked `central/{broker,central-broker,controller}` binaries exist);
  stage explicit paths. Pre-commit hook runs clippy/rustfmt only — it does NOT run go test;
  verify Go builds/tests yourself. End commit messages with the Co-Authored-By trailer.
- Prefer subagent-driven-development for multi-task work; run git-mutating subagents
  SEQUENTIALLY. Keep the fabric warm across tasks (one `make lab-up` for all live work).
- User directives (hard rules): (a) DRIVE TESTS THROUGH THE CONTROL PLANE — spawn real
  Pods (Multus + flowplane-cni) / KubeVirt VMs, not direct dataplane gRPC, where feasible;
  (b) DO NOT needlessly `t.Skip` or weaken assertions — root-cause failures and fix the
  real code; a skip needs evidence + explicit human sign-off.

### Current fabric-attach model (important background)
A Pod attaches to our overlay as a Multus SECONDARY network (`k8s.v1.cni.cncf.io/networks`,
iface `net1`; kindnet stays primary `eth0`). flowplane-cni reads the broker-synced
`CompiledNIC <ns>-<nic>` (RBAC `compilednics.get`) for `{vni, ips, mac}` and calls the
node-local dataplane `AttachInterface`. Pod placement currently uses the
`NetworkInterface.spec.clusterName` shortcut (compiler `resolvePlacement`: owning VM >
`nic.spec.clusterName` > `--cluster-name` default). `CompiledNIC.spec.mac` carries the MAC.

### Follow-up 1 (biggest, most valuable) — first-class Container workload CRD
Spec: `docs/superpowers/specs/2026-08-08-container-workload-crd-design.md`. Add a
`net.ectobase.dev/Container` workload CRD symmetric to `VirtualMachine`: schedulable
(`spec.clusterName` bound by the Phase-3 scheduler; `resources`/`poolSelector`/`antiAffinity`),
owns NICs via `interfaceRefs` (compiler `resolvePlacement` derives NIC placement from owning
Containers → `NetworkInterface.spec.clusterName` reverts to a fallback/removed), compiles to
`CompiledContainer` (broker-synced by `spec.clusterName`), and a NEW **pod-materializer**
(mirror `netplane/controllers/vmmaterializer.go`) turns `CompiledContainer` → a real `v1.Pod`
with the Multus NAD + `net.ectobase.dev/network-interface` annotation (→ flowplane-cni attaches
via the CompiledNIC). Then rework `TestPodOverlayPing`/`TestVPCPeering` to create a `Container`
on central instead of a raw Pod. NOTE the central aggregated-apiserver conversion caveat: net
types are internal+external(aliases to `api/v1alpha1`)+hand-written `conversion.go`+roundtrip
fuzz (see how CP.2a `df9a4b7` added fields). START by brainstorming naming (Container vs
Workload vs Pod) + whether to remove `NIC.spec.clusterName`, then spec→plan→implement. This is
a multi-component feature — use subagent-driven-development.

### Follow-up 2 — N/S LoadBalancer via a flowplane pseudo-edge (kind)
Plan: `docs/superpowers/plans/2026-08-08-ns-lb-pseudo-edge-kind.md` (detailed, ready to
execute). Add a flowplane `wan_rx` edge sidecar sharing the VyOS `edge1` netns
(`flowplane serve --role edge --uplink eth1 --extra-uplink eth2 --wan-uplink eth3
--local-underlay fd00:ffff::e1 --pin-links false`), then a Go `TestLbDistributeSmoke`:
WAN client curls an **IPv6** VIP (kind edge WAN ifaces are v6-only) → edge `wan_rx` Maglev →
encap to backend → `uplink_rx` decap → ingress fw → backend HTTP → DSR reply. Reference the
deleted `test/scenario-lb-ingress.sh` logic via git history. LB datapath LOGIC is already
proven by `flowplane-sim/src/lb_scenario_test.rs` + the byte-parity anchor `anchor_lb.rs`;
this adds the live gRPC-programs-maps + real-kernel-forward proof. Key risks: SKB `wan_rx`
attach in the VyOS netns, ToR gateway-MAC resolution, v6 VIP WAN routing + DSR return.

### Follow-up 3 (small) — DPDK guest-name bug (mirror of the eBPF fix)
`flowplane-dpdk/src/node.rs:125` uses `r.interface_id` verbatim as the guest device name —
the SAME bug fixed in the eBPF `attach.rs` (CP.1, commit `ec59cdb`): a CNI-driven
`interface_id` like `<pod-uid>/net1` has `/` + >15 chars and fails the in-netns rename. Apply
the same fix: reuse/port the `guest_ifname()` helper (trailing CNI ifname if a valid ≤15-char
device name, else a stable FNV `g-<hash>`; keep the full `interface_id` as the map key; Detach
stays name-agnostic). Add unit tests. This is DPDK-only (no live gate on this dev host without
a real NIC) — verify via `cargo test` + the sim; it matters when the DPDK dataplane is fronted
by flowplane-cni.

### Follow-up 4 (small cleanup) — prune orphaned test/e2e fixtures
After Phase 3, `test/e2e` has NO `package e2e` tests left (only `cmd/` probe sources +
`internal/` unit tests). Audit `test/e2e/fixtures/{kubevirt,edge,cni,multicluster-tier2}` —
their consumers (the deleted datapath tests + bash scenarios) are gone. Confirm nothing live
references each (git grep; note `test/lab/livetest/testdata/tier2-vm.yaml` has a *comment*
pointing at `multicluster-tier2` — update or drop it), then `git rm` the truly-dead ones +
their `.gitignore` render rules. Keep `test/e2e/cmd/` + `go.mod`/`go.sum` (the livetests build
probes from there). Purely subtractive; verify `test/e2e` + `test/lab` still build/vet.

### Suggested order
3 and 4 are quick wins (small, low-risk) — do them first. Then 2 (LB, plan ready). Then 1
(Container CRD, the big one — brainstorm/spec first). Confirm scope with me before the
Container CRD build.

## (end prompt)
