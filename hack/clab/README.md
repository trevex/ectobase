# IPv6 fabric (containerlab + kind) for ectobase

The integration environment for **ectobase** — the `flowplane` dataplane + the `netplane` control
plane: a **containerlab IPv6 fabric** wrapping one
or more **kind** clusters, with **FRR ToRs**, **dual VyOS WAN edges** (each with a `flowplane` sidecar),
a **Cilium** CNI, and the full **netplane** control plane deployed. It exercises the real paths:
underlay inference, overlay routing over the fabric, distributed SNAT + WAN egress through the edges,
North-South load balancing, and graceful datapath restart.

> Historical note: this started as a *lean* single-ToR underlay-inference lab; it has since grown the
> VyOS WAN edges, multiple kind clusters, and the netplane stack. The Cilium section at the bottom and
> the host/kernel gotchas are the load-bearing operational knowledge — read them.

## What is here

| File | Role |
|------|------|
| `ipv6-fabric.clab.yml` | Topology: FRR ToRs `sw1`/`sw2` (+ `sw1-pass`/`sw2-pass` xdp_pass sidecars), VyOS edges `edge1`/`edge2` (+ `edge1-xdp`/`edge2-xdp` dataplane sidecars), the `clabwan` "internet" bridge, and kind clusters `k01`/`k02`/`k03`. |
| `kind-cluster.yaml`, `kind-cluster-k0{2,3}.yaml` | The kind cluster configs clab deploys (IPv6, `disableDefaultCNI: true`, `kubeProxyMode: none`). |
| `frr/` | FRR configs for the ToRs (`sw1.conf`/`sw2.conf`) + `daemons`. Unnumbered eBGP-via-LLA transit + BFD + ECMP. |
| `vyos/` | VyOS edge boot configs (`edge{1,2}.boot`): BGP to the fabric + WAN forwarding/masquerade toward `clabwan`. |
| `cilium-up.sh`, `cilium-values.yaml` | Install Cilium (IPv6, tunnel/VXLAN mode) per kind cluster — the pod CNI (see below). |
| `wan-up.sh`, `wan-down.sh` | Create/destroy the `clabwan` host bridge + the WAN masquerade (the edges' path to the "internet"). |
| `edge-agents-up.sh`, `edge-xdp-wrapper.sh`, `sw-pass-wrapper.sh` | Start the edge `flowplane` sidecars (`--role edge`, `wan_rx`) + their brokered agents; the ToR xdp_pass shims. |
| `prefixes/` | Per-node announced-prefix inputs. |
| `../clab-up.sh`, `../clab-down.sh` | Idempotent deploy/destroy wrappers (WAN bring-up → clab deploy → Cilium per cluster). |

## Topology (k01 shown)

```
                 clabwan  (host bridge = "the internet", NAT-masqueraded)
                    │
          ┌─────────┴─────────┐
      edge1 (VyOS)        edge2 (VyOS)     WAN edges: VyOS owns BGP + WAN forwarding;
      + edge1-xdp         + edge2-xdp      a flowplane `--role edge` sidecar (wan_rx) shares its netns
          │                   │
        sw1 (FRR ToR)     sw2 (FRR ToR)    unnumbered eBGP-via-LLA transit + BFD + ECMP
          │   ┌───────────────┤            (sw{1,2}-pass = xdp_pass shims on the edge-facing ports)
   ┌──────┴───┴──────┐
   │ k01-control-plane│  k01-worker        kind nodes (ext-container): each runs the flowplane DaemonSet
   │   (fd00:db8:0:1::/64)  (…:0:2::/64)    + a netplane agent; Cilium is the pod CNI
   └──────────────────┘
```

## Bring it up

Prereqs — all provided by the default dev shell, so just run everything inside **`nix develop`**:

- `containerlab`, `kind`, `kubernetes-helm`, `docker`, `kubectl`, `envsubst` (gettext) — all in the
  default devShell (`flake.nix`); no `nix shell nixpkgs#…` or manual installs.
- The invoking **user** must be in the `docker` group and have **passwordless `sudo`**. The scripts
  run as your user and self-sudo ONLY the privileged bits (containerlab, `sysctl`, `iptables`, the
  host bpffs sweep) via `CLAB_SUDO` from `env.sh` — docker/kind/kubectl/helm run as you (your
  kubeconfig, your docker socket). No `sudo -E bash …` wrapper, no PATH shims.
- The `dummy` kernel module, and the images built (`make image` + `make image-netplane` +
  `make image-kindnode` at the repo root — `clab-up.sh` auto-builds the kind-node image if missing;
  `multicluster-e2e.sh` preflights the flowplane/netplane `:dev` images and fails loudly if absent).

All constants (fabric/overlay IPs, VNI, ports, `:dev` image refs, cluster/node names,
`CILIUM_VERSION`) live once in `env.sh`, sourced by every script and mirrored in `test/e2e/env.go`.

```bash
nix develop            # everything below runs inside the default dev shell
hack/clab-up.sh        # wan-up → clab deploy (--reconfigure, idempotent) → Cilium per cluster
# deploy the netplane stack (agent + reflector + controller) + the flowplane DaemonSet on k01:
# Helm (preferred): renders the same stack; dataplane=ebpf reproduces the kustomize manifests.
helm upgrade --install ectobase deploy/charts/ectobase --namespace ectobase-system --create-namespace
# Legacy kustomize (kept until the Helm chart passes a live clab smoke):
kubectl apply -k config/deploy            # (namespace ectobase-system)
hack/clab/edge-agents-up.sh               # start the WAN-edge flowplane sidecars + brokered agents

# end-to-end cross-cluster proof: deploys the stack across k01+k02 and asserts a k01<->k02
# overlay ping in BOTH directions (self-contained; applies the test/e2e/fixtures/multicluster
# kustomize scenario). This is the primary "does route distribution work" gate.
hack/multicluster-e2e.sh

# sanity: fabric addressing + BGP/BFD
docker exec k01-control-plane ip -6 -o addr show dev dummy0   # fd00:db8:0:1::1/64
docker exec clab-xdp-ipv6-fabric-sw1 vtysh -c 'show bgp ipv6 unicast summary'

# scenarios (repo root; need sudo + the flake PATH):
sudo -E bash test/scenario-nat-egress.sh   # container egress via distributed SNAT + the VyOS WAN edge
sudo -E bash test/scenario-lb-ingress.sh   # N-S load balancing
sudo -E bash test/scenario-restart.sh      # graceful datapath restart (crictl kill -> adopt)

hack/clab-down.sh      # destroy the fabric + kind clusters
```

## The kind ↔ containerlab integration

- **`k8s-kind` nodes** (`k01`/`k02`/`k03`) — containerlab owns the kind cluster lifecycle
  (create on deploy, delete on destroy).
- **`ext-container` nodes** (`k01-control-plane`, `k01-worker`, …) — the kind node containers,
  referenced by the exact name kind gives them; these are the clab link endpoints, so the kind nodes
  attach to the FRR fabric (`sw1:eth1 ↔ k01-control-plane:eth1`). Their `exec:` blocks create
  `dummy0` + the announced `/64` **inside the kind node's netns** — where `flowplane` infers from.
- **FRR runs in the kind node's netns** (shared-netns sidecar) so it can announce `dummy0`'s `/64`
  over the fabric uplink without baking FRR into the kubelet/containerd node image.
- **`vyosnetworks_vyos` edges** (`edge1`/`edge2`) run real VyOS (BGP + WAN forwarding, what hardware
  runs); a `flowplane --role edge` sidecar shares each edge's netns and owns the overlay `wan_rx` path.

The **mgmt-IPv6-disabled** note genuinely bites: a clab-auto mgmt IPv6 default route can outrank the
fabric — keep it disabled on the fabric nodes.

## CNI = Cilium (tunnel mode), and the harness gotchas behind it

The kind clusters run **Cilium** (not kindnet) — `disableDefaultCNI: true` + `kubeProxyMode:
none` in `kind-cluster*.yaml`, installed by `cilium-up.sh` (values in `cilium-values.yaml`,
IPv6-only, `routingMode: tunnel`/vxlan, `kubeProxyReplacement`). Rationale + the debugging that
led here:

- **Why not kindnet:** kindnet reconciles `ip -6 route add <peer-pod-CIDR> via <peer-InternalIP>`
  unconditionally and panics on `EHOSTUNREACH`. On our per-node `/64` BGP fabric the peer
  InternalIP is a BGP-recursive, non-on-link gateway, so that add can never succeed (no covering
  route or blackhole helps — kindnet adds it regardless). Cilium tunnel mode VXLAN-encaps pod
  traffic to the peer **node IP** instead, so the k8s pod overlay never enters the underlay FIB
  or the BGP fabric — which is also the production-correct separation.
- **Nodes come up NotReady until `cilium-up.sh` runs** (no default CNI). `clab-up.sh` therefore
  runs the deploy first, then installs Cilium per cluster. The k8s-kind `deploy.wait` is a
  boot-marker scan timeout (NOT a Ready gate) — keep it comfortably above the node's boot time.

`clab-up.sh` also handles three host/kernel + clab interactions that otherwise break a headless
bring-up (each cost real debugging — do not "simplify" them away):

1. **`bridge-nf-call-ip6tables=0`** — with it =1, even same-bridge IPv6 ND frames traverse the
   host ip6tables FORWARD chain, and clab sets that chain's policy to DROP with ACCEPT only for
   its own bridges (not the `kind` bridge). Result: a multi-node cluster's nodes can't ND each
   other over the kind bridge → worker can't reach the API → never Ready ("flaky boot-race").
2. **pty for the deploy** — clab's `vyosnetworks_vyos` kind talks to the VyOS CLI over a pty to
   wait for "Cli ready". Headless (backgrounded / CI / `>log`) that read fails
   (`read /dev/ptmx: input/output error`) and clab loops forever. `clab-up.sh` runs the deploy
   under `script(1)` when stdout is not a TTY.
3. **VyOS `admin` user + `enforce-startup-config: false`** — clab's vyos readiness probe runs
   `su - admin`, but `vyos:latest` ships only user `vyos`; `edge{1,2}.boot` therefore also define
   an `admin` login. Enforce is off because its `docker exec -it … su - admin` needs a TTY and
   re-applies config redundantly (config.boot is applied at boot regardless — BGP comes up).

**Cilium is pinned to >=1.20** (`cilium-up.sh`) for a reason: on an **nftables-only host kernel
without the legacy `ip6_tables` modules** (e.g. this NixOS box), Cilium <=1.19's IPv6 iptables
manager fatally `modprobe ip6_tables` on startup and the agent crash-loops (`could not load module
ip6_tables`) — even though the rules would go through `iptables-nft`/`nft_compat` fine and the
modules aren't actually needed (cilium/cilium#30638). kubeProxyReplacement forces
`install-iptables-rules=true`, so the "disable iptables rules" escape does not apply. **Cilium
1.20 handles the missing legacy module gracefully**, so agents come up `1/1` on the stock config
here. (If you must run an older Cilium, the alternative is a modprobe stub — `install ip6_tables
/bin/true` in the agent's modprobe.d — or providing the modules via the host kernel config.)
