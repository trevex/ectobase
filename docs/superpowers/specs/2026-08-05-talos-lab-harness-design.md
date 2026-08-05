# Talos Lab Harness (Go/cobra) — Design

**Status:** Approved (brainstorm output) — ready for implementation planning.
**Date:** 2026-08-05
**Branch:** `feat/talos-lab-harness` (off the `feat/tier2-live-gate` fixes it reuses).

## 1. Motivation

The current test fabric is kind + containerlab + bash (`hack/clab/*`, `hack/clab-up.sh`, `test/*.sh`). Running the Tier-2 live gate on it surfaced structural limits that are the *fabric's*, not the product's: kind nodes ship no kernel modules / read-only `/sys` / tmpfs `/dev` (krbd needs all three), the cluster is IPv6-only with **no fabric egress** (pods reach the internet only through a docker mgmt side-channel, which breaks CDI image pulls), and everything is imperative bash that pulls from the internet every run.

`icn/sandbox` (a Go + mage lab) already solves this cleanly: a pure-IPv6 unnumbered-eBGP fabric of VyOS edges (default-origin + DNS64 + Tayga NAT64) and switches (RA + transit), Talos nodes as native GoBGP speakers, fabric-only egress, and a WAN sim that masquerades to the real internet. This design **adopts icn/sandbox's mechanics** in a new, self-contained Go/**cobra** harness under `test/` for ectobase — with a **local registry mirror** so we stop pulling from the internet every run.

## 2. Scope

**In scope (this foundation slice):**
- A Go/cobra CLI harness under `test/lab/` (a new module in `go.work`), coexisting additively with the existing kind/clab bash fabric (nothing existing is changed or removed).
- A **multi-cluster** Talos IPv6-BGP fabric on containerlab (**containers only**, no VMs): VyOS edges + VyOS switches (**RA**) + Tayga NAT64/DNS64 + WAN sim + **local registry mirror**; **fabric-only egress** (no docker side-channel).
- **N clusters, M nodes each** — default 1 node per cluster, node count **templatable per cluster** (generalizing icn/sandbox's single-cluster/N-node model). Each cluster is a distinct Talos cluster (own etcd + anycast API VIP + kubeconfig) on the shared fabric.
- The three **container** images under `test/images/**` (talos-container, tayga, vyos-clab) wired into the `Makefile`. No `vrnetlab-base`, no VM variants, no `test-environment-node`.
- A **pull-through + push-local** registry mirror with a **persistent cache volume** surviving `down`/`up`, wired as a Talos `machine.registries.mirrors` target.
- **Last step of `up`:** deploy the ectobase control-plane + overlay substrate (central + brokers + flowplane/netplane) across the clusters via explicit YAML + Helm, verify both compute **ClusterPools `Ready` with NodePrefixes** + a cross-cluster overlay ping.

**Out of scope (follow-on specs):**
- Ceph / ceph-csi / csi-addons and the **Tier-2 VM-reschedule gate** on the Talos harness.
- Migrating the existing `test/*.sh` scenarios onto Talos; retiring `hack/clab`.
- Pluggable multi-topology architecture (icn/sandbox's `Topology` registry) — single `fabric` topology only (Approach B, below).
- Full airgap (fully-preloaded registry); VM (vrnetlab) nodes.

## 3. Approach

**Chosen: B — simplified single-kind harness.** Adopt icn/sandbox's proven *mechanics* — the render pipeline (templates → `build/<name>/`), Talos container-mode (`PLATFORM=container` + base64 `USERDATA` + bind-mounts), offline VyOS render (`vyos-commands-to-config`), fabric-only egress, native Talos `BGPPeerConfig` GoBGP, and the registry mirror — but as **one `fabric` topology** with a flat, focused package layout and a cobra CLI, dropping the pluggable-kind registry (YAGNI: ectobase has exactly one topology). Rejected: A (faithful port with `Topology` plugin registry — more abstraction than needed) and C (thin bash-in-Go wrapper — loses typed config/validation/testable seams).

## 4. Repo layout & CLI

New Go module `test/lab/` (module `github.com/trevex/ectobase/test/lab`, added to `go.work`). Cobra CLI → a `lab` binary, also `go run ./test/lab`.

```
test/lab/
  go.mod
  main.go                      # cobra root; --config (default test/lab/lab.yaml) → $LAB_CONFIG
  cmd/                         # up, down, render, deploy, test, kubeconfig, kubectl, ssh, capture
  internal/
    config/                    # typed load + validate + per-cluster prefix derivation
    render/                    # sprig template rendering → build/<name>/
    clab/                      # containerlab deploy/destroy wrapper (sudo -E)
    talos/                     # machineconfig gen (container mode) + bootstrap
    vyos/                      # offline `vyos-commands-to-config` render
    registry/                  # local pull-through + push registry lifecycle (persistent cache)
    deploy/                    # ectobase stack deploy (helm + kubectl)
    exec/, wait/, log/         # subprocess, polling, slog helpers
  templates/                   # *.clab.yml.tmpl, vyos/*.set.tmpl, talos/*.tmpl, k8s/*.tmpl
  topology/fabric.go           # the single orchestration wiring the above together
  build/                       # gitignored: render output, kubeconfigs, talos secrets
```

Commands (icn/sandbox mage targets, minus mage): `lab up` (render → registry up → clab deploy → per-cluster bootstrap+wait Ready → Cilium → **deploy ectobase**), `lab down [--purge]`, `lab render`, `lab deploy`, `lab test`, plus access helpers `lab kubeconfig/kubectl/ssh/capture`.

## 5. Config model

One typed `lab.yaml` (no pluggable-kind envelope):

```yaml
name: ectobase
images:
  talos:    ghcr.io/trevex/ectobase/talos:container
  vyos:     ghcr.io/trevex/ectobase/vyos:clab
  tayga:    ghcr.io/trevex/ectobase/tayga:latest
  registry: registry:2
fabric:
  as: { edge: 65000, switch: 65010, host: 65100 }
  nat64Prefix: 64:ff9b::/96
  registry:
    upstreams: [docker.io, ghcr.io, quay.io, registry.k8s.io, gcr.io]
    push: [flowplane, netplane, cni, central-apiserver, central-controller, central-broker]  # :dev
  clusters:
    - { name: central, nodes: 1 }   # k01 role (central apiserver + controller)
    - { name: k02, nodes: 1 }
    - { name: k03, nodes: 1 }
```

Each cluster = a distinct Talos cluster (own etcd + anycast API VIP + kubeconfig) sharing the fabric. Per-cluster/per-node IPv6 prefixes are **derived** (FNV hash of `name`, icn/sandbox-style) so parallel clusters never collide: each node gets a `/128` identity + its cluster's API VIP `/128`, each switch host-port an RA `/64`. `nodes` templatable per cluster (default 1). Validation: ASNs > 0, node counts 1–15 (hex nibble), CIDR/addr syntax, unique cluster names.

## 6. Fabric topology & fabric-only egress

Containerlab, **containers only**:

- **`sw1`, `sw2`** (VyOS, AS 65010) — transit eBGP peering both edges + every Talos node across all clusters (`as-override` on the host peer-group); **RA (`service router-advert`) on each host-facing port** advertising that port's `/64` + the edge DNS64 name-server. Host-port count templated = total nodes.
- **`edge1`, `edge2`** (VyOS, AS 65000) — unnumbered eBGP to both switches, **`default-originate`** (::/0) + advertise `64:ff9b::/96`; **DNS64 forwarding** on a loopback (`fd00:ffff::e1/e2`, upstream `2606:4700:4700::1111`); `eth3`→WAN, `eth4`→its tayga.
- **`nat64-1/2`** (tayga) — `64:ff9b::/96` → IPv4 pool → MASQUERADE to WAN, one per edge.
- **`wan`** (WAN sim) — masquerades all fabric prefixes to the real host uplink; the host's single route into the fabric.
- **`registry`** (registry:2) — on the WAN segment (`fd00:29::/64`): fabric-reachable by nodes via edge→WAN, and has WAN internet for pull-through.
- **Talos nodes** `<cluster>-<n>` (talos:container) — dual-homed `eth1`→sw1 / `eth2`→sw2; native GoBGP (AS 65100) advertising `dummy0` `/128` + `vip0`.

**Fabric-only egress ("no side channel"):** the Talos machine config makes the docker **mgmt interface carry no default route** — the node's default (::/0) comes only from the edges via GoBGP + the switch RA, so all internet-bound traffic goes node→switch→edge→(tayga NAT64 for v4)→WAN→real internet; DNS is the edge DNS64 loopback. The docker mgmt net is used solely for clab management, never egress.

## 7. Talos machine-config & registry mirror

Talos boots as a **container** (icn/sandbox mechanism): `PLATFORM=container`, base64 machineconfig in `USERDATA`, `/var //run //etc/cni` bind-mounted from `build/<name>/mounts/…`, `/usr/lib/modules:ro`. **Per cluster:** own `talosctl gen secrets` (persisted) + `gen config` → own etcd + kubeconfig. **Per node:** a patch adds the `dummy0 /128` identity + `BGPPeerConfig` (peers both switches; advertises `dummy0` + `vip0`). **Cluster-wide patch:** `KubeNodeConfig.nodeIP` = fabric `/64`, `ResolverConfig` = edge DNS64 loopbacks, `KubeProxyConfig.enabled=false`, etcd `advertisedSubnets` = fabric, and the health-gated **anycast API-VIP** static pod (holds `vip0` only while `/healthz` is ok → BGP withdraws it on failure → ECMP to healthy nodes). **CNI:** Cilium (IPv6-only, vxlan tunnel, kube-proxy replacement) via Helm.

**Registry mirror:** the `registry:2` node runs per-upstream **proxy/pull-through** remotes backed by a **named docker volume `ectobase-lab-registry-cache`** that survives `down`/`up`; `up` also **pushes the local `:dev` images** (flowplane/netplane/cni/central-*) into it. Every Talos machine config sets `machine.registries.mirrors` for each upstream → the registry's fabric-reachable address. All pulls go node→fabric→registry (cached or local); only cold pulls reach the internet, over the WAN. `lab down` keeps the cache volume by default; `lab down --purge` removes it.

## 8. Ectobase deploy (last step of `up`)

Reuses the **existing committed artifacts** — explicit YAML + Helm, no new manifests: `central/config` (kustomize) on the `central` cluster + the `deploy/charts/ectobase` Helm chart (`broker.enabled`) on each compute cluster, minting the broker central-token — the Phase-3 substrate already made green on kind, now codified in the `deploy` package on Talos. **Foundation scope:** central + brokers + flowplane/agent/reflector up; both compute **ClusterPools `Ready` with NodePrefixes**; a cross-cluster overlay ping. (Ceph/csi-addons + the Tier-2 VM gate are the follow-on spec.)

## 9. Images (`test/images/**`) + Makefile

Port only the **container** variants from `icn/images`:
- `test/images/talos/` — `container/Dockerfile` + `extract-rootfs.sh` (imager initramfs → sqfs → rootfs tar → `FROM scratch` + `in-container` marker). Pinned Talos version.
- `test/images/tayga/` — `Dockerfile` (debian + tayga/iptables/iproute2) + `entrypoint.sh` (renders `/etc/tayga.conf`, wires the `nat64` TUN + `64:ff9b::/96`/pool routes + MASQUERADE).
- `test/images/vyos/` — `clab/Dockerfile` + `fetch-iso.sh`/`extract-rootfs.sh` + the `clab-lla-ensure` EUI-64 link-local fix service. Pinned VyOS rolling ISO.

**Makefile:** `make lab-images` (+ `image-talos`/`image-tayga`/`image-vyos`), tagged `ghcr.io/trevex/ectobase/{talos:container,tayga:latest,vyos:clab}`. Rootfs-extraction tooling (`squashfs-tools-ng`, `libarchive`/`bsdtar`, `talosctl`/imager) is added to the nix devShell.

## 10. Testing

- **Live suite** (`lab test`, `//go:build live`): BGP sessions established; host-route propagation + ≥2-path ECMP; edges originate `::/0`; per-cluster API-VIP anycast (one path per node); **NAT64+DNS64** (ping `64:ff9b::1.1.1.1` + dig a synthesized AAAA); **registry mirror** serves (a pull-through upstream image + a local `:dev` image); **fabric-only egress** (a node reaches the internet via the edge; mgmt has no default route).
- **Ectobase verification:** both compute ClusterPools `Ready` + a cross-cluster overlay ping.
- **Unit tests** (no fabric): config validation, per-cluster prefix derivation, golden-file template renders.

## 11. Success criteria

- `make lab-images && go run ./test/lab up` brings up the multi-cluster Talos fabric on containerlab (containers only), all clusters `Ready`, **egress only over the fabric** (mgmt carries no default), image pulls served by the local registry mirror (persistent cache across runs), and the ectobase substrate deployed with both compute ClusterPools `Ready` + a cross-cluster overlay ping.
- `lab down` tears down cleanly and **keeps** the registry cache (unless `--purge`); a second `up` is materially faster (no cold pulls).
- Additive: the existing kind/clab bash fabric and `make chart-test` / envtests are untouched and still green.
- `lab test` (live) passes the connectivity + egress + registry + ectobase assertions.
