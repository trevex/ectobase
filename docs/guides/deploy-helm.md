# Deploying with Helm

!!! success "Status: Implemented"
    ectobase deploys as **two Helm charts** — one for the fleet/dispatch cluster, one per
    compute/pool cluster. The charts are the generated deploy artifact: their CRDs and RBAC
    are produced by `make generate` directly into the chart trees, so they never drift from
    the API types or the component code.

ectobase is a multi-cluster substrate. A single **dispatch** cluster runs the control plane (an
aggregated apiserver, the dispatch controller, the netplane compiler, and the reflector); each
**compute/pool** cluster runs the dataplane, the netplane agent, and a broker that syncs
compiled objects down from the dispatch. Those two roles map onto the two charts:

| Chart | Runs on | Installs |
|---|---|---|
| `charts/ectobase-dispatch` | the dispatch cluster | aggregated apiserver + kine (+ postgres), dispatch-controller, netplane compiler, reflector, dispatch-side broker identity |
| `charts/ectobase-pool` | each compute cluster | dataplane (`ebpf`/`dpdk`), netplane agent, broker, cni, KubeVirt NAD, pod-materializer (always), vm-materializer / tier1 (gated), the `net` + `compiled` CRDs |

The reference install sequence lives in `test/lab/internal/deploy/ectobase.go` — the lab CLI
installs both charts exactly the way an operator would, so it is the source of truth for the
namespaces, the broker secret, and the two `helm install`s below.

## 1. Dispatch cluster

The dispatch chart carries two namespaces on purpose:

- The **release namespace** (`namespace`, default `system`) holds the baseline-PSA-safe pods:
  the aggregated apiserver, dispatch-controller, kine, and the dispatch-side broker identity. Create it
  with `--create-namespace`.
- The chart itself creates the **PSA-privileged `ectobase-system`** namespace
  (`agentNamespace`) for the hostNetwork netplane compiler and reflector.

```sh
helm install ectobase-dispatch charts/ectobase-dispatch \
  --namespace system --create-namespace \
  --set reflectorAdmin='[fd00:cafe:1::1]:1338'
```

`reflectorAdmin` is the address the dispatch-controller hands to the agents (the `-reflector-admin`
flag); it is the dispatch's fabric identity where the reflector listens. Point it at the dispatch's
reachable address on your underlay.

Wait for the aggregated API to serve before proceeding — the apiserver pod must start and its
`APIService` become `Available`:

```sh
kubectl get clusterpools.platform.ectobase.dev
```

### Dispatch values

Source of truth: `charts/ectobase-dispatch/values.yaml` (schema: `values.schema.json`).

| Value | Default | Meaning |
|---|---|---|
| `namespace` | `system` | Release namespace for the baseline-safe apiserver/controller/kine + broker identity. |
| `agentNamespace` | `ectobase-system` | PSA-privileged namespace the chart creates for the hostNetwork compiler + reflector. |
| `reflectorAdmin` | `[fd00:db8:0:1::1]:1338` | Address passed to the dispatch-controller as `-reflector-admin` (where the reflector listens). |
| `imagePullPolicy` | `IfNotPresent` | Applied to every container. |
| `images.dispatchApiserver` | `…/dispatch-apiserver:dev` | Aggregated apiserver image. |
| `images.dispatchController` | `…/dispatch-controller:dev` | Dispatch controller (ClusterPool reconciler + scheduler). |
| `images.netplane` | `…/netplane:dev` | Shared image for the netplane compiler + reflector. |
| `images.kine` | `rancher/kine:v0.13.0` | etcd-v3 shim over postgres. |
| `images.postgres` | `postgres:16` | Backing store for kine (dev/smoke; not HA). |

## 2. Each compute/pool cluster

The pool chart does **not** manage its own release namespace, and its broker needs the
dispatch-broker kubeconfig at startup. So two fixtures must exist before `helm install`:

1. A **PSA-privileged `ectobase-system`** namespace (the dataplane pods are
   privileged/hostPID/hostPath, the agent/broker are hostNetwork — Talos enforces baseline PSA
   cluster-wide and would reject them; kind does not enforce PSA, so this only bites on Talos).
2. A **`broker-dispatch-kubeconfig` Secret** (key `kubeconfig`) holding the broker's credential to
   the dispatch — a token kubeconfig pointing at the dispatch's apiserver on the fabric.

```sh
# 1. privileged namespace
kubectl create namespace ectobase-system
kubectl label namespace ectobase-system pod-security.kubernetes.io/enforce=privileged

# 2. broker → dispatch credential (a token minted for the dispatch-side dispatch-broker ServiceAccount)
kubectl create secret generic broker-dispatch-kubeconfig \
  -n ectobase-system --from-file=kubeconfig=./broker-dispatch.kubeconfig

# 3. the chart
helm install ectobase-pool charts/ectobase-pool \
  --namespace ectobase-system \
  --set broker.clusterName=k02 \
  --set apiserverAddress='https://[fd00:cafe:2::1]:6443' \
  --set reflectorAddress='[fd00:cafe:1::1]:1338' \
  --set dataplane=ebpf \
  --set installCRDs=true \
  --set underlayWithin='fd00:cafe::/32'
```

`broker.clusterName` is the pool's name (must match a `ClusterPool` on the dispatch) and is
**required**. `apiserverAddress` is *this* cluster's local apiserver (the agent reads/writes
its own cluster); `reflectorAddress` is the dispatch's reflector on the fabric. The NAD CRD
(`NetworkAttachmentDefinition`) must exist first — the chart renders a NAD unconditionally.

To install the DPDK dataplane instead of eBPF, set `--set dataplane=dpdk` (and, on real
hardware, `--set env=hw` plus the `dpdk.*` hugepage/vfio knobs).

### Pool values

Source of truth: `charts/ectobase-pool/values.yaml` (schema: `values.schema.json`).

| Value | Default | Meaning |
|---|---|---|
| `namespace` | `ectobase-system` | Namespace all pool resources deploy into. |
| `dataplane` | `ebpf` | Datapath backend for the whole cluster: `ebpf` or `dpdk` (no mixed clusters). |
| `env` | `clab` | Deployment environment: `clab` or `hw` (drives the DPDK hugepage/vfio knobs). |
| `uplink` | `eth1` | Overlay uplink interface (used by the DPDK datapath). |
| `underlayWithin` | `""` | Node-underlay aggregate CIDR. When set, flowplane picks the host address inside it as the underlay (the authoritative filter past mgmt/hostDNS addresses). Empty = infer from the fabric loopback. |
| `reflectorAddress` | `[fd00:db8:0:1::1]:1338` | Dispatch reflector address the agent dials. |
| `apiserverAddress` | `https://[fd00:db8:0:1::1]:6443` | This cluster's local apiserver (the agent's kubeconfig server URL). |
| `installCRDs` | `true` | Install the `net`/`compiled` CRDs with the chart (managed on `helm upgrade`). |
| `broker.clusterName` | `""` | **Required.** This cluster's pool name (e.g. `k02`). |
| `broker.dispatchKubeconfigSecret` | `broker-dispatch-kubeconfig` | Secret (key `kubeconfig`) with the broker's dispatch token. |
| `vmMaterializer.enabled` | `false` | Deploy the vm-materializer (CompiledVM → KubeVirt VM). Pools with KubeVirt only. |
| `tier1Failover.enabled` | `false` | Render the Tier-1 local-failover objects (medik8s NHC + SNR). Opt-in per pool. |
| `blueGreen.enabled` | `false` | Blue-green upgrade operator (requires `dataplane: dpdk`). |
| `images.flowplane` | `…/flowplane:dev` | eBPF dataplane image. |
| `images.flowplaneDpdk` | `…/flowplane-dpdk:dev` | DPDK dataplane image. |
| `images.netplane` | `…/netplane:dev` | netplane agent image. |
| `images.cni` | `…/cni:dev` | flowplane CNI plugin image. |
| `images.dispatchBroker` | `…/dispatch-broker:dev` | Per-pool broker image. |

The DPDK-only knobs live under `dpdk.*` (`lcores`, `hugepages`, `hugepageSize`,
`hugepageLimit`, `vfioDevices`) and only take effect when `dataplane: dpdk`. The Tier-1
knobs live under `tier1Failover.*` (`snrNamespace`, `nodeSelector`, `unhealthyThreshold`,
`minHealthy`, `remediationStrategy`, `watchdog.*`). See the
[Helm values reference](../reference/helm-values.md) for the complete list.

## Trying it end to end

The [local fabric](./local-fabric.md) runs this exact two-chart install for you across a
dispatch + compute-pool kind fabric — `make lab-up` renders the charts, brings up the clusters,
mints the broker secret, and installs both charts. Read
`test/lab/internal/deploy/ectobase.go` to see the reference sequence (namespaces, secret,
the two `helm install`s) that this page mirrors.

## Releasing the charts

!!! note "Status: Planned"
    The charts are consumed today from the repo tree (`charts/ectobase-dispatch`,
    `charts/ectobase-pool`). Publishing them as versioned **OCI chart releases** is planned;
    until then, install from a checkout of the repository at the desired revision.
