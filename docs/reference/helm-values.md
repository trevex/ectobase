# Helm chart values

ectobase ships two Helm charts: **`ectobase-hub`** for the fleet control plane
and **`ectobase-pool`** for a workload cluster and its per-node dataplane. This
page documents the important knobs of each, grouped by concern. It is not an
exhaustive key dump — see each chart's `values.yaml` for every field.

---

## ectobase-hub

The hub chart deploys the aggregated apiserver, the hub controller, the compiler,
the reflector, and the broker's hub-side identity.

### Images and pull policy

| Value | Default | Meaning |
| --- | --- | --- |
| `images.hubApiserver` | `ghcr.io/trevex/ectobase/hub-apiserver:dev` | Aggregated apiserver image. |
| `images.hubController` | `ghcr.io/trevex/ectobase/hub-controller:dev` | Hub controller (ClusterPool reconciler + scheduler). |
| `images.netplane` | `ghcr.io/trevex/ectobase/netplane:dev` | Shared image for the compiler (netplane-controller) and reflector. |
| `images.kine` | `rancher/kine:v0.13.0` | etcd-v3 shim in front of PostgreSQL. |
| `images.postgres` | `postgres:16` | Backing store for kine (dev/smoke; not HA). |
| `imagePullPolicy` | `IfNotPresent` | Applies to all containers in the chart. |

### Namespaces

| Value | Default | Meaning |
| --- | --- | --- |
| `namespace` | `system` | Namespace for the hub infrastructure (apiserver, controller, kine, postgres, broker identity). Baseline-PSA-safe. |
| `agentNamespace` | `ectobase-system` | Namespace for the compiler and reflector; created PSA-privileged because they run hostNetwork. |

### Control-plane addresses

| Value | Default | Meaning |
| --- | --- | --- |
| `reflectorAdmin` | `[fd00:db8:0:1::1]:1338` | Address the hub-controller passes to agents (`-reflector-admin`); the fabric loopback of the control-plane node. |

---

## ectobase-pool

The pool chart deploys the node dataplane (eBPF or DPDK), the netplane agent, the
CNI, the broker runtime, and optional materializers and failover.

### Images and pull policy

| Value | Default | Meaning |
| --- | --- | --- |
| `images.flowplane` | `ghcr.io/trevex/ectobase/flowplane:dev` | eBPF dataplane image. |
| `images.flowplaneDpdk` | `ghcr.io/trevex/ectobase/flowplane-dpdk:dev` | DPDK dataplane image. |
| `images.netplane` | `ghcr.io/trevex/ectobase/netplane:dev` | Agent, pod-materializer and vm-materializer image. |
| `images.cni` | `ghcr.io/trevex/ectobase/cni:dev` | flowplane-cni image. |
| `images.hubBroker` | `ghcr.io/trevex/ectobase/hub-broker:dev` | Broker runtime image. |
| `imagePullPolicy` | `IfNotPresent` | Applies to all containers in the chart. |

### Namespace

| Value | Default | Meaning |
| --- | --- | --- |
| `namespace` | `ectobase-system` | Namespace for all pool resources. |

### Control-plane addresses

The agent dials the fabric control plane over the underlay.

| Value | Default | Meaning |
| --- | --- | --- |
| `reflectorAddress` | `[fd00:db8:0:1::1]:1338` | Fabric reflector address the agent dials. |
| `apiserverAddress` | `https://[fd00:db8:0:1::1]:6443` | Control-plane apiserver the agent dials over the fabric (kubeconfig server URL). |

### Dataplane

Selects and configures the node datapath. The choice is whole-cluster; mixed
clusters are not supported.

| Value | Default | Meaning |
| --- | --- | --- |
| `dataplane` | `ebpf` | Datapath backend: `ebpf` or `dpdk`. |
| `env` | `clab` | Deployment environment (`clab` or `hw`); drives datapath-specific knobs (hugepages, vfio, lcores). |
| `uplink` | `eth1` | Overlay uplink interface (used by the DPDK datapath; the eBPF wrapper defaults to `eth1`). |
| `underlayWithin` | `""` | Expected node-underlay aggregate (CIDR). When set, flowplane picks the host address inside it as the underlay. Empty = infer from the fabric loopback. |
| `dpdk.lcores` | `"0"` | EAL `-l` value. clab must be a single lcore (shared host). |
| `dpdk.hugepages` | `false` | clab: `false` (`--no-huge`); hw: `true`. |
| `dpdk.hugepageSize` | `1Gi` | Hugepage size request. |
| `dpdk.hugepageLimit` | `2Gi` | Hugepage limit. |
| `dpdk.vfioDevices` | `[]` | hw: `[{name: <resource>, count: <n>}]` device-plugin requests. |

### Broker

The per-cluster broker is always deployed; `clusterName` is required.

| Value | Default | Meaning |
| --- | --- | --- |
| `broker.clusterName` | `""` | This cluster's pool name (e.g. `k02`). Required. |
| `broker.hubKubeconfigSecret` | `broker-hub-kubeconfig` | Secret (key `kubeconfig`) holding a hub token. |

### CRDs

| Value | Default | Meaning |
| --- | --- | --- |
| `installCRDs` | `true` | Install the pool-shipped CRDs (net + compiled) with the chart; managed on `helm upgrade`. |

### VM materializer

| Value | Default | Meaning |
| --- | --- | --- |
| `vmMaterializer.enabled` | `false` | Turn broker-synced CompiledVM/CompiledVolumeAttachment into KubeVirt VMs. Enable on pools with KubeVirt installed. |

### Blue-green (Planned)

!!! note "Planned"
    The blue-green operator has not landed yet; this toggle renders nothing today
    and requires `dataplane: dpdk`.

| Value | Default | Meaning |
| --- | --- | --- |
| `blueGreen.enabled` | `false` | Enable the blue-green dataplane-upgrade operator. |

### Tier-1 failover

Opt-in autonomous local failover (medik8s NodeHealthCheck + Self-Node
Remediation). Renders nothing when disabled.

| Value | Default | Meaning |
| --- | --- | --- |
| `tier1Failover.enabled` | `false` | Opt-in per pool; renders NodeHealthCheck + SelfNodeRemediationTemplate when true. |
| `tier1Failover.snrNamespace` | `self-node-remediation` | Namespace where the SNR operator (and our Template/Config) live. |
| `tier1Failover.nodeSelector` | control-plane excluded | LabelSelector of nodes the NHC watches. |
| `tier1Failover.unhealthyThreshold` | `60s` | Node `Ready=Unknown/False` duration before remediation. |
| `tier1Failover.minHealthy` | `51%` | NHC guard: never remediate below this healthy quorum. |
| `tier1Failover.remediationStrategy` | `OutOfServiceTaint` | SNR strategy: `Automatic`, `ResourceDeletion`, or `OutOfServiceTaint`. |
| `tier1Failover.watchdog.enabled` | `false` | dev/kind: software reboot; prod `true`: hardware watchdog. |
| `tier1Failover.watchdog.device` | `/dev/watchdog` | `watchdogFilePath` on SelfNodeRemediationConfig (when enabled). |
