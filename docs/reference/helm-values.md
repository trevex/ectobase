# Helm chart values

ectobase ships two Helm charts: `ectobase-dispatch` for the fleet control plane
and `ectobase-pool` for a workload cluster and its per-node dataplane. This
page documents the important knobs of each, grouped by concern. It is not an
exhaustive key dump — see each chart's `values.yaml` for every field.

---

## ectobase-dispatch

The dispatch chart deploys the aggregated apiserver, the dispatch controller, the compiler,
the reflector, and the `ectobase-ca` root CA + ClusterIssuer.

### Images and pull policy

| Value | Default | Meaning |
| --- | --- | --- |
| `images.dispatchApiserver` | `ghcr.io/trevex/ectobase/dispatch-apiserver:dev` | Aggregated apiserver image. |
| `images.dispatchController` | `ghcr.io/trevex/ectobase/dispatch-controller:dev` | Dispatch controller (ClusterPool reconciler + scheduler). |
| `images.mesh` | `ghcr.io/trevex/ectobase/mesh:dev` | Shared image for the compiler (mesh-controller) and reflector. |
| `images.kine` | `rancher/kine:v0.13.0` | etcd-v3 shim in front of PostgreSQL. |
| `images.postgres` | `postgres:16` | Backing store for kine (dev/smoke; not HA). |
| `imagePullPolicy` | `IfNotPresent` | Applies to all containers in the chart. |

### Namespaces

| Value | Default | Meaning |
| --- | --- | --- |
| `namespace` | `system` | Namespace for the dispatch infrastructure (apiserver, controller, kine, postgres, root CA). Must be PSA-privileged: with `pki.enabled` the apiserver is hostNetwork on `:6444`. |
| `agentNamespace` | `ectobase-system` | Namespace for the compiler and reflector; created PSA-privileged because they run hostNetwork. |

### Control-plane addresses

| Value | Default | Meaning |
| --- | --- | --- |
| `reflectorAdmin` | `[fd00:db8:0:1::1]:1339` | Reflector RouteBusAdmin (fence) address the dispatch-controller dials via `-reflector-admin`; the separate admin port, not the agent-facing session port `1338`. |

### PKI

Mandatory and default-on: mTLS is the sole broker→dispatch auth path, so cert-manager must be
installed in the cluster. `pki.enabled` MUST match the pool chart's.

| Value | Default | Meaning |
| --- | --- | --- |
| `pki.enabled` | `true` | Turns on route-bus mutual TLS and CN-gates the fence API to the dispatch-controller identity. Provisions the self-signed CA + ClusterIssuer both charts issue from. Also makes the aggregated apiserver hostNetwork on `:6444`. |
| `pki.clusterIssuer` | `ectobase-ca` | Name of the shared CA `ClusterIssuer`; MUST match the pool chart. |
| `pki.caSecretName` | `ectobase-ca` | Secret holding the CA keypair backing that ClusterIssuer. |
| `pki.reflectorIP` | `fd00:db8:0:1::1` | Fabric-loopback IP agents dial, added as a SAN on the reflector server cert. MUST match the host part of `reflectorAddress`/`reflectorAdmin`. |
| `dispatchApiserver.serviceIP` | `fd00:db8:0:1::1` | IPv6 fabric address the broker dials the aggregated apiserver at; must be an IP SAN on the serving cert, and must equal the host in the pool chart's `dispatchServer`. |

---

## ectobase-pool

The pool chart deploys the node dataplane (eBPF), the mesh agent, the
CNI, the broker runtime, and optional materializers and failover.

### Images and pull policy

| Value | Default | Meaning |
| --- | --- | --- |
| `images.flowplane` | `ghcr.io/trevex/ectobase/flowplane:dev` | eBPF dataplane image. |
| `images.mesh` | `ghcr.io/trevex/ectobase/mesh:dev` | Agent, pod-materializer and vm-materializer image. |
| `images.cni` | `ghcr.io/trevex/ectobase/cni:dev` | flowplane-cni image. |
| `images.dispatchBroker` | `ghcr.io/trevex/ectobase/dispatch-broker:dev` | Broker runtime image. |
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
| `dispatchServer` | `https://[fd00:db8:0:1::1]:6444` | The directly-exposed dispatch aggregated-apiserver URL the broker dials — `:6444`, not the host kube-apiserver's `:6443`. Host MUST match the serving cert's IP SAN (`dispatchApiserver.serviceIP`). |

### Dataplane

Configures the node's eBPF datapath: environment, uplink interface, and underlay detection.

| Value | Default | Meaning |
| --- | --- | --- |
| `env` | `clab` | Deployment environment: `clab` or `hw`. On `clab`, flowplane gets `FLOWPLANE_SKB_MODE=1` — the jumbo gate, not an XDP attach mode (the forwarding datapath is tcx). Containerlab veths advertise no `xdp-features`, so the scatter-gather probe comes back unknown and would conservatively clamp the guest to the 1500-derived MTU, defeating the fabric's 9000 underlay. Unnecessary on hardware that advertises SG. |
| `uplink` | `eth1` | Overlay uplink interface. |
| `underlayWithin` | `""` | Expected node-underlay aggregate (CIDR). When set, flowplane picks the host address inside it as the underlay. Empty = infer from the fabric loopback. |

### Broker

The per-cluster broker is always deployed; `clusterName` is required. Its dispatch credential is
a cert-manager client cert (`broker-dispatch-tls`, `CN=ectobase:cluster:<pool>`,
`O=ectobase:brokers`) rendered by the `pki` block below — there is no token Secret.

| Value | Default | Meaning |
| --- | --- | --- |
| `broker.clusterName` | `""` | This cluster's pool name (e.g. `k02`). Required. |

### PKI

Mandatory and default-on: cert-manager must be installed in the pool. `pki.enabled` MUST match
the dispatch chart's.

| Value | Default | Meaning |
| --- | --- | --- |
| `pki.enabled` | `true` | Turns on mutual TLS to the reflector and mints the broker's dispatch credential. The pool gets its own intermediate CA via a `RouteBusIdentity` CSR to dispatch, so there is no cross-cluster cert-manager dependency. |
| `pki.intermediateSecret` | `ectobase-pool-ca` | Pool CA Secret the broker requests from dispatch and writes locally (`tls.crt`=intermediate, `tls.key`=pool key, `ca.crt`=root). Backs the pool cert-manager `Issuer` that mints per-node agent leaves, and carries the root the agent trusts. |
| `pki.underlayCIDRs` | `""` | Comma-separated underlay range(s) for this pool (e.g. its `/48`). IP-name-constrains the intermediate so it can only mint node leaves whose IP SAN falls inside them. Empty = no IP constraint. |

### CRDs

| Value | Default | Meaning |
| --- | --- | --- |
| `installCRDs` | `true` | Install the pool-shipped CRDs (net + compiled) with the chart; managed on `helm upgrade`. |

### VM materializer

| Value | Default | Meaning |
| --- | --- | --- |
| `vmMaterializer.enabled` | `false` | Turn broker-synced CompiledVM/CompiledVolumeAttachment into KubeVirt VMs. Enable on pools with KubeVirt installed. |

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
| `tier1Failover.watchdog.enabled` | `false` | dev/lab: software reboot; prod `true`: hardware watchdog. |
| `tier1Failover.watchdog.device` | `/dev/watchdog` | `watchdogFilePath` on SelfNodeRemediationConfig (when enabled). |
