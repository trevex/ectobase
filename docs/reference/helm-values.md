# Helm values

This page lists every value in the two charts, `ectobase-dispatch` and `ectobase-pool`, with its
default and what it controls. It matches each chart's `values.yaml`; the comments there are the
primary source. For how the values fit into an install, see
[Deploy with Helm](../operations/deploy-helm.md).

Both charts are version `0.1.0`. The pool chart's `values.schema.json` rejects keys it does not
know (`additionalProperties: false`); the dispatch chart's schema accepts unknown keys.

## ectobase-dispatch

The dispatch chart deploys `dispatch-apiserver` with kine and postgres, `dispatch-controller`,
`mesh-controller`, the `reflector`, and the `ectobase-ca` root CA with its `ClusterIssuer`.

### Namespaces

| Value | Default | Meaning |
| --- | --- | --- |
| `namespace` | `system` | Namespace for `dispatch-apiserver`, `dispatch-controller`, kine, postgres and the root CA. The installer creates it; with `pki.enabled` it must be PSA-privileged, because the apiserver runs `hostNetwork`. Required by the schema. |
| `agentNamespace` | `ectobase-system` | Namespace for `mesh-controller` and the reflector. The chart creates it, labelled PSA-privileged, because both run `hostNetwork`. Required by the schema. |

### Addresses and PKI

The route bus, the connection from each pool's broker (`dispatch-broker`) to the dispatch, and
the fence API all run over mTLS from one root. cert-manager is required in the cluster.

| Value | Default | Meaning |
| --- | --- | --- |
| `reflectorAdmin` | `[fd00:db8:0:1::1]:1339` | The reflector's admin (fence) address that `dispatch-controller` dials. Port 1339, separate from the agents' session port 1338. Required by the schema. |
| `pki.enabled` | `true` | Turns on mTLS for the route bus, limits the fence API to the `dispatch-controller` certificate, and runs `dispatch-apiserver` on `hostNetwork` port 6444 with a cert-manager serving certificate. Must be `true` on both charts: without it the pool's broker has no dispatch credential. |
| `pki.clusterIssuer` | `ectobase-ca` | Name of the CA `ClusterIssuer` both charts issue from. Must match the pool chart. |
| `pki.caSecretName` | `ectobase-ca` | Secret holding the root CA key pair. cert-manager must run with `--cluster-resource-namespace` set to `namespace` so the `ClusterIssuer` can read it. |
| `pki.reflectorIP` | `fd00:db8:0:1::1` | The address agents dial, added as an IP SAN on the reflector's server certificate. Must match the host in `reflectorAdmin` and in the pools' `reflectorAddress`. |
| `pki.clientCASecretName` | `ectobase-dispatch-client-ca` | Secret of the dispatch client CA, a separate self-signed root the chart creates. It is the only CA `dispatch-apiserver` accepts client certificates from (it mounts only the certificate), and the dispatch-controller signs each broker's client certificate from it. Not the route-bus root: every pool intermediate chains to that one. |
| `pki.fleetIdentities` | `[]` | `RouteBusIdentity` names that are not pools, such as the WAN edge fleet's `edge`, passed to the signer as `--routebus-fleet-identities`. The signer constrains a fleet identity's intermediate to its own `spec.permittedUnderlayCIDRs`, so list only identities the operator creates and no broker can write. Every other identity must be a `ClusterPool` with `spec.underlayPrefix`. Empty trusts none. A name that is also a `ClusterPool` is denied. |
| `dispatchApiserver.serviceIP` | `fd00:db8:0:1::1` | The address brokers dial `dispatch-apiserver` at, added as an IP SAN on its serving certificate. Must equal the host in each pool's `dispatchServer`. |
| `dispatchApiserver.grantClusterAdmin` | `false` | Binds the apiserver's ServiceAccount to `cluster-admin`. Off by default: the auth-delegator binding, the extension-apiserver-authentication reader and a scoped informer role are what it needs. |

### Storage fencing

| Value | Default | Meaning |
| --- | --- | --- |
| `ceph.clusterID` | `""` | The external Ceph cluster's fsid, passed to `dispatch-controller` as `-csi-cluster-id` and written into each `NetworkFence`. Empty leaves the storage fence unable to act, since the ceph-csi driver rejects a fence without it. The lab sets it from `lab tier2 up` and carries it through every redeploy. |

### Postgres and kine

Postgres holds all dispatch state behind kine. It runs as one pod with the `Recreate` strategy.

| Value | Default | Meaning |
| --- | --- | --- |
| `postgres.persistence.type` | `pvc` | `pvc`: a ReadWriteOnce claim `postgres-data` that `helm uninstall` keeps. `hostPath`: a node directory, safe only on a single-node cluster. `emptyDir`: lost on every postgres restart or pod-template change. Any other value fails the render. |
| `postgres.persistence.storageClass` | `""` | StorageClass for `pvc`; empty uses the cluster default. |
| `postgres.persistence.size` | `1Gi` | Size of the `pvc`. |
| `postgres.persistence.path` | `/var/lib/ectobase/postgres` | Node directory for `hostPath`, created if missing. |
| `kine.password` | `kine` | Password for postgres and kine's DSN, delivered through the `kine-db` Secret. Postgres reads it only when it initialises an empty data directory, so changing it later on persistent storage locks kine out. |

### Images

| Value | Default | Meaning |
| --- | --- | --- |
| `images.dispatchApiserver` | `ghcr.io/trevex/ectobase/dispatch-apiserver:dev` | The aggregated apiserver. |
| `images.dispatchController` | `ghcr.io/trevex/ectobase/dispatch-controller:dev` | `dispatch-controller`. |
| `images.mesh` | `ghcr.io/trevex/ectobase/mesh:dev` | Shared by `mesh-controller` and the reflector. |
| `images.kine` | `rancher/kine:v0.13.0` | The etcd-v3 shim. |
| `images.postgres` | `postgres:16` | kine's backing store. Single instance, not HA. |
| `imagePullPolicy` | `IfNotPresent` | Applies to every container. One of `Always`, `IfNotPresent`, `Never`. Use `Always` with mutable tags such as `:dev`. |

## ectobase-pool

The pool chart deploys `flowplane`, `mesh-agent`, `dispatch-broker`, the `flowplane-cni`
installer, `pod-materializer`, the overlay NADs and the CRDs, plus `vm-materializer` and the
Tier-1 failover objects when enabled.

### Namespace and environment

| Value | Default | Meaning |
| --- | --- | --- |
| `namespace` | `ectobase-system` | Namespace for every pool resource. Install the release into the same namespace and create it PSA-privileged first. Keep the default: the compiler on the dispatch references the overlay NADs as `ectobase-system/flowplane-overlay` and `ectobase-system/flowplane`. |
| `env` | `clab` | `clab` or `hw`. On `clab`, `flowplane` gets `FLOWPLANE_SKB_MODE=1`, which gates jumbo guest MTUs, not an XDP attach mode. Containerlab veths advertise no XDP features, so without it the scatter-gather probe comes back unknown and clamps guests to the standard MTU, defeating the fabric's 9000-byte underlay. Hardware that advertises scatter-gather needs no pin. |

### Dataplane

| Value | Default | Meaning |
| --- | --- | --- |
| `uplink` | `eth1` | Declared as the overlay uplink, but no template reads it today: the `flowplane` wrapper uses `$XDP_UPLINK` with a fallback of `eth1`, and nothing sets `XDP_UPLINK`. Required by the schema. |
| `underlayWithin` | `""` | The node-underlay aggregate (a CIDR). When set, `flowplane` picks the host address inside it as the underlay, past management and host-DNS addresses. Empty means infer it from the `dummy*` or `lo` fabric loopback. The lab sets `fd00:cafe::/32`. |

The `flowplane` wrapper also passes every other interface named `eth1` or higher whose state is
up as `--extra-uplink`, so returns arriving over a second top-of-rack switch are decapped too.

### Control-plane addresses

| Value | Default | Meaning |
| --- | --- | --- |
| `reflectorAddress` | `[fd00:db8:0:1::1]:1338` | The reflector's session address that the agent dials. |
| `apiserverAddress` | `https://[fd00:db8:0:1::1]:6443` | This pool's own apiserver, written into the agent's kubeconfig. The agent reads its `CompiledNIC`s here. It never talks to the dispatch apiserver; its only link to the dispatch cluster is its route-bus session to the reflector. Because the agent runs `hostNetwork` on every node, `127.0.0.1` works only where every node runs an apiserver. That kubeconfig skips TLS verification and authenticates with the ServiceAccount token. The lab sets `https://127.0.0.1:6443`. |
| `dispatchServer` | `https://[fd00:db8:0:1::1]:6444` | The `dispatch-apiserver` URL the broker dials directly, on 6444 rather than the host apiserver's 6443. The host must equal the dispatch chart's `dispatchApiserver.serviceIP`. |

### Broker and PKI

| Value | Default | Meaning |
| --- | --- | --- |
| `broker.clusterName` | `""` | This pool's name, matching its `ClusterPool` on the dispatch. Required: the chart refuses to render without it. |
| `pki.enabled` | `true` | Turns on mTLS to the reflector and the broker's dispatch credential: `broker-dispatch-tls`, which the broker writes itself from the client certificate the dispatch signer issues (`CN=ectobase:cluster:<pool>`, `O=ectobase:brokers`, 90 days, from the dispatch client CA). Must match the dispatch chart; requires cert-manager in the pool. |
| `pki.intermediateSecret` | `ectobase-pool-ca` | The Secret the broker writes the pool's intermediate CA into (`tls.crt`, `tls.key`, `ca.crt` = root). It backs the pool's `ectobase-pool-ca` `Issuer`, which issues each agent's node certificate, and the agent trusts its `ca.crt`. |
| `pki.underlayCIDRs` | `""` | Advisory. Comma-separated underlay ranges of this pool, sent with the broker's intermediate CSR. The dispatch signer ignores them: it constrains the pool intermediate to the `ClusterPool`'s `spec.underlayPrefix`, and denies a pool that has none. A range outside that prefix is only named in the `Signed` condition. |

### CRDs and optional components

| Value | Default | Meaning |
| --- | --- | --- |
| `installCRDs` | `true` | Install the `net` and `compiled` CRDs from `crd-bases/` as ordinary chart resources. Helm updates them on upgrade and deletes any it no longer renders. Never upgrade a live pool to `installCRDs=false`, and never `helm uninstall` it: removing the compiled CRDs deletes every twin, and garbage collection then deletes the VMs, Pods and DataVolumes the materializers own. |
| `vmMaterializer.enabled` | `false` | Deploy `vm-materializer`, which turns `CompiledVM`s into KubeVirt VMs and `CompiledVolumeAttachment`s into CDI `DataVolume`s. Enable only on pools with KubeVirt and CDI. |

### Tier-1 failover

Opt-in node-level remediation inside one pool, using medik8s NodeHealthCheck and Self Node
Remediation. The chart renders their custom resources only; install the operators separately.
With `enabled: false` nothing is rendered.

| Value | Default | Meaning |
| --- | --- | --- |
| `tier1Failover.enabled` | `false` | Render a `NodeHealthCheck` and a `SelfNodeRemediationTemplate`, both named `ectobase-tier1`. |
| `tier1Failover.snrNamespace` | `self-node-remediation` | Namespace of the Self Node Remediation operator, where the template and config go. |
| `tier1Failover.nodeSelector` | nodes without `node-role.kubernetes.io/control-plane` | Label selector of the nodes the health check watches. |
| `tier1Failover.unhealthyThreshold` | `60s` | How long a node's `Ready` condition must be `False` or `Unknown` before remediation. |
| `tier1Failover.minHealthy` | `51%` | Never remediate when fewer nodes than this are healthy. |
| `tier1Failover.remediationStrategy` | `OutOfServiceTaint` | One of `Automatic`, `ResourceDeletion`, `OutOfServiceTaint`. |
| `tier1Failover.watchdog.enabled` | `false` | Render a `SelfNodeRemediationConfig` that uses a hardware watchdog. Off means a software reboot, which suits development. |
| `tier1Failover.watchdog.device` | `/dev/watchdog` | `watchdogFilePath` for that config. Must be set when the watchdog is enabled, or the render fails. |

### Images

| Value | Default | Meaning |
| --- | --- | --- |
| `images.flowplane` | `ghcr.io/trevex/ectobase/flowplane:dev` | The eBPF dataplane. |
| `images.mesh` | `ghcr.io/trevex/ectobase/mesh:dev` | `mesh-agent`, `pod-materializer` and `vm-materializer`. |
| `images.cni` | `ghcr.io/trevex/ectobase/cni:dev` | The `flowplane-cni` binary and installer. |
| `images.dispatchBroker` | `ghcr.io/trevex/ectobase/dispatch-broker:dev` | The broker. |
| `imagePullPolicy` | `IfNotPresent` | Applies to every container. One of `Always`, `IfNotPresent`, `Never`. |

## Where to go next

- [Deploy with Helm](../operations/deploy-helm.md): the install sequence these values feed.
- [Components](components.md): what each deployed component does.
- [Runbook](../operations/runbook.md): what goes wrong when values disagree.
