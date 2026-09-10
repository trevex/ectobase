# Deploying with Helm

!!! success "Status: Implemented"
    ectobase deploys as two Helm charts, one for the fleet/dispatch cluster and one per
    compute/pool cluster. The charts are the generated deploy artifact: their CRDs and RBAC
    are produced by `make generate` directly into the chart trees, so they never drift from
    the API types or the component code.

ectobase is a multi-cluster substrate. A single dispatch cluster runs the control plane (an
aggregated apiserver, the dispatch controller, the mesh compiler, and the reflector); each
compute/pool cluster runs the dataplane, the mesh agent, and a broker that syncs
compiled objects down from the dispatch. Those two roles map onto the two charts:

| Chart | Runs on | Installs |
|---|---|---|
| `charts/ectobase-dispatch` | the dispatch cluster | aggregated apiserver + kine (+ postgres), dispatch-controller, mesh compiler, reflector, dispatch-side broker identity |
| `charts/ectobase-pool` | each compute cluster | dataplane (`ebpf`), mesh agent, broker, cni, KubeVirt NAD, pod-materializer (always), vm-materializer / tier1 (gated), the `net` + `compiled` CRDs |

The reference install sequence lives in `test/lab/internal/deploy/ectobase.go` — the lab CLI
installs both charts exactly the way an operator would, so it is the source of truth for the
namespaces and the two `helm install`s below.

## 1. Dispatch cluster

The dispatch chart carries two namespaces:

- The release namespace (`namespace`, default `system`) holds the baseline-PSA-safe pods:
  the aggregated apiserver, dispatch-controller, kine, and the dispatch-side broker identity. Create it
  with `--create-namespace`.
- The chart itself creates the PSA-privileged `ectobase-system` namespace
  (`agentNamespace`) for the hostNetwork mesh compiler and reflector.

```sh
helm install ectobase-dispatch charts/ectobase-dispatch \
  --namespace system --create-namespace \
  --set reflectorAdmin='[fd00:cafe:1::1]:1339'
```

`reflectorAdmin` is the RouteBusAdmin fence address the dispatch-controller dials (the
`-reflector-admin` flag): the reflector's admin port 1339, separate from the agent-facing session
port 1338 so a session-cert holder cannot reach the fence API. Point it at the dispatch's reachable
address on the underlay.

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
| `reflectorAdmin` | `[fd00:db8:0:1::1]:1339` | Fence address the dispatch-controller dials via `-reflector-admin`: the reflector's admin port 1339, separate from the agent session port 1338. |
| `pki.enabled` | `false` | Turn on cert-manager PKI: route-bus mTLS, the dispatch serving cert, and trusting `ectobase-ca` as a client CA for cert-authenticated brokers. MUST match the pool chart's `pki.enabled`. |
| `pki.clusterIssuer` / `pki.caSecretName` | `ectobase-ca` | The shared root `ClusterIssuer` / CA Secret name. |
| `dispatchApiserver.serviceIP` | `fd00:db8:0:1::1` | IPv6 fabric address the broker dials the aggregated apiserver at; set as an IP SAN on the serving cert. Must equal the host the pool chart's `dispatchServer` dials. |
| `imagePullPolicy` | `IfNotPresent` | Applied to every container. |
| `images.dispatchApiserver` | `…/dispatch-apiserver:dev` | Aggregated apiserver image. |
| `images.dispatchController` | `…/dispatch-controller:dev` | Dispatch controller (ClusterPool reconciler + scheduler). |
| `images.mesh` | `…/mesh:dev` | Shared image for the mesh compiler + reflector. |
| `images.kine` | `rancher/kine:v0.13.0` | etcd-v3 shim over postgres. |
| `images.postgres` | `postgres:16` | Backing store for kine (dev/smoke; not HA). |

## 2. Each compute/pool cluster

The pool chart does not manage its own release namespace, so one fixture must exist before
`helm install`:

1. A PSA-privileged `ectobase-system` namespace (the dataplane pods are
   privileged/hostPID/hostPath, the agent/broker are hostNetwork — Talos enforces baseline PSA
   cluster-wide and would reject them; the lab fabric runs on Talos today, so this always
   applies there; a bare `kind` cluster outside the lab does not enforce PSA by
   default).

```sh
# 1. privileged namespace
kubectl create namespace ectobase-system
kubectl label namespace ectobase-system pod-security.kubernetes.io/enforce=privileged

# 2. the chart
helm install ectobase-pool charts/ectobase-pool \
  --namespace ectobase-system \
  --set broker.clusterName=k02 \
  --set apiserverAddress='https://[fd00:cafe:2::1]:6443' \
  --set reflectorAddress='[fd00:cafe:1::1]:1338' \
  --set installCRDs=true \
  --set underlayWithin='fd00:cafe::/32' \
  --set pki.enabled=true \
  --set pki.underlayCIDRs='fd00:cafe:2::/48' \
  --set dispatchServer='https://[fd00:cafe:1::1]:6443'
```

`broker.clusterName` is the pool's name (must match a `ClusterPool` on the dispatch) and is
required. `apiserverAddress` is this cluster's local apiserver (the agent reads/writes
its own cluster); `reflectorAddress` is the dispatch's reflector on the fabric. The NAD CRD
(`NetworkAttachmentDefinition`) must exist first — the chart renders a NAD unconditionally.

### The broker's dispatch credential

The broker's credential to the dispatch is a cert-manager `Certificate`, not a token. With
`pki.enabled=true` on both charts, the pool chart renders `broker-dispatch-tls`: `CN=ectobase:cluster:<pool>`,
`O=ectobase:brokers`, issued by the pool's `ectobase-pool-ca` Issuer (the same intermediate the
agent's node leaves come from) and auto-renewed by cert-manager every 90d. There is no
`kubectl create token`, no hand-minted kubeconfig, and nothing to re-mint on expiry — client-go
reloads the cert+key files off disk as cert-manager rotates them.

On the dispatch side, the aggregated apiserver trusts the `ectobase-ca` root as a client CA
(`--client-ca-file`) and serves a cert-manager-issued serving cert instead of its self-signed
default, so the broker verifies the server instead of setting `insecure-skip-tls-verify`. That
serving cert needs the dispatch's fabric IPv6 as an IP SAN — set it via
`dispatchApiserver.serviceIP` on the dispatch chart, and it must equal the host in the pool
chart's `dispatchServer` URL (the address the broker actually dials):

```sh
# dispatch cluster
helm install ectobase-dispatch charts/ectobase-dispatch \
  --namespace system --create-namespace \
  --set reflectorAdmin='[fd00:cafe:1::1]:1339' \
  --set pki.enabled=true \
  --set dispatchApiserver.serviceIP='fd00:cafe:1::1'
```

The `CN=ectobase:cluster:<pool>` identity is also what activates the `ClusterRestriction`
admission plugin's per-pool write-scoping — see
[Multi-cluster control plane](../architecture/multi-cluster-control-plane.md#the-brokers-dispatch-credential).

`pki.enabled` defaults to `false` on both charts. With it off, the broker falls back to the
legacy path: a `broker-dispatch-kubeconfig` Secret (key `kubeconfig`) holding a token minted for
the dispatch-side `dispatch-broker` ServiceAccount, and `insecure-skip-tls-verify` on the
dispatch connection. That path still works — the aggregated apiserver's delegated
authentication unions token and cert auth — but it is a migration fallback, not the default:

```sh
kubectl create secret generic broker-dispatch-kubeconfig \
  -n ectobase-system --from-file=kubeconfig=./broker-dispatch.kubeconfig
```

### Pool values

Source of truth: `charts/ectobase-pool/values.yaml` (schema: `values.schema.json`).

| Value | Default | Meaning |
|---|---|---|
| `namespace` | `ectobase-system` | Namespace all pool resources deploy into. |
| `env` | `clab` | Deployment environment: `clab` or `hw`. |
| `uplink` | `eth1` | Overlay uplink interface. |
| `underlayWithin` | `""` | Node-underlay aggregate CIDR. When set, flowplane picks the host address inside it as the underlay (the authoritative filter past mgmt/hostDNS addresses). Empty = infer from the fabric loopback. |
| `reflectorAddress` | `[fd00:db8:0:1::1]:1338` | Dispatch reflector address the agent dials. |
| `apiserverAddress` | `https://[fd00:db8:0:1::1]:6443` | This cluster's local apiserver (the agent's kubeconfig server URL). |
| `installCRDs` | `true` | Install the `net`/`compiled` CRDs with the chart (managed on `helm upgrade`). |
| `broker.clusterName` | `""` | Required. This cluster's pool name (e.g. `k02`). |
| `broker.dispatchKubeconfigSecret` | `broker-dispatch-kubeconfig` | Legacy path only (`pki.enabled=false`): Secret (key `kubeconfig`) with the broker's dispatch token. |
| `pki.enabled` | `false` | Mint the broker's dispatch credential as a cert-manager `Certificate` (`broker-dispatch-tls`) instead of using the token Secret; also turns on route-bus mTLS. MUST match the dispatch chart's `pki.enabled`. |
| `pki.intermediateSecret` | `ectobase-pool-ca` | Pool CA Secret the broker requests from dispatch and backs its local `Issuer` with (mints the broker leaf and the agent's node leaves). |
| `pki.underlayCIDRs` | `""` | Comma-separated pool underlay range(s); name-constrains the pool intermediate. |
| `dispatchServer` | `https://[fd00:db8:0:1::1]:6443` | mTLS mode only: the dispatch aggregated-apiserver URL the broker dials. Host must equal the dispatch chart's `dispatchApiserver.serviceIP`. |
| `vmMaterializer.enabled` | `false` | Deploy the vm-materializer (CompiledVM → KubeVirt VM). Pools with KubeVirt only. |
| `tier1Failover.enabled` | `false` | Render the Tier-1 local-failover objects (medik8s NHC + SNR). Opt-in per pool. |
| `images.flowplane` | `…/flowplane:dev` | eBPF dataplane image. |
| `images.mesh` | `…/mesh:dev` | mesh agent image. |
| `images.cni` | `…/cni:dev` | flowplane CNI plugin image. |
| `images.dispatchBroker` | `…/dispatch-broker:dev` | Per-pool broker image. |

The Tier-1 knobs live under `tier1Failover.*` (`snrNamespace`, `nodeSelector`, `unhealthyThreshold`,
`minHealthy`, `remediationStrategy`, `watchdog.*`). See the
[Helm values reference](../reference/helm-values.md) for the complete list.

## Trying it end to end

The [local fabric](../tutorials/local-fabric.md) runs this exact two-chart install across a
dispatch + compute-pool Talos fabric: `make lab-up` renders the charts, brings up the clusters,
and installs both charts, mTLS enabled by default (`ECTOBASE_ROUTEBUS_MTLS=false` opts back into
the token path). Read `test/lab/internal/deploy/ectobase.go` to see the reference sequence
(namespaces, the `pki.enabled` flags, the two `helm install`s) that this page mirrors — it also
carries the legacy token-minting path for comparison.

## Releasing the charts

!!! note "Status: Planned"
    The charts are consumed today from the repo tree (`charts/ectobase-dispatch`,
    `charts/ectobase-pool`). Publishing them as versioned OCI chart releases is planned;
    until then, install from a checkout of the repository at the desired revision.
