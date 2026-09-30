# ectobase-dispatch

Helm chart for the ectobase fleet control-plane ("dispatch") cluster. Deploys:

- **dispatch-apiserver** — aggregated Kubernetes apiserver serving all ectobase API groups
  (`platform`, `net`, `compute`, `storage`, `compiled`) backed by kine+postgres.
- **dispatch-controller** — controller-runtime manager running the ClusterPool reconciler +
  VM scheduler/failover against the aggregated apiserver.
- **kine** — etcd-v3 shim over postgres, providing storage for the aggregated apiserver.
- **postgres** — single postgres instance backing kine; its data persists on a PVC by default (not HA).
- **mesh-controller** (compiler) — compiles NIC/VM/Container objects into CompiledNIC/VM/Container.
- **reflector** — routebus gRPC rendezvous server for the per-pool mesh agents.

RBAC for `mesh-controller`, `dispatch-controller`, and the dispatch-side `dispatch-broker` identity
is generated from `files/<role>/role.yaml` (committed via `make generate`).

## Values

| Key | Default | Description |
|-----|---------|-------------|
| `namespace` | `system` | Namespace for dispatch infra (apiserver, controller, kine, broker identity) |
| `agentNamespace` | `ectobase-system` | Namespace for compiler and reflector |
| `reflectorAdmin` | `[fd00:db8:0:1::1]:1339` | Reflector RouteBusAdmin (fence) address the dispatch-controller dials via `-reflector-admin` |
| `imagePullPolicy` | `IfNotPresent` | Image pull policy for all containers |
| `images.dispatchApiserver` | `ghcr.io/trevex/ectobase/dispatch-apiserver:dev` | Dispatch aggregated apiserver image |
| `images.dispatchController` | `ghcr.io/trevex/ectobase/dispatch-controller:dev` | Dispatch controller image |
| `images.mesh` | `ghcr.io/trevex/ectobase/mesh:dev` | Compiler + reflector image |
| `images.kine` | `rancher/kine:v0.13.0` | Kine image |
| `images.postgres` | `postgres:16` | Postgres image |
| `postgres.persistence.type` | `pvc` | Where postgres keeps ALL dispatch state: `pvc`, `hostPath`, or `emptyDir` (lost on every postgres pod restart) |
| `postgres.persistence.storageClass` | `""` | StorageClass for `pvc`; empty uses the cluster default |
| `postgres.persistence.size` | `1Gi` | Size of the `pvc` |
| `postgres.persistence.path` | `/var/lib/ectobase/postgres` | Node directory for `hostPath` (single-node clusters only) |

## Upgrading from a chart version before Recreate

The `postgres` and `reflector` Deployments now roll out with `Recreate`. A Deployment first
created under the default `RollingUpdate` carries an apiserver-defaulted
`spec.strategy.rollingUpdate` that Helm 4's server-side apply does not own and so never removes,
and the API rejects `Recreate` next to it. Upgrading such a release fails with:

```text
Error: UPGRADE FAILED: server-side apply failed for object system/postgres apps/v1, Kind=Deployment: Deployment.apps "postgres" is invalid: spec.strategy.rollingUpdate: Forbidden: may not be specified when strategy `type` is 'Recreate'
```

Before that first upgrade, switch both Deployments once (the namespaces are the defaults of
`namespace` and `agentNamespace`; use yours if you override them):

```sh
kubectl -n system patch deploy postgres --type=merge \
  -p '{"spec":{"strategy":{"type":"Recreate","rollingUpdate":null}}}'
kubectl -n ectobase-system patch deploy reflector --type=merge \
  -p '{"spec":{"strategy":{"type":"Recreate","rollingUpdate":null}}}'
```

This is a one-time step. The strategy is not part of the pod template, so the patch starts no
rollout, and it sets the value the chart applies, so it never conflicts with Helm afterwards. The
lab runs it on every deploy (`migrateRecreateDeployments` in `test/lab/internal/deploy/ectobase.go`).
