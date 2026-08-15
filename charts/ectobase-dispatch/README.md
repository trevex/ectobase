# ectobase-dispatch

Helm chart for the ectobase fleet control-plane ("dispatch") cluster. Deploys:

- **dispatch-apiserver** — aggregated Kubernetes apiserver serving all ectobase API groups
  (`platform`, `net`, `compute`, `storage`, `compiled`) backed by kine+postgres.
- **dispatch-controller** — controller-runtime manager running the ClusterPool reconciler +
  VM scheduler/failover against the aggregated apiserver.
- **kine** — etcd-v3 shim over postgres, providing storage for the aggregated apiserver.
- **postgres** — ephemeral postgres instance (dev/smoke; not HA).
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
