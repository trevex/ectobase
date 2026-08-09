# ectobase-hub

Helm chart for the ectobase fleet control-plane ("hub") cluster. Deploys:

- **hub-apiserver** — aggregated Kubernetes apiserver serving all ectobase API groups
  (`platform`, `net`, `compute`, `storage`, `compiled`) backed by kine+postgres.
- **hub-controller** — controller-runtime manager running the ClusterPool reconciler +
  VM scheduler/failover against the aggregated apiserver.
- **kine** — etcd-v3 shim over postgres, providing storage for the aggregated apiserver.
- **postgres** — ephemeral postgres instance (dev/smoke; not HA).
- **netplane-controller** (compiler) — compiles NIC/VM/Container objects into CompiledNIC/VM/Container.
- **reflector** — routebus gRPC rendezvous server for the per-pool netplane agents.

RBAC for `netplane-controller`, `hub-controller`, and the hub-side `hub-broker` identity
is generated from `files/<role>/role.yaml` (committed via `make generate`).

## Values

| Key | Default | Description |
|-----|---------|-------------|
| `namespace` | `system` | Namespace for hub infra (apiserver, controller, kine, broker identity) |
| `agentNamespace` | `ectobase-system` | Namespace for compiler and reflector |
| `reflectorAdmin` | `[fd00:db8:0:1::1]:1338` | Address hub-controller passes to agents via `-reflector-admin` |
| `imagePullPolicy` | `IfNotPresent` | Image pull policy for all containers |
| `images.hubApiserver` | `ghcr.io/trevex/ectobase/hub-apiserver:dev` | Hub aggregated apiserver image |
| `images.hubController` | `ghcr.io/trevex/ectobase/hub-controller:dev` | Hub controller image |
| `images.netplane` | `ghcr.io/trevex/ectobase/netplane:dev` | Compiler + reflector image |
| `images.kine` | `rancher/kine:v0.13.0` | Kine image |
| `images.postgres` | `postgres:16` | Postgres image |
