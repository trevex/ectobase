# The fleet: dispatch and pools

An ectobase fleet is one dispatch cluster and any number of pool clusters, joined by an
IPv6 fabric. This page explains what runs on each, how the code splits into flowplane,
mesh and dispatch, and why the dispatch serves its API without CRDs while every pool uses
ordinary CRDs.

```mermaid
flowchart TB
    subgraph dispatch["Dispatch cluster: the fleet control plane"]
        api["dispatch-apiserver<br/>all five API groups"]
        store[("kine on postgres")]
        compiler["compiler<br/>(mesh-controller)"]
        dctl["dispatch-controller"]
        refl["reflector"]
        api --- store
        compiler <--> api
        dctl <--> api
    end

    subgraph pool["Pool cluster (one ClusterPool), repeated per pool"]
        broker["dispatch-broker"]
        crds[("compiled.ectobase.dev CRDs<br/>on the pool apiserver")]
        mat["pod-materializer<br/>vm-materializer"]
        cni["flowplane-cni"]
        agent["mesh-agent<br/>(per node)"]
        fp["flowplane<br/>(per node)"]
        broker -->|writes twins| crds
        crds --> mat
        crds --> agent
        crds --> cni
        cni -->|attach| fp
        agent -->|program| fp
    end

    subgraph edge["WAN edge (not a Kubernetes node)"]
        eagent["mesh-agent<br/>(edge mode)"]
        efp["flowplane<br/>(--role edge)"]
        eagent --> efp
    end

    broker <-->|"twins in pool-&lt;name&gt; down,<br/>status up (mTLS, :6444)"| api
    agent <-->|"route bus (mTLS, :1338)"| refl
    eagent <-->|route bus| refl
    dctl -->|"fence (:1339)"| refl
```

## The dispatch

The **dispatch** is the fleet control plane. It runs on one Kubernetes cluster and holds
the only copy of your intent. The `ectobase-dispatch` Helm chart installs it.

| Component | What it does |
|---|---|
| `dispatch-apiserver` | An aggregated apiserver that serves all five API groups: `net`, `compute`, `storage`, `compiled` and `platform` (all `*.ectobase.dev`). Brokers reach it directly on port 6444. |
| kine and postgres | Storage for the apiserver. kine presents an etcd v3 endpoint backed by postgres, whose data directory is persistent by default. |
| `mesh-controller` (the compiler) | Allocates VNIs, overlay IPs, MACs and public addresses, and lowers intent into `Compiled*` objects for one pool. |
| `dispatch-controller` | Tracks pool health from each broker's lease, schedules unbound workloads onto pools, runs failover and fencing, and signs the route-bus intermediate CAs for each pool and for the WAN edges. |
| reflector | The hub of the route bus. Agents in every pool and on every WAN edge hold a session to it. |

Each runs as a single replica today. [HA and restarts](../architecture/ha-and-restarts.md)
covers what survives a restart of each.

### Why the dispatch holds no CRDs

The five API groups are registered with the dispatch's host cluster as `APIService`
objects that point at `dispatch-apiserver`. The host cluster has no ectobase CRDs. The
API server is ectobase's own process, which buys three things.

- The fleet's objects live in their own store. Intent and compiled state for every pool
  sit in postgres through kine, separate from the host cluster's etcd.
- Validation and lifecycle hooks are Go code in the API types (`api/<group>/*_validate.go`
  and `*_rest.go`), not OpenAPI schemas and webhooks.
- Brokers in other clusters connect straight to it and authenticate with ectobase's own
  PKI, rather than going through the host kube-apiserver and its cluster CA.

Clients don't notice the difference. `kubectl` and client-go talk to the aggregated groups
through the host apiserver like any other API.

## The pools

A **pool** is an ordinary Kubernetes cluster that runs workloads. It is registered on the
dispatch as a cluster-scoped `ClusterPool`, and the dispatch keeps the pool's compiled
objects in the namespace `pool-<name>`. The `ectobase-pool` Helm chart installs the pool
side.

| Component | Runs as | What it does |
|---|---|---|
| `dispatch-broker` | Deployment | Syncs this pool's twins down from the dispatch, and reports lease, capacity, VM placement, disk identity and releases back up. |
| `flowplane` | DaemonSet | The eBPF dataplane. It serves the node-local `DataplaneNode` gRPC on a root-only unix socket. |
| `mesh-agent` | DaemonSet | Programs the local flowplane from `CompiledNIC`s and speaks the route bus. |
| `flowplane-cni` | DaemonSet (installer) | Attaches a workload's overlay interface to flowplane when its pod sandbox is created. |
| `pod-materializer` | Deployment | Turns a `CompiledContainer` into a Pod. |
| `vm-materializer` | Deployment, opt-in | Turns a `CompiledVM` and its `CompiledVolumeAttachment`s into a KubeVirt `VirtualMachine`. |

A pool also needs cert-manager and Multus, and for VMs KubeVirt, CDI and ceph-csi. The
chart can optionally add in-pool node remediation (medik8s NodeHealthCheck and
SelfNodeRemediation) for failures inside one pool.

### Why a pool uses real CRDs

The pool side is a set of ordinary controllers against the pool's own kube-apiserver, so
CRDs are the simplest fit: nothing extra to run in every pool. What the pool stores is
deliberately narrow.

- A pool only ever receives `compiled.ectobase.dev` objects. The compiled group is
  self-contained, so no pool component reads `net`, `compute` or `storage` intent, and a
  pool never has to understand the full API.
- The broker can only read its own pool's compiled objects on the dispatch. That scoping
  is RBAC, a `Role` in `pool-<name>`, not a filter the broker chooses to apply, so one
  pool can't read another's state.
- The broker writes each twin back into its source namespace in the pool, not into
  `pool-<name>`. The CNI and the materializers find a workload's objects in the
  workload's own namespace and never learn about the dispatch's layout.
- The pool keeps its own copy. If the dispatch is unreachable, the broker can't fetch a
  new desired set and leaves the local objects alone, so running workloads stay
  programmed.

## WAN edges

A WAN edge connects the overlay to networks outside the fleet. An edge is a router, not a
Kubernetes node: it runs `flowplane serve --role edge` and a `mesh-agent` in edge mode with
no apiserver. It joins the route bus with a certificate it mints itself from the edge
fleet's intermediate CA. [The WAN edge](../features/ns-edge.md) covers what it does with
traffic.

## flowplane, mesh and dispatch

The code splits into three parts by job, not by where each part runs.

| Part | Language | Contains | Runs on |
|---|---|---|---|
| flowplane (`flowplane/`) | Rust, eBPF via aya | The dataplane: eBPF programs, the pure core, the `flowplane` binary | every pool node, every WAN edge |
| mesh (`mesh/`) | Go | The network control plane: compiler, agent, reflector, route bus, materializers | compiler and reflector on the dispatch; materializers in pools; agent in pools and on edges |
| dispatch (`dispatch/`) | Go | Fleet orchestration: apiserver, broker, dispatch-controller | apiserver and controller on the dispatch; broker in each pool |

flowplane holds no policy of its own. Every decision it makes is a map lookup, and the
agent fills the maps from `CompiledNIC`s and from routes it learns on the route bus. The
API types live in `api/`, and the CNI plugin in `cni/`.

## How the pieces talk

| From | To | Over | Carries |
|---|---|---|---|
| broker | dispatch-apiserver | HTTPS with mTLS, port 6444 | twins down; lease, capacity and status up |
| mesh-agent | reflector | gRPC (`routebus.v1`) with mTLS, port 1338 | overlay routes, per VNI |
| dispatch-controller | reflector | gRPC (`RouteBusAdmin`), port 1339 | route fences |
| mesh-agent, flowplane-cni | flowplane | gRPC (`DataplaneNode`) on a unix socket | interface attach, routes, firewall, NAT, LB, QoS |
| flowplane | flowplane | Geneve over IPv6, UDP 6081 | tenant traffic |

The admin port is separate from the session port so that an agent with a valid session
certificate can't drive fencing.

## Where to go next

- [From intent to a running workload](intent-to-running.md): how a request moves through these components.
- [Multi-cluster orchestration](../architecture/multi-cluster.md): scheduling, the broker and per-pool authorization in depth.
- [The route bus](../architecture/route-bus.md): how the reflector and agents distribute overlay routes.
- [Deploy with Helm](../operations/deploy-helm.md): install the two charts.
