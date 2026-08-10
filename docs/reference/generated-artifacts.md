# Generated artifacts

A large part of ectobase's repository is **generated, not hand-written**. The Go
API types and a small set of RBAC markers are the single source of truth; a
`make generate` pipeline derives everything downstream from them — deepcopy and
conversion code, CRD manifests, per-component RBAC roles, and the CRD API
reference. Nothing that is generated is ever edited by hand, so the manifests
cannot drift from the code they describe.

This page documents that pipeline as durable architecture. It is driven entirely
by the `generate` (and its sub-target `docs-crd-ref`) targets in the top-level
`Makefile`.

## SolAr-style API layout

Each API group is split into two Go packages:

- an **internal** package (`api/<group>/`) holding apimachinery-only,
  hub-facing types, and
- a **versioned** package (`api/<group>/v1alpha1/`) holding the on-the-wire
  types plus their kubebuilder markers.

`kube::codegen` (from `k8s.io/code-generator`) generates the `zz_generated.*`
deepcopy and conversion functions and an `install` package that registers the
group into a scheme. This is the SolAr shape: users and CRDs speak the versioned
type; controllers work against a stable internal type; conversions between them
are generated, never authored.

```mermaid
flowchart TD
    subgraph src["Source of truth"]
        TYPES["Go API types<br/>api/*/v1alpha1/*_types.go<br/>(+kubebuilder markers)"]
        MARKERS["RBAC markers<br/>cmd/*/rbac.go, broker rbac/*/doc.go<br/>(+kubebuilder:rbac)"]
    end

    TYPES -->|kube::codegen| DEEP["zz_generated deepcopy / conversion + install"]
    TYPES -->|controller-gen crd| CRD["CRD manifests"]
    TYPES -->|crd-ref-docs| REF["docs/reference/api/*.md"]
    MARKERS -->|controller-gen rbac| ROLES["role.yaml per component"]

    CRD --> POOLCRD["charts/ectobase-pool/crd-bases<br/>(net + compiled)"]
    CRD --> TESTCRD["test/crds<br/>(compute + storage + platform)"]
    ROLES --> CHARTFILES["charts/*/files/<role>/role.yaml"]
    CHARTFILES -->|.Files.Get \| fromYaml| RBACTMPL["chart rbac.yaml templates"]
```

## Deepcopy and conversion

`make generate` runs the `kube::codegen` helpers in both `api/` and `hub/`. These
produce the `zz_generated.deepcopy.go`, `zz_generated.conversion.go`,
`zz_generated.defaults.go` and `zz_generated.model_name.go` files under each
versioned package — the runtime.Object plumbing every Kubernetes type needs. They
are regenerated from the Go types on every run.

## CRDs

CRDs are emitted by `controller-gen crd` directly into the tree, split by where
the resource is served:

| Group(s) | Output | Why |
| --- | --- | --- |
| `net`, `compiled` | `charts/ectobase-pool/crd-bases` | Shipped to pool clusters (gated by `installCRDs`); the agent, CNI and materializers read them locally. |
| `compute`, `storage`, `platform` | `test/crds` | Served by the hub aggregated apiserver (not shipped in any chart); the `test/crds` copies exist for envtest. |

Because the pool chart's `crds.yaml` template globs `crd-bases/*.yaml`, adding or
changing a `net`/`compiled` field regenerates the manifest and the chart picks it
up with no manual edit.

## RBAC

Each component's least-privilege ClusterRole is declared as `//+kubebuilder:rbac`
markers next to its binary — in a `cmd/<component>/rbac.go` (or, for a marker-only
package, a `doc.go`). `controller-gen rbac` renders each marker set into a
`role.yaml` under the owning chart's `files/<role>/` directory:

| Marker source | Generated into | Chart |
| --- | --- | --- |
| `netplane/cmd/controller` | `files/netplane-controller/role.yaml` | hub |
| `netplane/cmd/agent` | `files/netplane-agent/role.yaml` | pool |
| `netplane/cmd/vm-materializer` | `files/vm-materializer/role.yaml` | pool |
| `netplane/cmd/pod-materializer` | `files/pod-materializer/role.yaml` | pool |
| `cni` | `files/flowplane-cni/role.yaml` | pool |
| `hub/cmd/controller` | `files/hub-controller/role.yaml` | hub |
| `hub/cmd/broker/rbac/hubside` | `files/hub-broker/role.yaml` | hub |
| `hub/cmd/broker/rbac/poolside` | `files/hub-broker/role.yaml` | pool |

The chart templates then inject the generated rules — the `rbac.yaml` template
reads its role file and splices the rules in:

```yaml
rules:
  {{- (.Files.Get "files/netplane-controller/role.yaml" | fromYaml).rules | toYaml | nindent 2 }}
```

so the ClusterRole a component runs with is exactly the set of markers on its
code — permissions are proven against the reconcilers that need them.

!!! note "The hub-broker has two roles"
    The broker needs two distinct least-privilege identities: a **hub-side** role
    (read compiled objects, manage ClusterPools in the hub apiserver) and a
    **pool-side** role (write compiled objects into the pool cluster). Because
    `controller-gen` merges every marker under a package into one role, the
    markers are split into two import-nowhere sub-packages,
    `hub/cmd/broker/rbac/hubside` and `.../poolside`, generated into the hub chart
    and the pool chart respectively.

## CRD API reference

The `docs-crd-ref` target (run as the last step of `make generate`) invokes
`crd-ref-docs` over each versioned package and writes the per-group markdown under
`docs/reference/api/`:

- [`api/net.md`](api/net.md)
- [`api/compute.md`](api/compute.md)
- [`api/storage.md`](api/storage.md)
- [`api/compiled.md`](api/compiled.md)
- [`api/platform.md`](api/platform.md)

These pages are generated from the Go types plus their kubebuilder field
descriptions, so the per-field reference never drifts from the code. The
hand-written [CRD interactions](crd-interactions.md) page supplies the
cross-resource context the generated pages deliberately omit.

## Why generate everything

The payoff is **no drift**. There is no hand-maintained RBAC that can fall behind
a new reconciler, no CRD YAML that can lag a new field, and no API reference that
can go stale. Editing a Go type or an RBAC marker and re-running `make generate`
propagates the change to every derived artifact at once — deepcopy, conversion,
CRDs, roles and docs. The rule of thumb: **if a file is `zz_generated.*`, lives
under `crd-bases`/`test/crds`/`files/<role>`, or under `docs/reference/api/`, do
not edit it — change the source and regenerate.**
