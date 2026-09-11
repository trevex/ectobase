// Package dispatchside carries the dispatch-broker DISPATCH-SIDE RBAC markers (the credential the
// broker uses against the dispatch aggregated apiserver). It holds only //+kubebuilder:rbac
// comments; controller-gen reads it by path (paths=./cmd/broker/rbac/dispatchside/...). It is
// imported nowhere. Split from poolside because controller-gen merges all markers under a
// package into one role, and the broker needs two distinct least-privilege roles.
package dispatchside

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compiledvms;compiledvolumeattachments;compiledcontainers,verbs=get;list;watch
// The broker reports each VM's actual running location onto its OWN pool's CompiledVM status —
// never onto the source VirtualMachine, which sits in a tenant namespace shared with other pools'
// workloads and so would need a grant no per-pool RBAC can scope. A mesh controller mirrors it up.
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms/status,verbs=get;update;patch
// The broker only READS ClusterPool spec (to resolve its cluster) and writes its OWN pool STATUS
// (the lease/capacity heartbeat + node prefixes). It never creates or mutates pool spec — the
// operator owns that — so the parent resource is read-only here, scoped to the broker's own pool
// by the ClusterRestriction admission plugin (which matches the ClusterPool name against the
// broker's cert CN).
//
// NOTE: nothing on compute.ectobase.dev is granted, so the broker's attempt to report
// VirtualMachine.status.placement upward (dispatch/pkg/broker/broker.go) is RBAC-denied and
// silently dropped — that field has never been populated in a deployed cluster. Granting it
// here would be a CROSS-POOL write (ClusterRestriction does not scope virtualmachines), so the
// fix is to report placement into the pool's own namespaced CompiledVM status instead; see the
// per-pool authorization design.
//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=clusterpools,verbs=get;list;watch
//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=clusterpools/status,verbs=get;update;patch
// Route-bus PKI access is deliberately NOT granted here. A RouteBusIdentity carries a pool's
// intermediate-CA CSR + signed cert, so a fleet-wide grant on this shared role would let ANY
// pool's credential obtain ANY other pool's intermediate CA (and thus mint leaves impersonating
// that pool's nodes on the bus). Instead each pool gets its own ClusterRole scoped with
// resourceNames to its own object, bound to that pool's cert identity (ectobase:cluster:<pool>)
// and its first-boot bootstrap SA — provisioned per pool at enrollment alongside the ClusterPool.
// Because resourceNames cannot scope `create`, the RouteBusIdentity is pre-created at enrollment
// and the broker only ever get/updates it.
