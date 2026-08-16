// Package dispatchside carries the dispatch-broker DISPATCH-SIDE RBAC markers (the credential the
// broker uses against the dispatch aggregated apiserver). It holds only //+kubebuilder:rbac
// comments; controller-gen reads it by path (paths=./cmd/broker/rbac/dispatchside/...). It is
// imported nowhere. Split from poolside because controller-gen merges all markers under a
// package into one role, and the broker needs two distinct least-privilege roles.
package dispatchside

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compiledvms;compiledvolumeattachments;compiledcontainers,verbs=get;list;watch
// The broker only READS ClusterPool spec (to resolve its cluster) and writes its OWN pool STATUS
// (heartbeat + per-VM placement). It never creates or mutates pool spec — the operator owns that —
// so the parent resource is read-only here and the ClusterRestriction admission plugin is
// defense-in-depth, not the sole guard against a broker editing pools.
//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=clusterpools,verbs=get;list;watch
//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=clusterpools/status,verbs=get;update;patch
// Route-bus PKI: the broker submits its pool intermediate-CA CSR as a RouteBusIdentity and reads
// back the signed cert (the dispatch signer fills status).
//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=routebusidentities,verbs=get;list;watch;create;update
//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=routebusidentities/status,verbs=get
