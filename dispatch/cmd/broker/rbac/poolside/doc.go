// Package poolside carries the dispatch-broker POOL-SIDE (downstream, in-cluster) RBAC markers.
// Marker-only; read by controller-gen via paths=./cmd/broker/rbac/poolside/...; imported
// nowhere. See the dispatchside package for why the two roles are split.
package poolside

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compiledvms;compiledvolumeattachments;compiledcontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
//+kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachineinstances,verbs=get;list;watch
