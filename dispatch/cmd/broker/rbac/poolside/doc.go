// Package poolside carries the dispatch-broker POOL-SIDE (downstream, in-cluster) RBAC markers.
// Marker-only; read by controller-gen via paths=./cmd/broker/rbac/poolside/...; imported
// nowhere. There is no dispatchside counterpart: the broker's dispatch-side grant is per pool by
// construction (a namespaced Role in pool-<clusterName> plus a resourceNames-scoped ClusterRole),
// so it is provisioned at enrollment rather than generated into a chart.
package poolside

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compiledvms;compiledvolumeattachments;compiledcontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
//+kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachineinstances,verbs=get;list;watch
// Release proof (dispatch/pkg/broker/release.go): a retired VM is released only once its KubeVirt
// VM, its virt-launcher pods and its disk claims are gone. The downstream client is uncached, so
// get/list is all it needs.
//+kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachines,verbs=get
//+kubebuilder:rbac:groups="",resources=pods;persistentvolumeclaims,verbs=list
// Route-bus PKI: the broker writes the pool intermediate CA into a Secret (backs the pool
// cert-manager Issuer).
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
