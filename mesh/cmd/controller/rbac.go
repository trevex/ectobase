package main

// RBAC for the mesh compiler (mesh-controller). Rules generated into
// charts/ectobase-dispatch/files/mesh-controller/role.yaml by `make generate`
// (controller-gen rbac). Keep in sync with the reconcilers in mesh/controllers.

//+kubebuilder:rbac:groups=net.ectobase.dev,resources=natgateways,verbs=get;list;watch;update
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=natgateways/status,verbs=get;update
// Compiled-twin teardown puts a finalizer on the SOURCE objects below, and adding or removing a
// finalizer is an UPDATE on the main resource — CRDs/aggregated resources expose no /finalizers
// subresource, so `<resource>/status` is not enough. Without `update` here the finalizers are
// silently never written (RBAC is not enforced by envtest, only by a real cluster) and teardown
// quietly falls back to owner-ref GC, which stops working once twins move namespace.
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=networkinterfaces,verbs=get;list;watch;update
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=networkinterfaces/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=firewallpolicies;loadbalancers,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=loadbalancers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=subnets,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=subnets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=lbpools,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=lbpools/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcs,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcpeerings,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcpeerings/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=virtualmachines,verbs=get;list;watch;update
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=virtualmachines/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=containers,verbs=get;list;watch;update
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=containers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=storage.ectobase.dev,resources=volumes,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compiledvms;compiledvolumeattachments;compiledcontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics/status;compiledvms/status;compiledvolumeattachments/status;compiledcontainers/status,verbs=get;update;patch

// Leader election (review I3): the manager holds a Lease lock so only one pod is
// active fleet-wide (single-writer allocators). Leader election also emits events.
//+kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
