package main

// RBAC for the netplane compiler (netplane-controller). Rules generated into
// charts/ectobase-dispatch/files/netplane-controller/role.yaml by `make generate`
// (controller-gen rbac). Keep in sync with the reconcilers in netplane/controllers.

//+kubebuilder:rbac:groups=net.ectobase.dev,resources=natgateways,verbs=get;list;watch;update
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=natgateways/status,verbs=get;update
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=networkinterfaces,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=firewallpolicies;loadbalancers,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcs,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcpeerings,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcpeerings/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=virtualmachines,verbs=get;list;watch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=virtualmachines/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=containers,verbs=get;list;watch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=containers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=storage.ectobase.dev,resources=volumes,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compiledvms;compiledvolumeattachments;compiledcontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics/status;compiledvms/status;compiledvolumeattachments/status;compiledcontainers/status,verbs=get;update;patch
