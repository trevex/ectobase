package main

// RBAC for the netplane node agent. Rules generated into
// charts/ectobase-pool/files/netplane-agent/role.yaml by `make generate`.

//+kubebuilder:rbac:groups=net.ectobase.dev,resources=vpcs;vpcs/status;networkinterfaces;networkinterfaces/status;natgateways;natgateways/status;loadbalancers;loadbalancers/status,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compilednics/status,verbs=get;list;watch
//+kubebuilder:rbac:groups=net.ectobase.dev,resources=networkinterfaces/status,verbs=update;patch
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch;patch
