package main

// RBAC for the netplane node agent. Rules generated into
// charts/ectobase-pool/files/netplane-agent/role.yaml by `make generate`.
// networkinterfaces, vpcs, natgateways are intentionally absent: the agent reads QoS and all NIC
// policy from CompiledNICs (pool-synced by the broker) and never lists raw net-group objects except
// loadbalancers (edge-only LB VIP reconcile in lbreconcile.go).

//+kubebuilder:rbac:groups=net.ectobase.dev,resources=loadbalancers;loadbalancers/status,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compilednics/status,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch;patch
