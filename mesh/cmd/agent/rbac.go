package main

// RBAC for the mesh node agent. Rules generated into
// charts/ectobase-pool/files/mesh-agent/role.yaml by `make generate`.
// networkinterfaces, vpcs, natgateways are intentionally absent: the agent reads QoS and all NIC
// policy from CompiledNICs (pool-synced by the broker) and never lists raw net-group objects except
// loadbalancers (edge-only LB VIP reconcile in lbreconcile.go).

//+kubebuilder:rbac:groups=net.ectobase.dev,resources=loadbalancers;loadbalancers/status,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compilednics/status,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch;patch
// Route-bus PKI (per-node mTLS): self-mint a per-node leaf via a cert-manager Certificate from
// the pool Issuer and read the resulting Secret.
//+kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
