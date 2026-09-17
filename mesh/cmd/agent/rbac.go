package main

// RBAC for the mesh node agent. Rules generated into
// charts/ectobase-pool/files/mesh-agent/role.yaml by `make generate`.
// NO net.ectobase.dev group appears here, deliberately: the agent reads QoS, firewall, NAT and LB
// membership from CompiledNICs (pool-synced by the broker) and never lists a raw net-group object.
// The last exception was loadbalancers, for an edge-only VIP reconcile — retired, because the
// broker syncs only the compiled.* kinds downstream, so that list could only ever return zero
// items. The edge now learns its VIPs from the route bus (see lbreconcile.go).

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics;compilednics/status,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch;patch
// Route-bus PKI (per-node mTLS): self-mint a per-node leaf via a cert-manager Certificate from
// the pool Issuer and read the resulting Secret.
//+kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
