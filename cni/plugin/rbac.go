package main

// RBAC for the flowplane CNI plugin. Rules generated into
// charts/ectobase-pool/files/flowplane-cni/role.yaml by `make generate`.

//+kubebuilder:rbac:groups="",resources=pods,verbs=get
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics,verbs=get
