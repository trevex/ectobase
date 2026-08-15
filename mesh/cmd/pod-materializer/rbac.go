package main

// RBAC for the pod-materializer. Rules generated into
// charts/ectobase-pool/files/pod-materializer/role.yaml by `make generate`.

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledcontainers,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledcontainers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
