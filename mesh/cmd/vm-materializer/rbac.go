package main

// RBAC for the vm-materializer. Rules generated into
// charts/ectobase-pool/files/vm-materializer/role.yaml by `make generate`.

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms;compiledvolumeattachments,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms/status;compiledvolumeattachments/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachines,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachineinstances,verbs=get;list;watch
//+kubebuilder:rbac:groups=cdi.kubevirt.io,resources=datavolumes,verbs=get;list;watch;create;update;patch;delete
