package main

// RBAC for the hub controller (clusterpool + scheduler + failover/fence).
// Rules generated into charts/ectobase-hub/files/hub-controller/role.yaml.

//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=clusterpools,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=platform.ectobase.dev,resources=clusterpools/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=virtualmachines,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=virtualmachines/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=containers,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=compute.ectobase.dev,resources=containers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms;compilednics;compiledvolumeattachments,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=storage.ectobase.dev,resources=volumes,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=csiaddons.openshift.io,resources=networkfences,verbs=get;list;watch;create;update;patch;delete
