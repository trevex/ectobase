package main

// RBAC for the vm-materializer. Rules generated into
// charts/ectobase-pool/files/vm-materializer/role.yaml by `make generate`.

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms;compiledvolumeattachments,verbs=get;list;watch
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms/status;compiledvolumeattachments/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachines,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=kubevirt.io,resources=virtualmachineinstances,verbs=get;list;watch
//+kubebuilder:rbac:groups=cdi.kubevirt.io,resources=datavolumes,verbs=get;list;watch;create;update;patch;delete

// Disk identity + non-destructive rebind. PersistentVolumes are cluster-scoped and the reclaim
// policy lives on them, so patch is required: a dynamically provisioned PV inherits the
// StorageClass's reclaimPolicy (Delete in the lab), which destroys the RBD image the moment its
// PVC goes — including when a clusterName change prunes the attachment. Flipping it to Retain is
// what makes a rebind survivable. create/delete are for adopting an existing disk in a new cluster
// (a static PV replaying the recorded CSI source) and for removing the Released PV left behind in
// the cluster the disk moved away from.
//+kubebuilder:rbac:groups="",resources=persistentvolumes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
