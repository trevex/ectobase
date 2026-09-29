package main

// RBAC for the vm-materializer. Rules generated into
// charts/ectobase-pool/files/vm-materializer/role.yaml by `make generate`.

//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvms,verbs=get;list;watch
// compiledvolumeattachments needs update/patch on the OBJECT, not just its status: the
// disk-identity controller holds a finalizer on the attachment so it can let go of the disk
// (drop the claim, remove the PersistentVolume) before a prune takes the attachment away.
// Finalizers live in metadata, so adding one is an update of the object itself, and without this
// every reconcile fails with "cannot update resource compiledvolumeattachments" — which is
// exactly how this was found, once the binary had a logger. Downstream-only: these are the pool's
// own twins, and this role already creates and deletes KubeVirt VMs and DataVolumes there.
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compiledvolumeattachments,verbs=get;list;watch;update;patch
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
