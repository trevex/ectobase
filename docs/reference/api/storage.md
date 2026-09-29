# API Reference

## Packages
- [storage.ectobase.dev/v1alpha1](#storageectobasedevv1alpha1)


## storage.ectobase.dev/v1alpha1

Package v1alpha1 is the v1alpha1 version of the storage.ectobase.dev API group:
the storage objects (Volume) served by the aggregated apiserver
and consumed as CRDs by the mesh control plane.

### Resource Types
- [Volume](#volume)
- [VolumeList](#volumelist)



#### DiskIdentity



DiskIdentity is the CSI identity of the disk actually provisioned for this Volume, as observed by
the pool that provisioned it. It is what makes the disk's lifetime belong to the Volume — which is
cluster-agnostic — rather than to the placement-scoped attachment that happens to reference it.

The entire CSI source is kept verbatim rather than a handle plus reconstructed parameters:
rebuilding a ceph-csi PV from StorageClass parameters means re-deriving clusterID, pool, imageName,
journalPool and up to five distinct secret references by hand, and dropping any one of them yields
a PV that binds and then fails to mount at NodeStage.

Deliberately a separate declaration from compiled.DiskIdentity, mirroring the
compute.VMPlacement / compiled.VMPlacement split: the compiled group is self-contained so a pool
never needs the source API, and an import either way would break that.



_Appears in:_
- [VolumeStatus](#volumestatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `csi` _[CSIPersistentVolumeSource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#csipersistentvolumesource-v1-core)_ | CSI is the provisioned PersistentVolume's CSI source, copied as-is. |  | Optional: \{\} <br /> |
| `capacity` _[Quantity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#quantity-resource-api)_ | Capacity is the PV's actual capacity, which a driver may round up from the requested Size. |  | Optional: \{\} <br /> |


#### Volume



Volume is a persistent RBD-backed disk referenced by a VirtualMachine.



_Appears in:_
- [VolumeList](#volumelist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `storage.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `Volume` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[VolumeSpec](#volumespec)_ |  |  |  |
| `status` _[VolumeStatus](#volumestatus)_ |  |  |  |


#### VolumeList



VolumeList is a list of Volume objects.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `storage.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `VolumeList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[Volume](#volume) array_ |  |  |  |


#### VolumeSpec



VolumeSpec defines a persistent RBD-backed disk for a VM.



_Appears in:_
- [Volume](#volume)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `size` _[Quantity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#quantity-resource-api)_ | Size is the requested disk size (e.g. 10Gi). |  | Required: \{\} <br /> |
| `storageClass` _string_ | StorageClass is the ceph-csi RBD StorageClass; empty uses the cluster default. |  | Optional: \{\} <br /> |
| `bootImage` _string_ | BootImage, if set, is a containerDisk/registry image imported into the disk<br />(making it bootable). Empty leaves a blank data disk of Size. |  | Optional: \{\} <br /> |


#### VolumeStatus



VolumeStatus is the observed state of a Volume.



_Appears in:_
- [Volume](#volume)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `phase` _string_ | Phase is the current lifecycle phase of the Volume. |  | Optional: \{\} <br /> |
| `diskIdentity` _[DiskIdentity](#diskidentity)_ | DiskIdentity, once set, is the disk backing this Volume. It is mirrored here from the<br />CompiledVolumeAttachment a pool reported it on, and is what a later attachment in ANOTHER<br />cluster is stamped with so it adopts this disk instead of provisioning a blank one. |  | Optional: \{\} <br /> |
| `diskReclaimStarted` _boolean_ | DiskReclaimStarted records that the objects handing this Volume's image back to its CSI<br />driver for deletion have been created.<br />It exists to tell two states apart that look identical from outside: "the reclaim has not<br />begun" and "the driver finished and removed the PersistentVolume". Both present as an absent<br />PV, and only the second means the image is actually gone. |  | Optional: \{\} <br /> |


