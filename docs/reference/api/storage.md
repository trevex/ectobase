# API Reference

## Packages
- [storage.ectobase.dev/v1alpha1](#storageectobasedevv1alpha1)


## storage.ectobase.dev/v1alpha1

Package v1alpha1 is the v1alpha1 version of the storage.ectobase.dev API group:
the storage objects (Volume) served by the aggregated apiserver
and consumed as CRDs by the netplane control plane.

### Resource Types
- [Volume](#volume)
- [VolumeList](#volumelist)



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


