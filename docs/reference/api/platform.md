# API Reference

## Packages
- [platform.ectobase.dev/v1alpha1](#platformectobasedevv1alpha1)


## platform.ectobase.dev/v1alpha1

Package v1alpha1 is the v1alpha1 version of the platform.ectobase.dev API
(ClusterPool and, later, the compiled objects), served by the aggregated apiserver.



#### ClusterPool



ClusterPool is an attached cluster exposed as a schedulable capacity domain.



_Appears in:_
- [ClusterPoolList](#clusterpoollist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ClusterPoolSpec](#clusterpoolspec)_ |  |  |  |
| `status` _[ClusterPoolStatus](#clusterpoolstatus)_ |  |  |  |


#### ClusterPoolLease



ClusterPoolLease is the broker's heartbeat on a ClusterPool: the identity
holding it and when it was last renewed. Stale RenewTime => the pool is Unknown.



_Appears in:_
- [ClusterPoolStatus](#clusterpoolstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `holderIdentity` _string_ | HolderIdentity is the broker instance currently reporting for this pool. |  | Optional: \{\} <br /> |
| `renewTime` _[MicroTime](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#microtime-v1-meta)_ | RenewTime is when the holder last renewed the lease. |  | Optional: \{\} <br /> |




#### ClusterPoolSpec



ClusterPoolSpec defines the desired state of a ClusterPool.



_Appears in:_
- [ClusterPool](#clusterpool)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `region` _string_ | Region is the region the attached cluster resides in. |  |  |
| `endpoint` _string_ | Endpoint is the reachable API endpoint of the attached cluster. |  |  |


#### ClusterPoolStatus



ClusterPoolStatus defines the observed state of a ClusterPool.



_Appears in:_
- [ClusterPool](#clusterpool)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `phase` _string_ | Phase is the current lifecycle phase of the ClusterPool. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#condition-v1-meta) array_ | Conditions represent the latest available observations of the ClusterPool's state. |  | Optional: \{\} <br /> |
| `allocatable` _[ResourceList](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#resourcelist-v1-core)_ | Allocatable is the schedulable capacity the broker reports for this pool. |  | Optional: \{\} <br /> |
| `lease` _[ClusterPoolLease](#clusterpoollease)_ | Lease is the broker heartbeat; a stale RenewTime drives Phase to Unknown. |  | Optional: \{\} <br /> |
| `nodePrefixes` _string array_ | NodePrefixes is the set of node /64 underlay prefixes composing this cluster,<br />reported by the broker. Central fences these (Ceph NetworkFence + route<br />blocklist) to evacuate a lost pool without reaching it. |  | Optional: \{\} <br /> |
| `fencedPrefixes` _string array_ | FencedPrefixes is the subset of NodePrefixes central has fenced (evacuation). |  | Optional: \{\} <br /> |
| `nodeDrain` _[NodeDrainStatus](#nodedrainstatus) array_ | NodeDrain reports, per fenced /64, whether the returning broker has confirmed<br />its stale VMIs are terminated (safe to release the fence). |  | Optional: \{\} <br /> |


#### NodeDrainStatus



NodeDrainStatus is the per-/64 drain confirmation used to gate fence release.



_Appears in:_
- [ClusterPoolStatus](#clusterpoolstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `prefix` _string_ | Prefix is the node /64 underlay prefix. |  |  |
| `drained` _boolean_ | Drained is true once the broker confirms the /64's stale VMIs are gone. |  |  |


