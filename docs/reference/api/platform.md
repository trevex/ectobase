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


#### RouteBusIdentity



RouteBusIdentity is a pool's route-bus intermediate-CA request + signed response, served
by the dispatch aggregated apiserver. The broker creates it; the dispatch signer fills status.



_Appears in:_
- [RouteBusIdentityList](#routebusidentitylist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[RouteBusIdentitySpec](#routebusidentityspec)_ |  |  |  |
| `status` _[RouteBusIdentityStatus](#routebusidentitystatus)_ |  |  |  |




#### RouteBusIdentitySpec



RouteBusIdentitySpec is a pool's request for a route-bus intermediate CA. The pool (its
broker) generates the intermediate keypair LOCALLY and submits only the CSR — the private
key is never transmitted. The dispatch signer returns a name-constrained intermediate that
can mint per-node agent leaves scoped to this pool.



_Appears in:_
- [RouteBusIdentity](#routebusidentity)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `poolName` _string_ | PoolName is the ClusterPool this identity belongs to. The signed intermediate is<br />name-constrained to this pool so it can only mint node identities within it. |  |  |
| `request` _integer array_ | Request is the PEM-encoded PKCS#10 certificate-signing request for the pool's<br />intermediate CA (the pool keeps the matching private key). |  |  |
| `permittedUnderlayCIDRs` _string array_ | PermittedUnderlayCIDRs are the pool's underlay IPv6 ranges. The signer name-constrains<br />the intermediate to these so it can only mint node leaves whose IP SAN falls inside the<br />pool — the reflector binds route nexthops to that SAN. |  | Optional: \{\} <br /> |


#### RouteBusIdentityStatus



RouteBusIdentityStatus carries the signer's response: the signed intermediate and the
root CA bundle the reflector trusts.



_Appears in:_
- [RouteBusIdentity](#routebusidentity)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `certificate` _integer array_ | Certificate is the PEM-encoded signed intermediate CA certificate (the CSR response). |  | Optional: \{\} <br /> |
| `caBundle` _integer array_ | CABundle is the PEM-encoded root CA the reflector trusts, so the pool can present the<br />full chain (leaf -> intermediate -> root). |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#condition-v1-meta) array_ | Conditions represent the latest observations (e.g. Signed / Denied). |  | Optional: \{\} <br /> |


