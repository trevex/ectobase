# API Reference

## Packages
- [compute.ectobase.dev/v1alpha1](#computeectobasedevv1alpha1)


## compute.ectobase.dev/v1alpha1

Package v1alpha1 is the v1alpha1 version of the compute.ectobase.dev API group:
the compute objects (VirtualMachine, Container) served by the aggregated apiserver
and consumed as CRDs by the mesh control plane.

### Resource Types
- [Container](#container)
- [ContainerList](#containerlist)
- [VirtualMachine](#virtualmachine)
- [VirtualMachineList](#virtualmachinelist)



#### Container



Container is a schedulable container workload on the ectobase overlay.



_Appears in:_
- [ContainerList](#containerlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `compute.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `Container` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ContainerSpec](#containerspec)_ |  |  |  |
| `status` _[ContainerStatus](#containerstatus)_ |  |  |  |


#### ContainerList



ContainerList is a list of Container objects.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `compute.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `ContainerList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[Container](#container) array_ |  |  |  |


#### ContainerSpec



ContainerSpec is a schedulable container workload: it owns NetworkInterfaces and carries the pod
template. Placement (ClusterName/NodeName) is the authority for its owned NICs; in this slice it is
set by hand (no scheduler binds it yet).



_Appears in:_
- [Container](#container)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterName` _string_ | ClusterName is the cluster this container is bound to (the placement authority for owned NICs). |  | Optional: \{\} <br /> |
| `nodeName` _string_ | NodeName pins the Pod (and the owned NICs) to a node; the agent firewall reconcile gates on it. |  | Optional: \{\} <br /> |
| `interfaceRefs` _[LocalObjectReference](#localobjectreference) array_ | InterfaceRefs names the NetworkInterfaces (same namespace) this container owns. |  | Optional: \{\} <br /> |
| `image` _string_ | Image is the container image. |  | Optional: \{\} <br /> |
| `command` _string array_ | Command overrides the image entrypoint. |  | Optional: \{\} <br /> |
| `args` _string array_ | Args are the container args. |  | Optional: \{\} <br /> |
| `env` _[EnvVar](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#envvar-v1-core) array_ | Env are the container environment variables. |  | Optional: \{\} <br /> |
| `resources` _[ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#resourcerequirements-v1-core)_ | Resources is the compute request/limit. |  | Optional: \{\} <br /> |
| `restartPolicy` _[RestartPolicy](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#restartpolicy-v1-core)_ | RestartPolicy is the Pod restart policy (default Always). |  | Optional: \{\} <br /> |


#### ContainerStatus



ContainerStatus is the observed state of a Container.



_Appears in:_
- [Container](#container)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `state` _string_ | State is the compile/materialization state (e.g. Compiled, Pending). |  | Optional: \{\} <br /> |


#### LocalObjectReference



LocalObjectReference references an object by name within the same namespace.



_Appears in:_
- [ContainerSpec](#containerspec)
- [VirtualMachineSpec](#virtualmachinespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the referenced object. |  |  |


#### VMAntiAffinity



VMAntiAffinity is a minimal anti-affinity: VMs sharing Group should land on
different ClusterPools. Best-effort — a failover with no non-violating pool
places anyway and records the violation.



_Appears in:_
- [VirtualMachineSpec](#virtualmachinespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `group` _string_ | Group is the anti-affinity key; VMs with the same Group repel each other. |  |  |


#### VMPlacement



VMPlacement is the VM's actual running location, reported upward by the broker.



_Appears in:_
- [VirtualMachineStatus](#virtualmachinestatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterName` _string_ | ClusterName is the pool the VM is running on. |  |  |
| `nodeName` _string_ | NodeName is the node running the VM. |  |  |
| `nodePrefix` _string_ | NodePrefix is that node's /64 underlay prefix (the fence coordinate). |  |  |


#### VirtualMachine



VirtualMachine is the placement anchor for a workload.



_Appears in:_
- [VirtualMachineList](#virtualmachinelist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `compute.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `VirtualMachine` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[VirtualMachineSpec](#virtualmachinespec)_ |  |  |  |
| `status` _[VirtualMachineStatus](#virtualmachinestatus)_ |  |  |  |


#### VirtualMachineList



VirtualMachineList is a list of VirtualMachine objects.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `compute.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `VirtualMachineList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[VirtualMachine](#virtualmachine) array_ |  |  |  |


#### VirtualMachineSpec



VirtualMachineSpec defines the desired state of a VirtualMachine: the cluster
binding (placement anchor), the NetworkInterfaces it owns, its compute resources,
and — since Phase 4 — its boot intent (containerDisk Image + RunStrategy). The
compiler propagates ClusterName (and a workload=<name> label) onto the CompiledNICs
of the referenced interfaces and onto a CompiledVM. Ceph-backed volume lifecycle
is a later phase.



_Appears in:_
- [VirtualMachine](#virtualmachine)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterName` _string_ | ClusterName is the cluster this workload is bound to. Set manually or by<br />the compiler default in Phase 1b; the Phase-3 scheduler writes it later. |  | Optional: \{\} <br /> |
| `interfaceRefs` _[LocalObjectReference](#localobjectreference) array_ | InterfaceRefs names the NetworkInterfaces (same namespace) this VM owns. |  | Optional: \{\} <br /> |
| `volumeRefs` _[LocalObjectReference](#localobjectreference) array_ | VolumeRefs names the Volumes (same namespace) this VM attaches. A referenced<br />Volume with a BootImage is the boot disk; others are data disks. When empty the<br />VM boots ephemerally from Image (containerDisk). |  | Optional: \{\} <br /> |
| `resources` _[ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#resourcerequirements-v1-core)_ | Resources is the compute resource request/limit for this workload. Only<br />Requests is used for scheduling capacity fit; Limits is carried for parity. |  | Optional: \{\} <br /> |
| `image` _string_ | Image is the containerDisk image the VM boots from (e.g. quay.io/containerdisks/fedora:41). |  | Optional: \{\} <br /> |
| `runStrategy` _string_ | RunStrategy is the KubeVirt run strategy (Always, RerunOnFailure, Manual, Halted).<br />Empty defaults to RerunOnFailure (Tier-1 local restart on node death). |  | Optional: \{\} <br /> |
| `poolSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#labelselector-v1-meta)_ | PoolSelector, if set, restricts scheduling to ClusterPools whose labels match. |  | Optional: \{\} <br /> |
| `antiAffinity` _[VMAntiAffinity](#vmantiaffinity)_ | AntiAffinity, if set, spreads VMs sharing a Group across ClusterPools during<br />scheduling and failover (best-effort: availability wins if no non-violating pool). |  | Optional: \{\} <br /> |


#### VirtualMachineStatus



VirtualMachineStatus defines the observed state of a VirtualMachine.



_Appears in:_
- [VirtualMachine](#virtualmachine)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `phase` _string_ | Phase is the current lifecycle phase of the VirtualMachine. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#condition-v1-meta) array_ | Conditions capture scheduling/failover observations (Scheduled, Unschedulable, FailoverBlocked). |  | Optional: \{\} <br /> |
| `placement` _[VMPlacement](#vmplacement)_ | Placement is the VM's actual running location, stamped by the broker. Central<br />uses NodePrefix as the fence coordinate and to gate recovery drain. |  | Optional: \{\} <br /> |


