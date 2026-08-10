# API Reference

## Packages
- [compiled.ectobase.dev/v1alpha1](#compiledectobasedevv1alpha1)


## compiled.ectobase.dev/v1alpha1

Package v1alpha1 is the v1alpha1 version of the compiled.ectobase.dev API group:
the compiled objects (CompiledNIC, CompiledVM, CompiledContainer, CompiledVolumeAttachment)
served by the aggregated apiserver and consumed as CRDs by the netplane control plane.

### Resource Types
- [CompiledContainer](#compiledcontainer)
- [CompiledContainerList](#compiledcontainerlist)
- [CompiledNIC](#compilednic)
- [CompiledVM](#compiledvm)
- [CompiledVMList](#compiledvmlist)
- [CompiledVolumeAttachment](#compiledvolumeattachment)
- [CompiledVolumeAttachmentList](#compiledvolumeattachmentlist)



#### CompiledContainer



CompiledContainer is the lowered pod intent for a Container.



_Appears in:_
- [CompiledContainerList](#compiledcontainerlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `compiled.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `CompiledContainer` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[CompiledContainerSpec](#compiledcontainerspec)_ |  |  |  |
| `status` _[CompiledContainerStatus](#compiledcontainerstatus)_ |  |  |  |


#### CompiledContainerInterface



CompiledContainerInterface is a resolved overlay interface for a container.



_Appears in:_
- [CompiledContainerSpec](#compiledcontainerspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `networkName` _string_ | NetworkName is the multus NetworkAttachmentDefinition name for the overlay binding. |  | Optional: \{\} <br /> |
| `networkInterfaceRef` _string_ | NetworkInterfaceRef is "<namespace>/<nic>" — the pod's net.ectobase.dev/network-interface<br />annotation, which flowplane-cni resolves to the CompiledNIC. |  | Optional: \{\} <br /> |
| `mac` _string_ | MAC is the pinned L2 address (from the NetworkInterface). |  | Optional: \{\} <br /> |


#### CompiledContainerList



CompiledContainerList is a list of CompiledContainer objects.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `compiled.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `CompiledContainerList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[CompiledContainer](#compiledcontainer) array_ |  |  |  |


#### CompiledContainerSpec



CompiledContainerSpec is the lowered, ready-to-materialize intent for a container workload: the pod
template + the cluster/node binding + the per-interface overlay wiring. A downstream pod-materializer
turns this into a v1.Pod.



_Appears in:_
- [CompiledContainer](#compiledcontainer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterName` _string_ | ClusterName is the cluster this compiled container is bound to. The broker selects on this field. |  | Optional: \{\} <br /> |
| `nodeName` _string_ | NodeName is the pod nodeSelector (kubernetes.io/hostname). |  | Optional: \{\} <br /> |
| `image` _string_ | Image is the container image. |  | Optional: \{\} <br /> |
| `command` _string array_ | Command overrides the image entrypoint. |  | Optional: \{\} <br /> |
| `args` _string array_ | Args are the container args. |  | Optional: \{\} <br /> |
| `env` _[EnvVar](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#envvar-v1-core) array_ | Env are the container environment variables. |  | Optional: \{\} <br /> |
| `resources` _[ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#resourcerequirements-v1-core)_ | Resources is the compute request/limit. |  | Optional: \{\} <br /> |
| `restartPolicy` _[RestartPolicy](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#restartpolicy-v1-core)_ | RestartPolicy is the Pod restart policy. |  | Optional: \{\} <br /> |
| `interfaces` _[CompiledContainerInterface](#compiledcontainerinterface) array_ | Interfaces are the container's overlay interfaces (one per owned NetworkInterface). |  | Optional: \{\} <br /> |


#### CompiledContainerStatus



CompiledContainerStatus is the observed state of a CompiledContainer.



_Appears in:_
- [CompiledContainer](#compiledcontainer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `state` _string_ | State is the materialization state (e.g. Applied, Pending). |  | Optional: \{\} <br /> |


#### CompiledFirewall



CompiledFirewall holds pre-compiled ingress and egress rules for a NIC.



_Appears in:_
- [CompiledNICSpec](#compilednicspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `ingress` _[CompiledFwRule](#compiledfwrule) array_ | Ingress is the ordered list of ingress firewall rules. |  | Optional: \{\} <br /> |
| `egress` _[CompiledFwRule](#compiledfwrule) array_ | Egress is the ordered list of egress firewall rules. |  | Optional: \{\} <br /> |


#### CompiledFwRule



CompiledFwRule is a single compiled firewall rule (destination CIDR + proto + port + action).



_Appears in:_
- [CompiledFirewall](#compiledfirewall)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `cidr` _string_ | CIDR is the destination CIDR to match ("0.0.0.0/0" = any). |  |  |
| `proto` _string_ | Proto is the IP protocol ("TCP", "UDP", "ICMP", or "" for any). |  | Optional: \{\} <br /> |
| `port` _integer_ | Port is the destination port (0 = any). |  | Optional: \{\} <br /> |
| `action` _string_ | Action is the rule action: "Allow" or "Deny". |  |  |


#### CompiledLB



CompiledLB is one load-balancer this NIC backs: the VIP (v4 or v6) and its service ports.



_Appears in:_
- [CompiledNICSpec](#compilednicspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vip` _string_ | VIP is the load-balancer virtual IP (IPv4 or IPv6). |  |  |
| `ports` _[CompiledLBPort](#compiledlbport) array_ | Ports are the LB service (port, proto) tuples. |  | Optional: \{\} <br /> |


#### CompiledLBPort



CompiledLBPort is one LB service tuple.



_Appears in:_
- [CompiledLB](#compiledlb)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `port` _integer_ |  |  |  |
| `proto` _string_ |  |  |  |


#### CompiledNATSource



CompiledNATSource is one egress-SNAT mapping: an overlay source IP SNATed onto a public NAT IP
and source-port range. It corresponds to a single NATGateway allocation for one of the NIC's IPs.



_Appears in:_
- [CompiledNICSpec](#compilednicspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `sourceIP` _string_ | SourceIP is the overlay IP being SNATed (one of the NIC's OverlayIPs). |  |  |
| `natIP` _string_ | NATIP is the public NAT IPv4 address. |  |  |
| `portMin` _integer_ | PortMin is the start of the source-port range (inclusive). |  |  |
| `portMax` _integer_ | PortMax is the end of the source-port range (inclusive). |  |  |


#### CompiledNIC



CompiledNIC is a lowered, node-local bundle of all static per-NIC dataplane config.
It is produced by the Compile() function from a NetworkInterface + matching NetworkPolicies.



_Appears in:_
- [CompiledNICList](#compiledniclist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `compiled.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `CompiledNIC` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[CompiledNICSpec](#compilednicspec)_ |  |  |  |
| `status` _[CompiledNICStatus](#compilednicstatus)_ |  |  |  |




#### CompiledNICSpec



CompiledNICSpec is the fully lowered per-NIC STATIC POLICY the control plane hands to a node:
identity, VNI, overlay IPs, firewall rules (resolved from FirewallPolicy selectors), egress-SNAT
allocations, LB membership, and peer imports — derived from the NetworkInterface + VPC +
FirewallPolicy + LoadBalancer + NATGateway + VPCPeering so the agent never reads those directly.

The source NetworkInterface is the CompiledNIC's OWNER (a controller ownerReference) and its name
is encoded in the object name — so the spec carries no NICRef. It also deliberately does NOT carry
the NIC's underlay /128: that is node-local state the dataplane allocates at attach, and the agent
obtains it from the local DataplaneNode (ListInterfaces) to announce overlay routes with the
correct node-local nexthop. Keeping node-local state out of this central object avoids a
compile->sync round-trip that would lag (and flap) the announced nexthop.



_Appears in:_
- [CompiledNIC](#compilednic)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterName` _string_ | ClusterName is the cluster this compiled NIC is bound to (the pod->node<br />binding). Set by the compiler from the owning VirtualMachine's placement,<br />or the compiler's --cluster-name default for NICs with no owning VM.<br />The per-cluster broker selects on this field. |  | Optional: \{\} <br /> |
| `nodeName` _string_ | NodeName is the node this NIC is scheduled on. |  |  |
| `vni` _integer_ | VNI is the effective VXLAN network identifier for this NIC (resolved from the NIC's<br />status.vni, falling back to its VPC's status.vni). |  |  |
| `port` _[PortStatus](#portstatus)_ | Port describes the dataplane port allocated for this interface. |  |  |
| `overlayIPs` _string array_ | OverlayIPs are the guest overlay IP addresses. |  | Optional: \{\} <br /> |
| `firewall` _[CompiledFirewall](#compiledfirewall)_ | Firewall holds the compiled ingress and egress firewall rules. |  |  |
| `nat` _[CompiledNATSource](#compilednatsource) array_ | NAT lists the egress-SNAT sources for this NIC's overlay IPs — one entry per NATGateway<br />allocation whose source is one of this NIC's IPs. Empty if the NIC's VPC has no NAT gateway. |  | Optional: \{\} <br /> |
| `lb` _[CompiledLB](#compiledlb) array_ | LB lists the load balancers this NIC is a backend of. Pure forwarding membership —<br />it grants NO firewall permission (that comes solely from FirewallPolicy). |  | Optional: \{\} <br /> |
| `peerImports` _[CompiledPeerImport](#compiledpeerimport) array_ | PeerImports lists peer VPCs whose routes this NIC imports (reachability only — grants NO<br />firewall permission; that comes solely from FirewallPolicy). Populated from Ready VPCPeerings<br />involving this NIC's VPC. |  | Optional: \{\} <br /> |
| `mac` _string_ | MAC is the guest L2 address copied from the source NetworkInterface. The CNI<br />programs it as the datapath guest MAC (empty for containers — the datapath derives one). |  | Optional: \{\} <br /> |


#### CompiledNICStatus



CompiledNICStatus is the observed state of a CompiledNIC.



_Appears in:_
- [CompiledNIC](#compilednic)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `state` _string_ | State is the current lifecycle state (e.g. Applied, Pending). |  | Optional: \{\} <br /> |
| `generationApplied` _integer_ | GenerationApplied is the ObjectMeta.Generation of the CompiledNIC last applied. |  | Optional: \{\} <br /> |


#### CompiledPeerImport



CompiledPeerImport is one peer VPC's reachability import for a NIC.



_Appears in:_
- [CompiledNICSpec](#compilednicspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `peerVni` _integer_ | PeerVNI is the peer VPC's VNI to subscribe to on routebus. |  |  |
| `importPrefixes` _string array_ | ImportPrefixes is the peer's exposedPrefixes: only peer routes within these CIDRs are<br />imported (filter applied importer-side). |  | Optional: \{\} <br /> |


#### CompiledVM



CompiledVM is the lowered boot intent for a scheduled VirtualMachine.



_Appears in:_
- [CompiledVMList](#compiledvmlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `compiled.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `CompiledVM` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[CompiledVMSpec](#compiledvmspec)_ |  |  |  |
| `status` _[CompiledVMStatus](#compiledvmstatus)_ |  |  |  |


#### CompiledVMInterface



CompiledVMInterface is a resolved overlay interface for a VM: the pinned MAC
and the multus network (NetworkAttachmentDefinition) name for the flowplane binding.



_Appears in:_
- [CompiledVMSpec](#compiledvmspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `mac` _string_ | MAC is the pinned L2 address (from the NetworkInterface). |  | Optional: \{\} <br /> |
| `networkName` _string_ | NetworkName is the multus NetworkAttachmentDefinition name for the overlay binding. |  | Optional: \{\} <br /> |


#### CompiledVMList



CompiledVMList is a list of CompiledVM objects.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `compiled.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `CompiledVMList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[CompiledVM](#compiledvm) array_ |  |  |  |


#### CompiledVMSpec



CompiledVMSpec is the fully lowered, ready-to-materialize boot intent for a VM:
the containerDisk image, compute resources, run strategy, the cluster binding,
and the per-interface MAC + overlay network name. A downstream materializer
turns this into a kubevirt.io/v1.VirtualMachine.



_Appears in:_
- [CompiledVM](#compiledvm)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterName` _string_ | ClusterName is the cluster this compiled VM is bound to (the pod->node binding).<br />The per-cluster broker selects on this field. |  | Optional: \{\} <br /> |
| `image` _string_ | Image is the containerDisk image to boot from. |  | Optional: \{\} <br /> |
| `resources` _[ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#resourcerequirements-v1-core)_ | Resources is the compute request/limit; maps to the KubeVirt domain resources. |  | Optional: \{\} <br /> |
| `runStrategy` _string_ | RunStrategy is the KubeVirt run strategy (defaulted upstream by the compiler). |  | Optional: \{\} <br /> |
| `interfaces` _[CompiledVMInterface](#compiledvminterface) array_ | Interfaces are the VM's overlay interfaces (one per owned NetworkInterface). |  | Optional: \{\} <br /> |


#### CompiledVMStatus



CompiledVMStatus is the observed state of a CompiledVM. It is intentionally
minimal (State only): the downstream materializer reconciles CompiledVM into a
KubeVirt VirtualMachine via declarative set-reconcile, so — unlike CompiledNIC,
whose node agent tracks an applied generation — no GenerationApplied is needed here.



_Appears in:_
- [CompiledVM](#compiledvm)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `state` _string_ | State is the materialization state (e.g. Applied, Pending). |  | Optional: \{\} <br /> |


#### CompiledVolumeAttachment



CompiledVolumeAttachment binds one Volume to one VM on a cluster.



_Appears in:_
- [CompiledVolumeAttachmentList](#compiledvolumeattachmentlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `compiled.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `CompiledVolumeAttachment` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[CompiledVolumeAttachmentSpec](#compiledvolumeattachmentspec)_ |  |  |  |
| `status` _[CompiledVolumeAttachmentStatus](#compiledvolumeattachmentstatus)_ |  |  |  |


#### CompiledVolumeAttachmentList



CompiledVolumeAttachmentList is a list of CompiledVolumeAttachment objects.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `compiled.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `CompiledVolumeAttachmentList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[CompiledVolumeAttachment](#compiledvolumeattachment) array_ |  |  |  |


#### CompiledVolumeAttachmentSpec



CompiledVolumeAttachmentSpec is the lowered, cluster-bound attachment of one
Volume to one VM: the RBD disk parameters a downstream materializer turns into a
CDI DataVolume (RBD PVC).



_Appears in:_
- [CompiledVolumeAttachment](#compiledvolumeattachment)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterName` _string_ | ClusterName is the cluster this attachment is bound to (the pod->node binding);<br />the per-cluster broker selects on this field. |  | Optional: \{\} <br /> |
| `size` _[Quantity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#quantity-resource-api)_ | Size is the RBD disk size. |  | Required: \{\} <br /> |
| `storageClass` _string_ | StorageClass is the ceph-csi RBD StorageClass (empty = cluster default). |  | Optional: \{\} <br /> |
| `bootImage` _string_ | BootImage, if set, is imported into the disk (bootable); empty = blank disk. |  | Optional: \{\} <br /> |
| `boot` _boolean_ | Boot marks this attachment as the VM's boot disk. |  | Optional: \{\} <br /> |


#### CompiledVolumeAttachmentStatus



CompiledVolumeAttachmentStatus is the observed state.



_Appears in:_
- [CompiledVolumeAttachment](#compiledvolumeattachment)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `state` _string_ | State is the materialization state. |  | Optional: \{\} <br /> |




#### PortStatus



PortStatus describes the dataplane port allocated for a NetworkInterface.



_Appears in:_
- [CompiledNICSpec](#compilednicspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `type` _[PortType](#porttype)_ | Type is the port type (e.g. tap or vf). |  | Enum: [tap vf] <br /> |
| `name` _string_ | Name is the host-side interface name (e.g. dtapvf_0) for tap ports. |  | Optional: \{\} <br /> |
| `pciAddress` _string_ | PCIAddress is the PCI address for vf ports. |  | Optional: \{\} <br /> |


#### PortType

_Underlying type:_ _string_

PortType is the kind of dataplane port backing a NetworkInterface.

_Validation:_
- Enum: [tap vf]

_Appears in:_
- [PortStatus](#portstatus)

| Field | Description |
| --- | --- |
| `tap` | PortTypeTap is a tap-backed (vhost-user) port.<br /> |
| `vf` | PortTypeVF is an SR-IOV virtual-function passthrough port.<br /> |


