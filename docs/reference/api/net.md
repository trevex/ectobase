# API Reference

## Packages
- [net.ectobase.dev/v1alpha1](#netectobasedevv1alpha1)


## net.ectobase.dev/v1alpha1

Package v1alpha1 is the v1alpha1 version of the net.ectobase.dev API group:
the user-facing overlay networking model plus the compiled objects, served by
the aggregated apiserver and consumed as CRDs by the netplane control plane.

### Resource Types
- [FirewallPolicy](#firewallpolicy)
- [FloatingIP](#floatingip)
- [LoadBalancer](#loadbalancer)
- [NATGateway](#natgateway)
- [NetworkInterface](#networkinterface)
- [VPC](#vpc)
- [VPCPeering](#vpcpeering)



#### EgressQoS



EgressQoS shapes total egress (EDT) with an optional external sub-cap.



_Appears in:_
- [InterfaceQoS](#interfaceqos)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `rateMbps` _integer_ | RateMbps is the EDT-shaped total egress rate in Mbit/s. 0 = unlimited. |  | Optional: \{\} <br /> |
| `burstKB` _integer_ | BurstKB is an optional burst allowance in KB. Reserved (EDT ignores it in v1). 0 = default. |  | Optional: \{\} <br /> |
| `publicMbps` _integer_ | PublicMbps caps external/NATed egress in Mbit/s (policed). 0 = unlimited. |  | Optional: \{\} <br /> |


#### FirewallPolicy



FirewallPolicy is a scaffold-only resource. Selector-based distributed firewall (§3.4).



_Appears in:_
- [FirewallPolicyList](#firewallpolicylist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `net.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `FirewallPolicy` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[FirewallPolicySpec](#firewallpolicyspec)_ |  |  |  |
| `status` _[FirewallPolicyStatus](#firewallpolicystatus)_ |  |  |  |




#### FirewallPolicyRule



FirewallPolicyRule is a single allow/deny rule for ingress or egress traffic.



_Appears in:_
- [FirewallPolicySpec](#firewallpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `cidr` _string_ | CIDR is the source (ingress) or destination (egress) CIDR to match.<br />"0.0.0.0/0" matches all addresses. |  |  |
| `proto` _string_ | Proto is the IP protocol to match ("TCP", "UDP", "ICMP", or "" for any). |  | Optional: \{\} <br /> |
| `port` _integer_ | Port is the destination port to match (0 = any). |  | Optional: \{\} <br /> |
| `action` _string_ | Action is "Allow" or "Deny". |  |  |


#### FirewallPolicySpec



FirewallPolicySpec is the desired state of a FirewallPolicy.



_Appears in:_
- [FirewallPolicy](#firewallpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `interfaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#labelselector-v1-meta)_ | InterfaceSelector selects the NetworkInterfaces this policy applies to via label matching. |  | Optional: \{\} <br /> |
| `ingress` _[FirewallPolicyRule](#firewallpolicyrule) array_ | Ingress is the ordered list of ingress rules to apply to selected interfaces. |  | Optional: \{\} <br /> |
| `egress` _[FirewallPolicyRule](#firewallpolicyrule) array_ | Egress is the ordered list of egress rules to apply to selected interfaces. |  | Optional: \{\} <br /> |


#### FirewallPolicyStatus



FirewallPolicyStatus is the observed state of a FirewallPolicy.

SCAFFOLD ONLY: intentionally empty.



_Appears in:_
- [FirewallPolicy](#firewallpolicy)



#### FloatingIP



FloatingIP is a scaffold-only resource. Floating/movable virtual IP (§3.7).



_Appears in:_
- [FloatingIPList](#floatingiplist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `net.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `FloatingIP` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[FloatingIPSpec](#floatingipspec)_ |  |  |  |
| `status` _[FloatingIPStatus](#floatingipstatus)_ |  |  |  |




#### FloatingIPSpec



FloatingIPSpec is the desired state of a FloatingIP.

SCAFFOLD ONLY: intentionally empty. Floating/movable virtual IP (§3.7).
Fleshed out in a later plan (YAGNI here).



_Appears in:_
- [FloatingIP](#floatingip)



#### FloatingIPStatus



FloatingIPStatus is the observed state of a FloatingIP.

SCAFFOLD ONLY: intentionally empty.



_Appears in:_
- [FloatingIP](#floatingip)



#### InterfaceQoS



InterfaceQoS is per-interface traffic control. Egress is EDT-shaped (smoothed) at the uplink fq
qdisc; ingress is token-bucket policed. Programmed into the dataplane via DataplaneNode/ConfigureQoS.



_Appears in:_
- [NetworkInterfaceSpec](#networkinterfacespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `egress` _[EgressQoS](#egressqos)_ | Egress shapes outbound (VM->out) throughput. |  | Optional: \{\} <br /> |
| `ingress` _[RateLimit](#ratelimit)_ | Ingress polices inbound (out->VM) throughput. |  | Optional: \{\} <br /> |


#### LoadBalancer



LoadBalancer is a scaffold-only resource. Selector-target load balancer (§3.5).



_Appears in:_
- [LoadBalancerList](#loadbalancerlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `net.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `LoadBalancer` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[LoadBalancerSpec](#loadbalancerspec)_ |  |  |  |
| `status` _[LoadBalancerStatus](#loadbalancerstatus)_ |  |  |  |




#### LoadBalancerPort



LoadBalancerPort is one LB service tuple.



_Appears in:_
- [LoadBalancerSpec](#loadbalancerspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `port` _integer_ | Port is the service port. |  |  |
| `proto` _string_ | Proto is the IP protocol ("TCP" or "UDP"). |  |  |


#### LoadBalancerSpec



LoadBalancerSpec is the desired state of a LoadBalancer. The VIP is the LB's identity
(v4 or v6); backends are the NetworkInterfaces matched by TargetSelector or named by TargetRefs.



_Appears in:_
- [LoadBalancer](#loadbalancer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vip` _string_ | VIP is the virtual IP (IPv4 or IPv6). It is the LB identity and the AddLbVip id. |  |  |
| `ports` _[LoadBalancerPort](#loadbalancerport) array_ | Ports are the LB service (port, proto) tuples. |  |  |
| `targetSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#labelselector-v1-meta)_ | TargetSelector selects backend NetworkInterfaces by label. Mutually exclusive with TargetRefs. |  | Optional: \{\} <br /> |
| `targetRefs` _[LocalObjectReference](#localobjectreference) array_ | TargetRefs names backend NetworkInterfaces explicitly. Mutually exclusive with TargetSelector. |  | Optional: \{\} <br /> |


#### LoadBalancerStatus



LoadBalancerStatus is the observed state of a LoadBalancer.



_Appears in:_
- [LoadBalancer](#loadbalancer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `state` _string_ | State is the lifecycle state (Pending \| Ready). |  | Optional: \{\} <br /> |


#### LocalObjectReference



LocalObjectReference references an object by name within the same namespace.



_Appears in:_
- [LoadBalancerSpec](#loadbalancerspec)
- [NATGatewaySpec](#natgatewayspec)
- [NetworkInterfaceSpec](#networkinterfacespec)
- [VPCPeeringSpec](#vpcpeeringspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the referenced object. |  |  |


#### NATAllocation



NATAllocation records one source's deterministic mapping.



_Appears in:_
- [NATGatewayStatus](#natgatewaystatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `source` _string_ | Source is the overlay IP (a NetworkInterface IP) being SNATed. |  |  |
| `publicIP` _string_ | PublicIP + [PortMin,PortMax] is the deterministic block. |  |  |
| `portMin` _integer_ |  |  |  |
| `portMax` _integer_ |  |  |  |


#### NATGateway



NATGateway is a drain-safe egress SNAT for the sources in a VPC, using
deterministic (public-IP, port-block) allocation.



_Appears in:_
- [NATGatewayList](#natgatewaylist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `net.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `NATGateway` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[NATGatewaySpec](#natgatewayspec)_ |  |  |  |
| `status` _[NATGatewayStatus](#natgatewaystatus)_ |  |  |  |




#### NATGatewaySpec



NATGatewaySpec is the desired state of a NATGateway: a drain-safe egress SNAT
for the sources in a VPC, using deterministic (public-IP, port-block) allocation.



_Appears in:_
- [NATGateway](#natgateway)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vpcRef` _[LocalObjectReference](#localobjectreference)_ | VPCRef selects the VPC whose interfaces egress through this gateway. |  |  |
| `publicIPs` _string array_ | PublicIPs is the pool of public IPv4s SNAT sources are mapped onto. |  |  |
| `portsPerSource` _integer_ | PortsPerSource is the deterministic port-block size handed to each source<br />(RFC 7422 / GCP-static style). Default 1024. |  | Optional: \{\} <br /> |
| `edgeUnderlay` _string_ | EdgeUnderlay is DEPRECATED and IGNORED. The edge fleet self-advertises via<br />EDGE_UNDERLAY: egress (0.0.0.0/0 and 64:ff9b::/96 for NAT64) is originated by<br />any agent started with --edge-loopback, nexthop'd at that edge's own anycast<br />underlay. Retained only to avoid a CRD breaking change; set nothing here. |  | Optional: \{\} <br /> |


#### NATGatewayStatus



NATGatewayStatus is the observed state.



_Appears in:_
- [NATGateway](#natgateway)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allocations` _[NATAllocation](#natallocation) array_ | Allocations is the deterministic source→block table (published to all gateways). |  | Optional: \{\} <br /> |
| `state` _string_ |  |  | Optional: \{\} <br /> |


#### NetworkInterface



NetworkInterface is a thin NIC attached to a VM: identity plus user-specified overlay IPs.



_Appears in:_
- [NetworkInterfaceList](#networkinterfacelist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `net.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `NetworkInterface` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[NetworkInterfaceSpec](#networkinterfacespec)_ |  |  |  |
| `status` _[NetworkInterfaceStatus](#networkinterfacestatus)_ |  |  |  |




#### NetworkInterfaceSpec



NetworkInterfaceSpec is the desired state of a NetworkInterface (a thin NIC).



_Appears in:_
- [NetworkInterface](#networkinterface)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vpcRef` _[LocalObjectReference](#localobjectreference)_ | VPCRef references the VPC this interface belongs to. |  |  |
| `ips` _string array_ | IPs are the user-specified overlay IPs (v4 and/or v6). The platform does<br />not allocate these. |  | Optional: \{\} <br /> |
| `mac` _string_ | MAC is the interface's L2 address. REQUIRED for a KubeVirt VM (device_type<br />pod-tap/tap): the datapath programs this as the guest MAC, and the VMI's<br />spec.domain.devices.interfaces[].macAddress MUST be set to the same value so<br />KubeVirt gives the VM's virtio NIC that MAC. Empty for containers (derived). |  | Optional: \{\} <br /> |
| `nodeName` _string_ | NodeName is the node the interface is scheduled onto. Set by the scheduler. |  | Optional: \{\} <br /> |
| `qos` _[InterfaceQoS](#interfaceqos)_ | QoS caps/shapes throughput for this interface. Nil = unlimited. |  | Optional: \{\} <br /> |
| `clusterName` _string_ | ClusterName is the compute cluster this standalone (e.g. Pod) NIC targets. The<br />compiler uses it for placement (CompiledNIC.spec.clusterName) when no<br />VirtualMachine owns this NIC; an owning VM's placement takes precedence. |  | Optional: \{\} <br /> |


#### NetworkInterfaceStatus



NetworkInterfaceStatus is the observed state of a NetworkInterface.



_Appears in:_
- [NetworkInterface](#networkinterface)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vni` _integer_ | VNI is the effective VXLAN network identifier resolved from the VPC. |  | Optional: \{\} <br /> |
| `underlayRoute` _string_ | UnderlayRoute is the allocated underlay /128 from the host's underlay /64. |  | Optional: \{\} <br /> |
| `port` _[PortStatus](#portstatus)_ | Port describes the dataplane port allocated for this interface. |  | Optional: \{\} <br /> |
| `state` _string_ | State is the current lifecycle state (e.g. Pending, Ready). |  | Optional: \{\} <br /> |


#### PortStatus



PortStatus describes the dataplane port allocated for a NetworkInterface.



_Appears in:_
- [NetworkInterfaceStatus](#networkinterfacestatus)

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


#### RateLimit



RateLimit is a token-bucket policing cap.



_Appears in:_
- [InterfaceQoS](#interfaceqos)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `rateMbps` _integer_ | RateMbps caps throughput in Mbit/s. 0 = unlimited. |  | Optional: \{\} <br /> |
| `burstKB` _integer_ | BurstKB is an optional burst allowance in KB. Reserved (default burst in v1). 0 = default. |  | Optional: \{\} <br /> |


#### VPC



VPC is an isolation domain (overlay network) identified by a VNI on the shared underlay.



_Appears in:_
- [VPCList](#vpclist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `net.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `VPC` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[VPCSpec](#vpcspec)_ |  |  |  |
| `status` _[VPCStatus](#vpcstatus)_ |  |  |  |




#### VPCPeering



VPCPeering is one direction of a mutual-consent VPC peering; a reciprocal pair (A→B and B→A)
forms an active peering. Reachability only — it grants no firewall permission.



_Appears in:_
- [VPCPeeringList](#vpcpeeringlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `net.ectobase.dev/v1alpha1` | | |
| `kind` _string_ | `VPCPeering` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[VPCPeeringSpec](#vpcpeeringspec)_ |  |  |  |
| `status` _[VPCPeeringStatus](#vpcpeeringstatus)_ |  |  |  |




#### VPCPeeringSpec



VPCPeeringSpec is the desired state of a one-directional VPC peering. A mutual peering
is formed by a reciprocal pair (A→B and B→A). Reachability only — never a firewall grant.



_Appears in:_
- [VPCPeering](#vpcpeering)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vpcRef` _[LocalObjectReference](#localobjectreference)_ | VPCRef is this side's VPC (same namespace as this VPCPeering object). |  |  |
| `peerVpcRef` _[VPCReference](#vpcreference)_ | PeerVPCRef references the other VPC (namespace + name). |  |  |
| `exposedPrefixes` _string array_ | ExposedPrefixes is the CIDR allow-list THIS side offers to the peer: only local routes<br />within these CIDRs become reachable to the peer VPC. Empty = expose nothing (fail-closed). |  | Optional: \{\} <br /> |


#### VPCPeeringStatus



VPCPeeringStatus is the observed state of a VPCPeering.



_Appears in:_
- [VPCPeering](#vpcpeering)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `state` _string_ | State is the peering lifecycle: Pending (awaiting the reciprocal), Ready (both sides<br />consent), or Invalid (validation failed). |  | Optional: \{\} <br /> |
| `message` _string_ | Message is a human-readable reason for the current State. |  | Optional: \{\} <br /> |




#### VPCReference



VPCReference references a VPC by namespace + name (peering may be cross-namespace,
since it is central-authored).



_Appears in:_
- [VPCPeeringSpec](#vpcpeeringspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `namespace` _string_ |  |  |  |
| `name` _string_ |  |  |  |


#### VPCSpec



VPCSpec is the desired state of a VPC (an isolation domain / overlay network).



_Appears in:_
- [VPC](#vpc)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vni` _integer_ | VNI optionally pins the VXLAN network identifier. When nil or 0, the VNI is<br />allocated by the central cluster from the global VNI space. |  | Optional: \{\} <br /> |
| `defaultPolicy` _string_ | DefaultPolicy overrides the global default firewall posture for this VPC.<br />One of Allow (k8s semantics) or Deny (VPC-wide default-deny). |  | Optional: \{\} <br /> |


#### VPCStatus



VPCStatus is the observed state of a VPC.



_Appears in:_
- [VPC](#vpc)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vni` _integer_ | VNI is the effective, allocated VXLAN network identifier. |  | Optional: \{\} <br /> |
| `state` _string_ | State is the current lifecycle state (e.g. Pending, Ready). |  | Optional: \{\} <br /> |


