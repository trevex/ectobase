# CNI integration

!!! success "Status: Implemented"
    Pods join the ectobase overlay through **flowplane-cni**, a purpose-built
    CNI plugin invoked as a Multus **secondary** network. On pod ADD the plugin
    resolves the pod's overlay identity from a `CompiledNIC` and programs the
    node dataplane over the `DataplaneNode` gRPC.

## The Multus-secondary model

ectobase does not replace a compute cluster's primary pod network. Instead the
pool installs **Multus (thin)** as a wrapper over whatever CNI the node already
runs. The Multus thin DaemonSet drops `/opt/cni/bin/multus` and a
`00-multus.conf` that delegates the pod's **default** network to the
lexicographically-first existing config on the node (for example the cluster's
own CNI). The overlay is layered on top as a **secondary** attachment, so a pod
keeps its normal primary connectivity and additionally gains an overlay NIC.

The overlay attachment is described by a `NetworkAttachmentDefinition` named
`flowplane` that references the `flowplane-cni` plugin type:

```json
{
  "cniVersion": "1.0.0",
  "name": "flowplane",
  "plugins": [
    { "type": "flowplane-cni", "deviceType": "pod-tap", "tapName": "tap0" }
  ]
}
```

A workload joins the overlay by selecting this NAD — either via the standard
`k8s.v1.cni.cncf.io/networks` pod annotation, or (for VMs) via KubeVirt's network
binding mechanism, which injects the NAD into the launcher pod's Multus
annotation. See [KubeVirt / VM integration](kubevirt-integration.md) for the VM
path.

## Installation

The `flowplane-cni` binary is delivered by an installer DaemonSet
(`flowplane-cni-install`) that runs on every node and mounts the host's
`/opt/cni/bin` and `/etc/cni/net.d`. It drops the plugin binary and a
service-account-token kubeconfig (`dataplane-kubeconfig`) the plugin later uses,
from the host netns, to read the pod and its compiled config. The installer, its
`ServiceAccount`, and the RBAC the plugin needs are all part of the pool chart.

## On pod ADD

When the container runtime creates a pod sandbox on the overlay network, Multus
invokes `flowplane-cni` with the pod coordinates in `CNI_ARGS`. The plugin:

1. **Identifies the pod.** It parses `K8S_POD_NAMESPACE`, `K8S_POD_NAME`, and
   `K8S_POD_UID` from `CNI_ARGS`.
2. **Finds the bound interface.** Using the on-node kubeconfig it reads the pod
   object and follows its `net.ectobase.dev/network-interface` annotation to the
   `NetworkInterface` custom resource that describes this attachment.
3. **Resolves overlay identity from `CompiledNIC`.** It GETs the
   `CompiledNIC` named `<ns>-<nic>` in the NIC's namespace and reads the
   overlay `{VNI, overlay IPs, MAC}` from its spec. The plugin reads **only** this
   lowered object — never the raw `NetworkInterface`/`VPC`/policy objects — so the
   compute cluster never needs the source CRDs. A `CompiledNIC` with `vni == 0`
   is treated as not-yet-compiled and the ADD fails cleanly so the kubelet
   retries.
4. **Programs the datapath.** It dials the node-local `DataplaneNode` gRPC
   (default `127.0.0.1:1337`, reachable because the dataplane DaemonSet runs with
   host networking) and calls `AttachInterface` with the interface id
   (`<pod-uid>/<ifname>`), the target netns, and the resolved `{VNI, MAC, IPs}`.
   The dataplane creates the guest device (a veth for containers) and programs the
   eBPF overlay for it.
5. **Returns a CNI result.** It builds a CNI v1.0.0 `Result` from the attach
   response's IPs, MAC, and gateway. A default/secondary network requires at least
   one IP; if the dataplane returns none, ADD fails.

The whole ADD flow is bounded by a 30-second deadline so a hung apiserver or an
unreachable dataplane cannot stall sandbox creation indefinitely.

### The `deviceType` selector

The NAD's `deviceType` selects which guest-edge device the dataplane creates:

| `deviceType` | Guest edge | Used for |
| --- | --- | --- |
| `""` / `veth` | veth pair; guest end in the pod netns | Containers (default) |
| `pod-tap` | a `tap` in the pod netns spliced to a root-netns veth | KubeVirt VMs |

For `pod-tap` the NAD also sets `tapName: tap0`, because KubeVirt's
`domainAttachmentType: tap` opens the primary tap by that literal name.

## On pod DEL

DEL is best-effort and idempotent. Keyed off the pod UID it calls
`DataplaneNode.DetachInterface(<pod-uid>/<ifname>)`, ignoring not-found and
unreachable-dataplane errors so teardown never blocks. CHECK is a no-op success —
the plugin holds no per-interface state to validate.

## Flow

```mermaid
sequenceDiagram
    participant Kubelet as kubelet / CRI
    participant Multus
    participant CNI as flowplane-cni
    participant API as apiserver
    participant DP as DataplaneNode (node-local gRPC)

    Kubelet->>Multus: CNI ADD (pod on flowplane network)
    Multus->>CNI: ADD (CNI_ARGS: K8S_POD_*)
    CNI->>API: GET pod → network-interface annotation
    CNI->>API: GET CompiledNIC <ns>-<nic>
    API-->>CNI: {VNI, overlayIPs, MAC}
    CNI->>DP: AttachInterface(id, netns, VNI, MAC, IPs, deviceType)
    DP->>DP: create veth (or pod-tap) + program eBPF overlay
    DP-->>CNI: {ifname, ips, mac, gateway, underlay_route}
    CNI-->>Multus: CNI Result (v1.0.0)
    Multus-->>Kubelet: Result
```

## Where this lives

| Concern | Location |
| --- | --- |
| Plugin entrypoint, ADD/DEL/CHECK | `cni/plugin/main.go` |
| Pod → NetworkInterface → `CompiledNIC` resolution | `cni/plugin/resolve.go` |
| gRPC dial + attach/detach | `cni/plugin/attach.go` |
| `DataplaneNode` service (`AttachInterface`, …) | `api/proto/dataplane/v1/dataplane.proto` |
| Installer DaemonSet + RBAC | `charts/ectobase-pool/templates/cni.yaml` |
| `flowplane` NAD | `charts/ectobase-pool/templates/kubevirt-binding.yaml` |
| Multus (thin) install | `test/lab/internal/deploy/multus.go` |
| Compiled per-NIC policy | `api/compiled/v1alpha1/compilednic_types.go` |
