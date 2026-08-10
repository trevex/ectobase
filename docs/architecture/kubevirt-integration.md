# KubeVirt / VM integration

!!! warning "Status: Partial"
    A VM's **primary** network is the ectobase overlay, attached through a
    KubeVirt network binding plugin backed by our CNI (`domainAttachmentType=tap`).
    The **vm-materializer** turns a `CompiledVM` into a KubeVirt `VirtualMachine`,
    and the tc-on-tap datapath is proven. Some of the KubeVirt control-plane wiring
    that stitches these together end-to-end is still settling; treat the VM path as
    functional-but-evolving rather than fully hardened.

## VMs on the overlay

An ectobase `VirtualMachine` (in the compute API group) is compiled into a
`CompiledVM`, which the per-cluster broker delivers to the target pool. On the
pool cluster the **vm-materializer** reconciles each `CompiledVM` into a
`kubevirt.io/v1` `VirtualMachine`. KubeVirt then runs the guest inside a
`virt-launcher` pod, and the VM's primary NIC is wired onto the ectobase overlay.

The overlay reaches the guest NIC through a **KubeVirt network binding plugin**
named `flowplane`, registered in the downstream KubeVirt CR as:

```json
"binding": {
  "flowplane": {
    "domainAttachmentType": "tap",
    "networkAttachmentDefinition": "ectobase-system/flowplane"
  }
}
```

virt-controller injects the referenced `flowplane` NAD into the launcher pod's
Multus annotation, so Multus runs `flowplane-cni` **in the launcher pod netns**.
With `deviceType=pod-tap` and `tapName=tap0`, the CNI asks the dataplane to
create a `tap` named `tap0` inside that netns, spliced to a root-netns veth that
carries the eBPF datapath. KubeVirt's `domainAttachmentType: tap` then opens
`tap0` as the VM's NIC. The dataplane's built-in DHCP/ARP/RA responders configure
the guest from inside the datapath, so the VM self-configures its address,
gateway, and MTU.

## Why tap, not managedTap

KubeVirt also ships a `managedTap` attachment mode, but it is unsuitable here:
`managedTap` **bridges** the tap and runs its own DHCP, hijacking address
assignment. That collides with the ectobase model, where the overlay identity is
central policy (VNI/IPs/MAC from the `CompiledNIC`) and the dataplane itself owns
DHCP/RA/ARP for the guest. Instead:

- **Our CNI creates the tap** (`domainAttachmentType=tap`, `deviceType=pod-tap`),
  so the device is spliced directly into our datapath rather than a Linux bridge.
- **The dataplane answers DHCP/RA/ARP**, so the guest gets exactly the overlay
  identity that was compiled for it — no bridge, no competing DHCP server.

## From `CompiledVM` to KubeVirt VM

The vm-materializer builds the `VirtualMachine` deterministically from the
`CompiledVM`:

- **Interfaces.** For each interface in the `CompiledVM` spec it emits a KubeVirt
  `Interface` with the **pinned MAC** and a `Binding{Name: flowplane}` (the tap
  binding plugin), plus a `Multus` network referencing the interface's network
  name. Pinning the MAC keeps the guest's L2 identity stable across reschedules.
- **Disks.** When the VM has `CompiledVolumeAttachment`s it boots from persistent
  CDI DataVolume disks (boot attachment first, then the rest by name); with no
  attachments it falls back to an ephemeral `containerDisk` from the VM image.
  See [Storage / CSI integration](storage-csi-integration.md).
- **Run strategy / resources** are copied from the compiled spec.

Materialization uses **server-side apply** rather than get-then-update. KubeVirt's
mutating webhook defaults many fields under `.spec.template.spec` (machine type,
firmware UUID, disk/feature defaults); a full-spec `DeepEqual` would always differ
from the sparse intent and churn the webhook on every reconcile. With SSA the
materializer owns only the fields it sets, and re-applying the same intent is a
genuine no-op.

The materializer also watches `CompiledVolumeAttachment` and maps each event back
to its owning `CompiledVM` (named `<namespace>-<workload>`), so adding or changing
a disk re-materializes the VM's disk list.

## Flow

```mermaid
sequenceDiagram
    participant Broker as broker (pool)
    participant VMM as vm-materializer
    participant KV as KubeVirt (virt-controller)
    participant Multus
    participant CNI as flowplane-cni (launcher netns)
    participant DP as DataplaneNode

    Broker->>VMM: CompiledVM (+ CompiledVolumeAttachments)
    VMM->>KV: apply VirtualMachine (flowplane binding, pinned MAC)
    KV->>KV: start virt-launcher pod (inject flowplane NAD)
    Multus->>CNI: CNI ADD in launcher netns (deviceType=pod-tap, tap0)
    CNI->>DP: AttachInterface(VNI, MAC, IPs, pod-tap)
    DP->>DP: create tap0 ↔ root-netns veth; program eBPF overlay
    KV->>KV: domainAttachmentType=tap opens tap0 as the VM NIC
    DP-->>KV: guest self-configures via DHCP/RA/ARP responders
```

## Where this lives

| Concern | Location |
| --- | --- |
| `CompiledVM` → KubeVirt `VirtualMachine` | `netplane/controllers/vmmaterializer.go` |
| `flowplane` NAD (the binding target) | `charts/ectobase-pool/templates/kubevirt-binding.yaml` |
| KubeVirt CR binding registration | `test/lab/internal/deploy/kubevirt.go` |
| CNI `pod-tap` device handling | `cni/plugin/main.go`, `api/proto/dataplane/v1/dataplane.proto` |
| Compiled VM spec | `api/compiled/v1alpha1/compiledvm_types.go` |
