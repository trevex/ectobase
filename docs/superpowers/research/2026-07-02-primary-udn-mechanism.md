# Primary-UDN mechanism for KubeVirt VMs on the eBPF dataplane — decision spike

**Status:** DONE_WITH_CONCERNS — decision made; manual proof deferred (see §6).
**Date:** 2026-07-02 (research 2026-07-13)
**Sub-project:** ① — KubeVirt VM on the eBPF dataplane
**Parent spec:** `docs/superpowers/specs/2026-07-02-subproject-01-vm-dataplane-attach-design.md`

---

## 0. TL;DR decision

Make our custom CNI the virt-launcher pod's **only** network interface by combining **two** KubeVirt/Multus mechanisms — they are complementary, not alternatives:

1. **Multus "default network" delegation** owns the *pod networking* layer.
   In the VMI spec set `spec.template.spec.networks[].multus.default: true` pointing at **our** `NetworkAttachmentDefinition`. KubeVirt renders this into the `v1.multus-cni.io/default-network` annotation on the virt-launcher pod. A Multus `multus.default` network and a `pod: {}` network are **mutually exclusive**, so the pod gets **our CNI as `eth0` and no cluster-default pod interface at all**. This is the piece that delivers "true primary-UDN, no pod network."

2. **A KubeVirt network binding plugin** owns the *domain/vNIC wiring* layer.
   Register a binding under `spec.configuration.network.binding.<name>` in the KubeVirt CR and reference it from the VM interface via `interfaces[].binding.name: <name>`. For sub-project ① the binding needs **no custom sidecar** — the built-in **`managedTap`** `domainAttachmentType` (KubeVirt ≥ v1.4) wires the pod's primary interface to a tap into the VM. It was explicitly built for "custom CNI plugins or non-OVN cluster networking." A custom sidecar image is only needed later if we want in-pod DHCP served by the binding rather than by the dataplane, or migration hooks.

**Why not the alternatives (short):**
- The **ovn-kubernetes primary-UDN API** (`UserDefinedNetwork role: Primary` + `k8s.ovn.org/primary-user-defined-network` namespace label, `binding.name: l2bridge`) is **ovn-kubernetes-specific** and, notably, **does NOT remove `eth0`** — it keeps the cluster-default network attached but "infrastructure-locked" (healthcheck-only). Not CNI-pluggable to our dataplane, and it fails our "no pod network at all" requirement. Rejected.
- A **network binding plugin alone** does NOT give us a primary-UDN: the binding CNI runs **in addition to** the primary pod network, not as a replacement (KubeVirt: "First it calls the 'regular' network CNI plugin … Secondly it calls the network binding CNI plugin"). It is the domain/tap glue, not the mechanism that removes the pod network. So the team's leading hypothesis is **half right**: we do need a binding plugin, but it is insufficient on its own — the Multus-default delegation is what actually suppresses the pod network.

---

## 1. Requirement restated

The virt-launcher pod must have **no default pod-network interface**. Its **only** NIC must be served by our eBPF-dataplane CNI, and that NIC must be wired into the guest VM as its primary interface. Analogous to OpenShift ovn-k + primary-UDN, but with our dataplane instead of ovn-kubernetes.

Acceptance signal (task 1 spike): inside the virt-launcher pod, `eth0` is the interface programmed by *our* CNI, and there is no second interface from a cluster-default CNI.

---

## 2. Candidate mechanisms investigated

### 2.1 Multus default-network delegation — CHOSEN (pod-networking layer)

**How it makes a custom CNI the primary / only network:**
Multus is the cluster's meta-CNI. The pod's *primary* interface (`eth0`, the one that provides "Pod IP") is whatever Multus is told is its **default network**. Two knobs:
- Cluster-wide: Multus config `clusterNetwork` = the single default CNI/NAD for every pod's `eth0`.
- Per-pod override: the **`v1.multus-cni.io/default-network`** pod annotation overrides `clusterNetwork` for that pod. Multus docs: "The `v1.multus-cni.io/default-network` … is used to overwrite the cluster default network defined in the Multus config file."

Because Multus already runs the default delegate as `eth0`, pointing the default at *our* NAD means the pod's single primary interface is our CNI — there is no separate cluster-default eth0. Requirement: **the default delegate's NAD must return at least one IP** (IPAM in the NAD, or our binding/dataplane answers DHCP and we still return an IP from CNI ADD).

**KubeVirt integration (this is the clean path — no Multus daemonset reconfig needed):**
Set on the VMI network object:
```yaml
spec:
  template:
    spec:
      networks:
        - name: dataplane
          multus:
            networkName: <ns>/<our-nad>
            default: true          # <-- makes this the pod's default network
```
KubeVirt docs: "Setting this field on a Network in the VMI spec will cause the `v1.multus-cni.io/default-network` annotation to be added to the launcher pod." And: "a multus `default` network and a `pod` network type are mutually exclusive" and "The multus delegate chosen as default **must** return at least one IP address." The default multus interface "will be marked as `eth0` on the pod."

**Version constraints:** `multus.default` on the VMI has been supported since early KubeVirt (kubevirt/kubevirt PR #1807). Requires Multus deployed cluster-wide (thin or thick). No feature gate for the multus-default path itself.

### 2.2 KubeVirt network binding plugin — CHOSEN (domain/vNIC layer), leading hypothesis, partially

**Contract (what our components must implement / configure):**
A binding plugin is up to three optional layers:
1. **`domainAttachmentType`** — a built-in KubeVirt method that builds the libvirt domain interface XML against an existing tap/macvtap. Values: `tap`, and **`managedTap`** (v1.4+) which "sets the domain configuration to use a tap device, wired to the pod interface through a bridge … with all components created as needed. No IPAM." This is the zero-custom-code option and the one we choose for ①.
2. **`sidecarImage`** (optional) — a container running a gRPC server that mutates the domain via the `OnDefineDomain` hook (e.g. to serve DHCP in-pod, custom vNIC model). Not required for ① since our dataplane already answers DHCP.
3. **binding CNI plugin** (optional, referenced via `networkAttachmentDefinition`) — a CNI invoked by Multus **in addition to** the primary network CNI, to tweak the pod netns for the binding. Runs *after* the regular network CNI, not instead of it.

**Registration in the KubeVirt CR:**
```yaml
spec:
  configuration:
    network:
      binding:
        dataplane:                      # our binding name
          domainAttachmentType: managedTap
          # sidecarImage: <optional>
          # networkAttachmentDefinition: <optional binding-CNI NAD>
          # migration: { method: link-refresh }   # later, for live migration
```
Referenced from the VM interface:
```yaml
spec:
  template:
    spec:
      domain:
        devices:
          interfaces:
            - name: dataplane
              binding:
                name: dataplane
```

**Crucial finding — a binding plugin does NOT suppress the pod network.** KubeVirt docs describe the flow as: regular network CNI first, then the binding CNI. The primary `eth0` "remains present; the binding CNI performs supplementary pod-namespace modifications." Therefore the binding plugin is necessary for wiring the tap into the guest, but the *pod-network suppression* comes from §2.1, not from here.

**Version constraints / feature gate:**
- `NetworkBindingPlugins` feature gate: introduced ~v1.1; **Beta and enabled-by-default in v1.4**; **GA (no feature gate) in v1.5**.
- `domainAttachmentType` field: v1.1.1+. `managedTap` value: **v1.4+**.
- `networkAttachmentDefinition` / `sidecarImage`: v1.1.0+.
- `migration`: v1.2.0+.
- Requires Multus on the cluster (for the NAD path).

### 2.3 KubeVirt primary user-defined network (ovn-kubernetes primary-UDN) — REJECTED

**How it works:** Namespace labeled `k8s.ovn.org/primary-user-defined-network: ""`; a `UserDefinedNetwork` (or `ClusterUserDefinedNetwork`) CRD with `role: Primary` (Layer2/Layer3); VM interface uses `binding.name: l2bridge`; the VM gets its IP via DHCP from ovn. Requires OpenShift ≥ 4.18 / recent ovn-kubernetes.

**Why rejected:**
- **ovn-kubernetes-specific.** The `UserDefinedNetwork` CRD, the `role: Primary` semantics, and the `l2bridge` binding are implemented by ovn-kubernetes; there is no pluggable interface to substitute our eBPF dataplane. The primary-UDN and cluster-default attachment even happen "within the same CNI ADD call" inside ovn-k.
- **It does not remove `eth0`.** With primary-UDN the virt-launcher pod's network-status shows **both** `eth0` (cluster-default) and `ovn-udn1` (the UDN, marked default). The cluster-default is "infrastructure-locked" (healthcheck-only, isolation ACLs), not absent. That violates our "no pod network at all" requirement.
- Adopting it would mean adopting ovn-kubernetes — the exact thing this platform replaces.

---

## 3. Decision

**Chosen mechanism:** Multus **default-network delegation** (via KubeVirt `networks[].multus.default: true`) to make our CNI the pod's sole `eth0`, **plus** a KubeVirt **network binding plugin** using the built-in **`managedTap`** domain attachment to wire that interface into the guest VM.

**Exact annotations / feature gates / fields:**
- Pod annotation (rendered by KubeVirt, we do not set it by hand): `v1.multus-cni.io/default-network: <ns>/<our-nad>`.
- KubeVirt CR: `spec.configuration.network.binding.dataplane.domainAttachmentType: managedTap`.
- KubeVirt feature gate `NetworkBindingPlugins` — **enable it** if on v1.4; not needed on v1.5+ (GA).
- VMI: `networks[].multus.default: true` + `interfaces[].binding.name: dataplane`.

**Version floor:**
- **KubeVirt ≥ v1.4** (for `managedTap`; feature gate Beta/default). Prefer **≥ v1.5** so `NetworkBindingPlugins` is GA (no gate to manage). Pin the e2e/kind harness to v1.5.x.
- **Multus** (thick or thin) deployed cluster-wide. Any recent release (default-network annotation is long-standing).
- **CDI** — required only for the VM disk import in the e2e; not part of the networking mechanism. Any version matching the chosen KubeVirt (CDI ≥ v1.60 tracks KubeVirt ≥1.4).

**Concrete steps our components must perform:**

*Our CNI (`cni/`, invoked by Multus as the default delegate for our NAD):*
1. On `ADD`: dial the local `flowplane` `DataplaneNode` socket, call `AttachInterface{netns, vni, mac?, requested_ips?}`.
2. Create the pod-side interface named **`eth0`** (Multus default → eth0) in the pod netns and program the eBPF endpoint for it.
3. Return a valid CNI `Result` with **at least one IP** (required for a default network) + gateway + routes, so Multus accepts it as the pod IP.
4. On `DEL`: `DetachInterface`.

*The `managedTap` binding (built-in KubeVirt):* creates the tap + bridge over our `eth0` and generates the domain XML. **No code from us for ①.** (A custom sidecar becomes relevant only if we later want in-pod DHCP or migration link-refresh instead of dataplane-served DHCP.)

*Node agent (`flowplane`):* serve `AttachInterface`/`DetachInterface`/`ConfigureNetwork`; program overlay/DHCP/ARP-ND for the attached endpoint (already the plan's §5.1–5.2).

*Cluster bring-up (`hack/`):* install KubeVirt v1.5.x (enable `NetworkBindingPlugins` if <1.5), Multus, CDI; register the `dataplane` binding in the KubeVirt CR; create our `NetworkAttachmentDefinition` referencing our CNI binary.

**Open risk to retire in task 2:** confirm empirically that `multus.default: true` + `binding.name: managedTap` compose cleanly on a **non-ovn** cluster (all published `managedTap` examples pair it with `multus.default` for the *primary pod interface*, which is exactly our case, but the concrete combo on a plain bridge/kind cluster is what the deferred proof below verifies). Confidence: high that this is the right design; medium that no small integration wrinkle (e.g. exact IP/route the default delegate must return, or a `managedTap`+bridge MTU detail) surfaces on first boot.

---

## 4. Component contract summary (for the next plan)

| Layer | Owner | Mechanism | Our work for ① |
|---|---|---|---|
| Pod primary interface = our CNI, no cluster eth0 | Multus | `networks[].multus.default: true` → `v1.multus-cni.io/default-network` | Ship a NAD + our CNI as the default delegate; return an IP |
| Tap into guest VM | KubeVirt | binding `domainAttachmentType: managedTap` | Register binding in KubeVirt CR; no code |
| Endpoint/overlay/DHCP program | `flowplane` | `DataplaneNode` gRPC | Implement `AttachInterface` (plan §5.1–5.2) |
| DHCP to guest | dataplane | eBPF DHCP responder (already built) | Reuse |

---

## 5. Key sources

- KubeVirt — Network Binding Plugins (user guide): https://kubevirt.io/user-guide/network/network_binding_plugins/
- KubeVirt — network-binding-plugin design doc (regular-CNI-then-binding-CNI flow; contract): https://github.com/kubevirt/kubevirt/blob/main/docs/network/network-binding-plugin.md
- KubeVirt — Interfaces and Networks (`multus.default=true`, mutually exclusive with `pod`, must return an IP, marked eth0): https://kubevirt.io/user-guide/network/interfaces_and_networks/
- KubeVirt PR #13024 — `managedTap` domainAttachmentType (tested on primary pod interface via Multus default flag): https://github.com/kubevirt/kubevirt/pull/13024
- KubeVirt PR #1807 — set Multus default network via annotation: https://github.com/kubevirt/kubevirt/pull/1807
- Multus — configuration reference (`clusterNetwork`, `v1.multus-cni.io/default-network` overrides cluster default): https://k8snetworkplumbingwg.github.io/multus-cni/docs/configuration.html
- OVN-Kubernetes — UserDefinedNetwork (role: Primary; ovn-specific): https://ovn-kubernetes.io/features/user-defined-networks/user-defined-networks/
- Red Hat Developer — native network segmentation for virt (primary-UDN keeps eth0 infra-locked; `l2bridge`; ovn-specific, OCP ≥4.18): https://developers.redhat.com/articles/2025/05/01/native-network-segmentation-virtualization-workloads
- KubeVirt v1.4 release (binding plugins → Beta, `managedTap`): https://kubevirt.io/2024/KubeVirt-v1-4.html

---

## 6. Manual proof — DEFERRED (best-effort skip, per task Step 3)

**Environment at spike time:** Docker running; Go 1.26; network available. **`kind` not installed**, and no KubeVirt/Multus/CDI cluster present. A faithful proof requires installing kind, standing up a cluster, and installing KubeVirt + Multus + CDI + a container-disk VM — well beyond the "do not fight environment setup" budget for a spike whose decision is already unambiguous from authoritative docs. **Deferred to task 2's kind e2e harness**, where this bring-up is a first-class deliverable anyway.

Confidence in the decision without the proof: **high** on mechanism selection; the proof exists to catch integration wrinkles (exact IP/route the default delegate must return; `managedTap` bridge/MTU details), not to change the decision.

### Exact YAML + commands to run when the harness exists

For the spike stand-in, use **stock bridge CNI** as the "our CNI" placeholder (real CNI arrives in task 4). The assertion — *virt-launcher pod has exactly one interface and it is NOT the cluster-default pod network* — is CNI-agnostic.

```bash
# 0. tools
go install sigs.k8s.io/kind@v0.29.0            # or download the kind binary
kind create cluster --name udn-spike

# 1. Multus (thick) + CNI plugins (bridge/host-local ship with the plugins image)
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset-thick.yml

# 2. KubeVirt v1.5.x (managedTap GA, NetworkBindingPlugins GA)
export KV=v1.5.0
kubectl apply -f https://github.com/kubevirt/kubevirt/releases/download/${KV}/kubevirt-operator.yaml
kubectl apply -f https://github.com/kubevirt/kubevirt/releases/download/${KV}/kubevirt-cr.yaml
kubectl -n kubevirt wait kv/kubevirt --for=condition=Available --timeout=10m
# kind has no KVM: enable emulation
kubectl -n kubevirt patch kubevirt kubevirt --type=merge \
  -p '{"spec":{"configuration":{"developerConfiguration":{"useEmulation":true}}}}'
```

```yaml
# 3. register the managedTap binding in the KubeVirt CR
apiVersion: kubevirt.io/v1
kind: KubeVirt
metadata: { name: kubevirt, namespace: kubevirt }
spec:
  configuration:
    network:
      binding:
        dataplane:
          domainAttachmentType: managedTap
    # For KubeVirt < v1.5 also add:
    # developerConfiguration: { featureGates: ["NetworkBindingPlugins"] }
```

```yaml
# 4. NAD = the pod's default network (stand-in: stock bridge + host-local IPAM)
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata: { name: dataplane-net, namespace: default }
spec:
  config: |
    {
      "cniVersion": "0.3.1",
      "name": "dataplane-net",
      "plugins": [
        { "type": "bridge", "bridge": "dpbr0", "isGateway": true,
          "ipam": { "type": "host-local", "subnet": "10.99.0.0/24",
                    "gateway": "10.99.0.1" } }
      ]
    }
```

```yaml
# 5. VM: multus.default:true (no pod: {}) + managedTap binding
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata: { name: udn-spike, namespace: default }
spec:
  runStrategy: Always
  template:
    spec:
      domain:
        devices:
          interfaces:
            - name: dataplane
              binding: { name: dataplane }
          disks:
            - name: containerdisk
              disk: { bus: virtio }
        resources: { requests: { memory: 256Mi } }
      networks:
        - name: dataplane
          multus:
            networkName: default/dataplane-net
            default: true                     # <-- sole primary; no pod network
      volumes:
        - name: containerdisk
          containerDisk: { image: quay.io/kubevirt/cirros-container-disk-demo }
```

```bash
# 6. ASSERTIONS
kubectl wait vmi/udn-spike --for=condition=Ready --timeout=5m
POD=$(kubectl get pod -l kubevirt.io/created-by -o name | head -1)

# (a) launcher pod carries our NAD as the DEFAULT and NOT the cluster pod network:
kubectl get $POD -o jsonpath='{.metadata.annotations.v1\.multus-cni\.io/default-network}'
#   expect: default/dataplane-net
kubectl get $POD -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}' | jq
#   expect: exactly ONE entry, "default": true, name "default/dataplane-net";
#           NO entry for the kind/kindnet cluster-default network.

# (b) inside the netns, eth0 is on our 10.99.0.0/24 (bridge), not the pod CIDR:
kubectl exec $POD -c compute -- ip -o addr show eth0
#   expect: inet 10.99.0.x/24  (our subnet)  -> confirms no cluster pod-network eth0
```

**Pass criteria:** network-status shows a single default attachment = our NAD; no cluster-default (kindnet) interface; `eth0` carries our subnet. That proves "custom CNI is the VM's only primary network, no pod network."
