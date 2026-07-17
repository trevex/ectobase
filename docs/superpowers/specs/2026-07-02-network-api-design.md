# Network API (VPC / NIC / Policy) — Design

**Status:** Draft (brainstorm output) — model agreed; feeds sub-project ② (aggregated API) and reworks parts of ①.
**Date:** 2026-07-02
**Parent vision:** `docs/superpowers/specs/2026-07-02-multicluster-kubevirt-dataplane-design.md`
**Sub-project ① spec:** `docs/superpowers/specs/2026-07-02-subproject-01-vm-dataplane-attach-design.md` (its Task 6 IPAM is reworked by this doc)

---

## 1. Summary

The user-facing network API for the platform: a **lean, hybrid** CRD set that lets tenants express overlay networking on our eBPF dataplane. Inspired by metalnet/ironcore-net, but **improved**: the `NetworkInterface` stays thin (identity + user-specified overlay IPs), and shareable concerns (firewall, LB, NAT, peering, floating IPs) are **separate, selector/ref-based resources**. Capabilities covered: **VPC, VPC Peering, Distributed Firewall, LB, NAT, VIP, multi-NIC per VM.**

## 2. Key principles

- **Overlay IPs are user-specified** on the NIC (`spec.ips`) — the platform does **not** allocate them.
- **The only allocation is the underlay** — each NIC endpoint gets an IPv6 `/128` from the **host's underlay `/64`**, which in a proper cluster is the **node's kubelet IP** (its loopback/dummy identity in the unnumbered IPv6-only BGP fabric). Resolution precedence (implemented in `flowplane serve`): (1) an explicit `--local-underlay` flag **overrides** — for tests / hosts without a fabric loopback; (2) the kubelet node IP from the downward-API `HOST_IP`/`NODE_IP` env (`status.hostIP`); (3) inference from the `lo`/`dummy*` fabric-loopback address. No CRD. This is what "IPAM" means here; it replaces sub-project ①'s placeholder overlay-host allocator.
- **Overlay IPs are free-form** for now (no `VPC`-level range validation).
- **VNI is a global space, allocated by the central cluster** (`VPC.status.vni`); when `VPC`s are pooled/synced from central, allocation happens there. Single-cluster (degenerate) = local. User-overridable via optional `spec.vni`.
- **Hybrid decomposition:** thin NIC; VIP/NAT/LB/Firewall/Peering are their own resources referencing NICs/VPCs by ref or **label selector** (k8s-idiomatic, shareable).
- **Improve on metalnet, don't copy:** mutual-consent peering (not raw VNI int lists), selector-based policy/LB (not embedded per-NIC), floating VirtualIP (not inline).

API group: **`net.ectobase.dev/v1alpha1`** (project **ectobase**).

## 3. Resource set

### 3.1 `VPC` — isolation domain (the overlay network)
```yaml
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata: { name: prod, labels: { env: prod } }
spec:
  vni: 0                 # optional; 0/absent => central-allocated (global VNI space)
  defaultPolicy: Allow   # optional; Allow (k8s semantics) | Deny (VPC-wide default-deny); inherits the global default
  # routingMode: Layer3  # (default; Layer2 future)
status:
  vni: 100
  state: Ready
```
The underlay `/64` is **inferred per-host** by the node agent (loopback/dummy primary IPv6 = kubelet IP in the unnumbered IPv6 BGP fabric), not a VPC field; VPCs are isolated by VNI on that shared underlay.

### 3.2 `NetworkInterface` — thin NIC (attaches to a VM)
```yaml
kind: NetworkInterface
metadata: { name: web-0-nic0, labels: { app: web, role: frontend } }
spec:
  vpcRef: { name: prod }
  ips: ["10.0.0.10", "2001:db8::10"]   # USER-specified overlay (v4 and/or v6)
  # nodeName: set by the scheduler
status:
  vni: 100
  underlayRoute: 2001:db8:fefe::a1b2    # ALLOCATED /128 from the underlay /64
  port: { type: tap, name: dtapvf_0 }   # or { type: vf, pciAddress: {...} }
  state: Ready
```
Multi-NIC = several `NetworkInterface`s referenced by one VM (§5). No embedded LB/NAT/FW/VIP.

### 3.3 `VPCPeering` — mutual consent
```yaml
kind: VPCPeering
metadata: { name: prod-to-shared }
spec:
  vpcRef: { name: prod }
  peerVpcRef: { name: shared, namespace: infra }   # cross-ns/tenant allowed
  exposedPrefixes: ["10.0.0.0/16"]                  # optional filter of what's reachable
status:
  state: Pending    # -> Ready only when a MATCHING peering exists on the other side
```
Peering is active only when both `prod→shared` and `shared→prod` exist (mutual consent). Improves on metalnet's one-sided `peeredIDs`.

### 3.4 `NetworkPolicy` — distributed firewall (VPC + selectors)
```yaml
kind: NetworkPolicy
metadata: { name: frontend-policy }
spec:
  vpcRef: { name: prod }
  interfaceSelector: { matchLabels: { role: frontend } }   # which NICs this applies to
  ingress:
    - from:
        - interfaceSelector: { matchLabels: { role: lb } }
        - cidr: "10.0.0.0/24"
      ports: [{ protocol: TCP, port: 443 }]
      action: Allow
  egress:
    - to: [{ cidr: "0.0.0.0/0" }]
      action: Allow
```
k8s-NetworkPolicy semantics (selecting an interface implies default-deny for that direction). Enforced distributed in the dataplane (conntrack/FW already exist).

**Default posture:** by default an interface is open until a policy selects it (k8s semantics). A **global cluster setting `defaultDeny: true`** (and per-`VPC` override `spec.defaultPolicy: Deny`) flips to deny-by-default — all traffic dropped unless explicitly allowed.

### 3.5 `LoadBalancer`
```yaml
kind: LoadBalancer
metadata: { name: web-lb }
spec:
  vpcRef: { name: prod }
  vip: "10.0.100.1"                       # or platform-allocated
  targetSelector: { matchLabels: { app: web } }   # selector-based (improvement)
  ports: [{ protocol: TCP, port: 443, targetPort: 8443 }]
status: { vip: 10.0.100.1, state: Ready }
```

### 3.6 `NATGateway`
```yaml
kind: NATGateway
metadata: { name: prod-nat }
spec:
  vpcRef: { name: prod }
  externalIPs: ["203.0.113.5"]
  interfaceSelector: { matchLabels: {} }   # NICs that SNAT through it
  portsPerInterface: 2048
status: { state: Ready }
```

### 3.7 `VirtualIP` — floating IP (movable)
```yaml
kind: VirtualIP
metadata: { name: web-float }
spec:
  vpcRef: { name: prod }
  ip: "10.0.200.1"                                        # or allocated
  targetRef: { kind: NetworkInterface, name: web-0-nic0 } # re-pointable => failover
status: { ip: 10.0.200.1, boundTo: web-0-nic0, state: Ready }
```
Separate resource (not inline `NIC.virtualIP`) so it can move between NICs for failover.

## 4. Capability → resource map

| Capability | Resource(s) | Improvement over metalnet |
|---|---|---|
| VPC | `VPC` | VNI central-allocated (global space), not user-picked int |
| VPC Peering | `VPCPeering` | mutual-consent + refs, not one-sided `peeredIDs` |
| Distributed Firewall | `NetworkPolicy` | selector-based, shareable, not per-NIC embedded |
| LB | `LoadBalancer` | selector targets |
| NAT | `NATGateway` | selector membership |
| VIP | `VirtualIP` | floating/movable, not inline |
| multi-NIC | multiple `NetworkInterface` | thin NIC |

## 5. NIC ↔ VM linkage

The KubeVirt VMI references `NetworkInterface` CRDs **by name** (one per VMI interface). The CNI/binding (sub-project ①) resolves: VMI interface → `NetworkInterface` → `vpcRef`→VNI + `spec.ips` (overlay) + allocated `status.underlayRoute`. Multi-NIC falls out naturally (several interfaces → several `NetworkInterface`s).

## 6. Impact on sub-project ①

- **Task 6 IPAM reworked:** from "allocate overlay host from a `/24`" → **"allocate an underlay `/128` from the dataplane `/64`."** The committed `10df2ff` allocator is unwired (dead code) and gets replaced.
- **`AttachInterface` contract (dataplane.v1):** the node agent receives `{ vni, overlay_ips }` (resolved from the `NetworkInterface` CRD) and **allocates + returns the underlay `/128`** (`underlay_route`). The proto's `AttachInterfaceResponse` gains an `underlay_route` field; `vni`/`requested_ips` already exist. Programs overlay encap for `{vni, overlay_ip → underlay_route}`.
- ①'s "real attach" (former Task 7) is rewritten against this contract once this model is committed.

## 7. Relationship to the platform

This is the core of **sub-project ② (the aggregated API + logical model)** surfacing early because ① depends on it. These types are authored for the aggregated apiserver (`apiserver-kit`, per the vision doc). The controllers/poollets that reconcile them onto the dataplane are later sub-projects; for ① single-cluster, a minimal controller (or the CNI reading the CRDs directly) suffices.

## 8. Resolved decisions & residual questions

**Resolved (2026-07-02):**
- **API group** = `net.ectobase.dev/v1alpha1` (project **ectobase**).
- **Underlay `/64`** = pre-allocated per host in an unnumbered IPv6-only BGP fabric (loopback/dummy = kubelet primary IP); the node agent **infers** it — no config or CRD.
- **Overlay IPs** = free-form (no `VPC` range validation) for now.
- **VNI** = global space, allocated by the **central cluster** (single-cluster = local).
- **Default firewall posture** = open-until-selected (k8s semantics), with a **global `defaultDeny` toggle** + per-`VPC` `spec.defaultPolicy` override.

**Residual:**
- How the central **VNI allocator** syncs allocations down to pooled/attached clusters (sub-project ②/③).
- Exact per-host `/64` **inference** — which interface/label identifies the fabric loopback, and the fallback if ambiguous.
- **Go module path** — code is currently under `github.com/trevex/flowplane`; whether to re-root under an `ectobase` module is a separate repo decision (the API *group* is `net.ectobase.dev` regardless).
