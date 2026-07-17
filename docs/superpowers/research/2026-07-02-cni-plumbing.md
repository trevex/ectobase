# CNI plumbing + node-install decision for Phase B — research spike

**Status:** DONE — decision made; **manual proof RAN (plain pod)** and passed (see §5).
**Date:** 2026-07-02 (research/experiment 2026-07-13)
**Phase:** B — KubeVirt VM on the eBPF dataplane, custom SDN as the *only* interface.
**Parent spec:** `docs/superpowers/specs/2026-07-02-multicluster-kubevirt-dataplane-design.md`
**Sibling spikes:**
- `docs/superpowers/research/2026-07-02-primary-udn-mechanism.md` — settled the **KubeVirt side** (Multus-default + `managedTap`, KubeVirt ≥1.5). READ IT; this doc is the **CNI's** k8s-resolution + node-install plumbing.
- `docs/superpowers/specs/2026-07-02-network-api-design.md` — defines the `VPC` / `NetworkInterface` CRDs this spike resolves against.

---

## 0. TL;DR decision

Our CNI is the Multus **default delegate** for the virt-launcher pod (via `v1.multus-cni.io/default-network`, rendered by KubeVirt's `networks[].multus.default: true`). On `ADD` it must:

1. Read pod identity from **`CNI_ARGS`** (`K8S_POD_NAME`, `K8S_POD_NAMESPACE`, `K8S_POD_UID`), which Multus forwards to the delegate unchanged.
2. Using an **in-cluster ServiceAccount token** (installed on the node as a kubeconfig by our CNI-installer DaemonSet), `GET` the pod object and read the annotation **`net.ectobase.dev/network-interface: <ns>/<name>`** naming a pre-created **`NetworkInterface`** CRD. **CHOSEN over a "direct API-derived" query** — the annotation is an explicit, immutable, race-free binding set at VM-create time.
3. `GET` that `NetworkInterface` → `spec.ips` (overlay IPs) + `vpcRef` → `VPC.status.vni`.
4. Dial the node-local `flowplane` `DataplaneNode` gRPC and call `AttachInterface{netns, vni, overlay_ips, mac?}`; receive `underlay_route` (`/128`).
5. Wire `eth0` in the pod netns, program the eBPF endpoint, and **return a CNI `Result` with ≥1 IP** (mandatory for a Multus default network).

Node-install: a **CNI-installer DaemonSet** copies our CNI binary into `/opt/cni/bin` and writes a kubeconfig (SA token) into `/etc/cni/net.d/` on every node. The NAD and `NetworkInterface`/`VPC` CRDs are ordinary cluster objects (applied via manifests/controller), not node-local files.

---

## 1. Step 1 — CNI ↔ pod plumbing (with citations)

### 1.a How a default-delegate obtains pod identity and reads annotations / the k8s API from the node

**Pod identity via `CNI_ARGS`.** The kubelet/CRI invokes the CNI with a set of env vars: `CNI_COMMAND`, `CNI_CONTAINERID`, `CNI_NETNS`, `CNI_IFNAME`, `CNI_PATH`, and **`CNI_ARGS`** — a `;`-separated `key=value` list. For k8s pods it carries the pod coordinates, e.g.:

```
CNI_ARGS="IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=udn-spike;K8S_POD_INFRA_CONTAINER_ID=…;K8S_POD_UID=4534d3d9-…"
```

`K8S_POD_UID` was added specifically to disambiguate a name reused across a fast delete/recreate (kubernetes#62900) — our CNI should include it when reconciling. Sources: CNI spec / kubernetes network-plugins docs; kubernetes#62900.

**Reading annotations = a k8s API `GET` from the node.** The CNI spec has no channel for arbitrary pod annotations; a plugin that needs them must **`GET` the pod object from the API server** using name+namespace from `CNI_ARGS`. (CNI ≥0.4.0 / config-version 0.2.0 *can* inject a fixed allow-list of annotations into the runtime config, but that is opt-in per-annotation and not how meta-CNIs resolve arbitrary CRDs — we do the direct `GET`.) Sources: kubernetes network-plugins docs; kubernetes#69882.

**Credentials on the node: in-cluster SA token dropped as a kubeconfig.** The established pattern (Calico, Multus) is a **kubeconfig file written onto each node** referencing a **ServiceAccount bearer token + cluster CA**, e.g. Calico's `"kubernetes": { "kubeconfig": "/etc/cni/net.d/calico-kubeconfig" }`. Multus (thick) uses a ServiceAccount named `multus`; its daemon holds the SA token and answers delegate requests over a unix socket. So: the token is an **in-cluster SA token**, materialised **as a kubeconfig on the node** (not the kubelet's admin kubeconfig, and not a user-supplied one). Sources: Calico "Install CNI plugin" hardway docs; Multus how-to-use (kubeconfig at `/etc/cni/net.d/multus.d/multus.kubeconfig` in thin mode).

### 1.b How Multus passes the default-network delegate its config + runtime args

- **Selecting the default delegate.** The pod annotation **`v1.multus-cni.io/default-network: <ns>/<nad>`** overrides Multus's cluster-wide `clusterNetwork` **for that pod only**; the referenced `NetworkAttachmentDefinition`'s `spec.config` becomes the delegate config for the pod's `eth0`. Pods without the annotation keep `clusterNetwork`. Source: Multus how-to-use / configuration reference.
- **KubeVirt sets that annotation for us** from `networks[].multus.default: true` (see the primary-UDN spike §2.1). We never hand-set it.
- **Runtime args reach the delegate.** In `delegateAdd`, Multus reads `CNI_ARGS` (`os.Getenv("CNI_ARGS")`) and **passes it to the delegate's exec environment**, and also parses `K8S_POD_NAME`/`K8S_POD_NAMESPACE`/`K8S_POD_UID` into the delegate's `RuntimeConfig`/`rt.Args`. **Net effect: our delegate CNI receives the same `K8S_POD_*` values in its own `CNI_ARGS`** — which is exactly what makes the §1.a `GET` possible. Source: multus-cni `multus/multus.go` (`delegateAdd`), `pkg/types/conf_test.go`.
- **Thick vs thin.** Thick Multus splits into a thin **`multus-shim`** binary in `/opt/cni/bin` (what the runtime execs) that RPCs to a per-node **multus-daemon** pod over a unix socket; the daemon holds the SA token and does the API lookups + delegate exec. The delegate (our CNI) is still exec'd as a normal binary from `/opt/cni/bin` with `CNI_ARGS` set. Observed on the node: `/etc/cni/net.d/00-multus.conf` `{"type":"multus-shim","clusterNetwork":"/host/etc/cni/net.d/10-kindnet.conflist", …}`.

### 1.c How a custom CNI binary + NAD + credentials get onto nodes

**CNI-installer DaemonSet** — the universal pattern (Multus, Calico, Istio-CNI, travelping/cni-installer, k0s cni-node): a privileged DaemonSet mounts the host's `/opt/cni/bin` and `/etc/cni/net.d`, then on start **copies the plugin binary into `/opt/cni/bin`** and **writes CNI config / a kubeconfig into `/etc/cni/net.d`** (env-substituted). `INSTALL_DIR` defaults to `/opt/cni/bin`, `CONF_DIR` to `/etc/cni/net.d`. The SA token is projected into the installer pod and written into the on-node kubeconfig. Sources: travelping/cni-installer, k0sproject/cni-node, Multus daemonset, Istio CNI.

- **The NAD** is a normal namespaced CR (`k8s.cni.cncf.io/v1 NetworkAttachmentDefinition`) applied via manifest/controller — **not** a node-local file. Multus resolves it from the API at ADD time.
- **`NetworkInterface` / `VPC`** are likewise cluster CRs (`net.ectobase.dev/v1alpha1`); the CNI reads them via the API.
- **Kind specifics (found empirically):** kind nodes ship only `host-local loopback portmap ptp passthru` in `/opt/cni/bin` — **no `bridge`**. So even the stock-bridge stand-in needs a binary drop; our real CNI installer covers this for production. (In the proof we `docker cp`'d `bridge` in, standing in for the DaemonSet.)

---

## 2. Step 2 — Decision record

### 2.1 Resolution mechanism — pod annotation → `NetworkInterface` CRD (CHOSEN)

On ADD our CNI resolves the VM's `{vni, overlay ips}` via:

```
pod.annotations["net.ectobase.dev/network-interface"] = "<ns>/<name>"   # names a NetworkInterface CR
  → NetworkInterface.spec.ips           # overlay IPs (user-specified; see network-api-design §3.2)
  → NetworkInterface.spec.vpcRef → VPC.status.vni   # the overlay VNI (network-api-design §3.1)
```

**Why the annotation, not a "direct API query":**
- **Explicit, immutable binding** authored at VM-create time — no guessing which of a pod's labels maps to which NIC (multi-NIC falls out: one annotation value per interface, or a list).
- **Race-free / restart-safe** — the `K8S_POD_UID` in `CNI_ARGS` plus the named CR give an idempotent key for reconcile on delete/recreate.
- **Decouples identity from IPAM** — matches network-api-design's "overlay IPs are user-specified on the NIC, platform does not allocate them"; the CNI just reads `spec.ips`.
- The `NetworkInterface`'s `status` (`underlayRoute`, `port`, `state`) is where the dataplane attach result is recorded, closing the loop.

KubeVirt's VMI already references the `NetworkInterface` by name (network-api-design §5); the virt-launcher pod carries that reference as the annotation above (set by our KubeVirt integration / a mutating step), so the CNI's job is a pure lookup.

### 2.2 Node-install approach (CHOSEN)

A privileged **CNI-installer DaemonSet** per node:
1. Copies our CNI binary → `/opt/cni/bin/<our-cni>`.
2. Writes a kubeconfig with the **in-cluster SA token** (projected `serviceAccountToken` volume) + cluster CA → `/etc/cni/net.d/<our-cni>.kubeconfig`; the CNI config references it (`"kubeconfig": "…"`), mirroring Calico.
3. RBAC: a ServiceAccount + ClusterRole granting `get` on `pods` and `get/list/watch` on `networkattachmentdefinitions`, `networkinterfaces`, `vpcs`.
4. Multus (thick) is a **prerequisite** DaemonSet (installs `multus-shim` + daemon); our NAD points its single delegate at our CNI. The `bridge`-less kind node confirms the installer must also ship any helper binaries our CNI needs.

### 2.3 Concrete ADD / DEL steps the CNI must perform

**ADD:**
1. Parse `CNI_ARGS` → `K8S_POD_{NAME,NAMESPACE,UID}`; read `CNI_NETNS`, `CNI_IFNAME` (=`eth0` for the default delegate).
2. `GET pods/<ns>/<name>` (SA-token kubeconfig); read annotation `net.ectobase.dev/network-interface`.
3. `GET networkinterfaces/<ns>/<name>` → `spec.ips`, `spec.vpcRef`; `GET vpcs/<vpcRef>` → `status.vni`.
4. Dial node-local `flowplane` `DataplaneNode` gRPC → `AttachInterface{netns: CNI_NETNS, vni, overlay_ips: spec.ips, mac?}`; get `underlay_route`.
5. Create/move the pod-side `eth0` into `CNI_NETNS`; program the eBPF endpoint.
6. (Optionally) patch `NetworkInterface.status` with `underlayRoute`/`port`/`state: Ready`.
7. Return a CNI `Result` (cniVersion, `interfaces`, `ips` with **≥1 IP** — mandatory for a Multus default network — gateway, routes).

**DEL:**
1. Parse `CNI_ARGS` (name/ns/uid) + `CNI_NETNS`.
2. `AttachInterface`'s inverse: `DetachInterface{netns/uid, vni}` on `flowplane` (idempotent — must succeed if already gone).
3. Tear down `eth0` / eBPF endpoint; free the underlay `/128`. Return success even if the pod/CR is already deleted (best-effort, key off `K8S_POD_UID`).

**CHECK** (optional but recommended): verify the endpoint still programmed for `{uid, vni}`.

---

## 3. Component contract summary

| Layer | Owner | Mechanism | Our work for Phase B |
|---|---|---|---|
| Pod primary iface = our CNI, no cluster `eth0` | Multus | `v1.multus-cni.io/default-network` (from KubeVirt `multus.default: true`) | Ship NAD → our CNI as sole delegate; return ≥1 IP |
| Pod identity → CNI | kubelet/CRI → Multus | `CNI_ARGS` `K8S_POD_{NAME,NAMESPACE,UID}` forwarded to delegate | Parse in ADD/DEL |
| Identity → `{vni, overlay ips}` | our CNI | pod annotation → `NetworkInterface` → `vpcRef`→`VPC.status.vni` | Implement API reads (SA token) |
| Node install | CNI-installer DaemonSet | copy binary → `/opt/cni/bin`; SA-token kubeconfig → `/etc/cni/net.d` | Build installer image + RBAC |
| Endpoint / overlay program | `flowplane` | `DataplaneNode` gRPC `AttachInterface`/`DetachInterface` | Implement (network-api-design §6) |
| Tap into guest VM | KubeVirt | binding `domainAttachmentType: managedTap` | Register binding; no code (primary-UDN spike) |

---

## 4. Key sources

- CNI spec / Kubernetes — Network Plugins (`CNI_ARGS`, env contract): https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/
- kubernetes#62900 — add `K8S_POD_UID` to CNI runtime args (delete/recreate disambiguation): https://github.com/kubernetes/kubernetes/issues/62900
- kubernetes#69882 — pass pod annotations to CNI (why plugins otherwise `GET` the pod): https://github.com/kubernetes/kubernetes/issues/69882
- Calico — Install CNI plugin (on-node `kubeconfig` with SA token: `"kubernetes":{"kubeconfig":"/etc/cni/net.d/calico-kubeconfig"}`): https://docs.tigera.io/calico/latest/getting-started/kubernetes/hardway/install-cni-plugin
- Multus — how-to-use (`v1.multus-cni.io/default-network`, kubeconfig path `/etc/cni/net.d/multus.d/multus.kubeconfig`): https://github.com/k8snetworkplumbingwg/multus-cni/blob/master/docs/how-to-use.md
- Multus — configuration reference (`clusterNetwork` default, kubeconfig for CRD lookups): https://k8snetworkplumbingwg.github.io/multus-cni/docs/configuration.html
- Multus source — `multus/multus.go` `delegateAdd` forwards `CNI_ARGS` to the delegate: https://github.com/k8snetworkplumbingwg/multus-cni/blob/master/multus/multus.go
- travelping/cni-installer — DaemonSet copies binaries to `/opt/cni/bin`, configs to `/etc/cni/net.d`: https://github.com/travelping/cni-installer
- k0sproject/cni-node — CNI binary installer container: https://github.com/k0sproject/cni-node
- Multus thick daemonset (installer + per-node daemon + shim): https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset-thick.yml

---

## 5. Step 3 — Manual proof (RAN — plain pod, PASSED)

**Environment:** kind v0.32 (k8s v1.36.1), Docker, Multus **thick** (`ghcr.io/k8snetworkplumbingwg/multus-cni:snapshot-thick`). A **plain pod** stand-in (per task: acceptable faster proxy); stock **bridge** CNI stands in for our real CNI (the assertion — *sole non-cluster-default interface* — is CNI-agnostic). KubeVirt/VM proof left to Phase B's e2e harness (design already settled by the primary-UDN spike).

### Commands run

```bash
sudo env "PATH=$HOME/go/bin:$PATH" kind create cluster --name cni-spike        # k8s v1.36.1
kubectl apply -f .../multus-cni/master/deployments/multus-daemonset-thick.yml  # Multus thick
# kind nodes ship NO `bridge` binary → drop it in (stands in for the CNI-installer DaemonSet):
curl -sL .../containernetworking/plugins/releases/download/v1.5.1/cni-plugins-linux-amd64-v1.5.1.tgz | tar xz ./bridge
docker cp bridge cni-spike-control-plane:/opt/cni/bin/bridge
kubectl apply -f -   # NAD `default/dataplane-net` (bridge dpbr0 + host-local 10.99.0.0/24)
                     # + plain pod `udn-spike` annotated v1.multus-cni.io/default-network: default/dataplane-net
kubectl wait pod/udn-spike --for=condition=Ready --timeout=90s                 # -> condition met
```

NAD + pod manifests are inline in §5 of the primary-UDN spike (identical, minus the VM wrapper).

### Evidence (assertions passed)

**(a) default-network annotation present:**
```
$ kubectl get pod udn-spike -o jsonpath='{...v1\.multus-cni\.io/default-network}'
default/dataplane-net
```

**(b) `k8s.v1.cni.cncf.io/network-status` — SINGLE default attachment = our NAD, NO kindnet:**
```json
[{
  "name": "default/dataplane-net",
  "interface": "eth0",
  "ips": ["10.99.0.2"],
  "mac": "fe:97:57:25:5e:9e",
  "default": true,
  "dns": {}
}]
```
Exactly one entry, `default: true`, `name: default/dataplane-net`. **No `kindnet` / cluster-default entry.**

**(c) `eth0` on the bridge subnet, NOT the kindnet CIDR:**
```
$ ip netns exec <pod-ns> ip -o -4 addr show eth0
2: eth0  inet 10.99.0.2/24 brd 10.99.0.255 scope global eth0
$ kubectl get pod udn-spike -o jsonpath='{.status.podIP}'
10.99.0.2
```
kindnet's CIDR is `10.244.0.0/16` (verified: kindnet ds `POD_SUBNET=10.244.0.0/16`, node `10-kindnet.conflist` subnet `10.244.0.0/24`). The pod IP `10.99.0.2` is **not** in that range → **no cluster pod-network `eth0`**.

**Pass criteria met:** network-status = single default attachment = our NAD; **no kindnet interface**; `eth0` carries the bridge subnet. This proves *a pod comes up on a trivial custom CNI as the Multus default network with NO kindnet pod network* — the Phase B requirement, minus the KubeVirt wrapper.

---

## 6. Open / low-confidence items (human verification)

1. **Who sets `net.ectobase.dev/network-interface` on the virt-launcher pod?** KubeVirt renders `multus.default` → `v1.multus-cni.io/default-network`, but the `NetworkInterface`-naming annotation is **ours**. Options: (a) a small mutating webhook / VM controller copies it from the VMI spec onto the launcher pod; (b) encode `<ns>/<name>` directly and skip a webhook by making the NAD per-NIC. Decide in the Phase B plan. **Medium confidence.**
2. **Multi-NIC mapping.** For >1 interface, confirm whether one annotation with a list vs. one annotation per NAD (Multus secondary attachments each carrying their own arg) is cleaner. The default-delegate path handles the primary; secondaries use the `k8s.v1.cni.cncf.io/networks` list. **Medium.**
3. **Thick-Multus arg passthrough in-vivo.** Source review confirms `CNI_ARGS` reaches the delegate; the proof used bridge (which ignores args). Add an assertion in the e2e that our real CNI actually observes `K8S_POD_UID`. **Low risk, verify empirically.**
4. **RBAC least-privilege.** `get pods` cluster-wide is broad; consider scoping or a per-node informer cache. **Low.**
5. **`managedTap` + our CNI on a plain (non-ovn) cluster** — still the one integration wrinkle flagged by the primary-UDN spike; retire it in the VM e2e. **Medium.**
