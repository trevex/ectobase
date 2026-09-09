# Guided IPAM walkthrough: VPC, Subnet, VMs, LoadBalancer, NAT

This is a hands-on, copy-pasteable walkthrough for driving a live ectobase fabric
with the central IPAM model. It covers four steps:

1. Create a VPC and a Subnet (the VPC's address space).
2. Boot a VM in the VPC and watch the platform allocate its overlay IP.
3. Put a second VM behind a LoadBalancer (VIP drawn from an LBPool).
4. Give the VPC NAT egress to the WAN.

Everything is authored as intent on the dispatch (central) cluster. The platform
compiles that intent into per-workload `Compiled*` objects, syncs them to the compute
pool, and the datapath programs eBPF. The platform assigns overlay IPs and VIPs; users
declare address space (Subnet/LBPool) and the central allocators fill in the rest.

> Steps 1–2 (VPC/Subnet/VM overlay connectivity) are exercised by the live suite and
> work end-to-end. For steps 3–4, IPAM does allocate the VIP and NAT port-blocks and
> records LB membership / SNAT sources in the compiled `CompiledNIC`, and those
> allocations are observable via the status fields shown below, but the North-South
> edge control plane is not yet driven by the `LoadBalancer` / `NATGateway` CRDs.
> Actual WAN reachability is still programmed directly over the
> dataplane gRPC socket (see `test/lab/livetest/lb_test.go`,
> `nategress_test.go`). So a WAN client won't reach a VIP or egress from
> `kubectl apply` alone yet. The steps below verify the parts that are wired.

## 0. Prerequisites

Bring the lab up (see [local-fabric.md](local-fabric.md) for details) and, because we
boot VMs, deploy the KubeVirt tier on a pool:

```sh
make lab-up          # Talos fabric + dispatch/pool charts (includes the IPAM controllers)
make lab-tier2-up    # KubeVirt + CDI + vm-materializer on the compute pool
```

Set up kubeconfig aliases. `khub` is the dispatch (central) apiserver that holds all
authored intent; `k02`/`k03` are compute pools that hold the synced `Compiled*` twins and
the materialized Pods/VMs:

```sh
alias khub='kubectl --kubeconfig test/lab/build/ectobase/dispatch.kubeconfig'
alias k02='kubectl  --kubeconfig test/lab/build/ectobase/k02.kubeconfig'
alias k03='kubectl  --kubeconfig test/lab/build/ectobase/k03.kubeconfig'
```

All `khub apply` blocks below go to dispatch. Verify the API is up:

```sh
khub api-resources --api-group=net.ectobase.dev
# vpcs, subnets, networkinterfaces, loadbalancers, lbpools, natgateways, firewallpolicies, ...
```

## 1. Create a VPC and a Subnet

A VPC is an isolation domain identified by a VXLAN VNI. A Subnet gives it an
address range that overlay IPs are allocated from. (A VPC can hold several Subnets; a
NIC then names one via `subnetRef`. With exactly one Subnet, `subnetRef` is optional.)

```sh
khub apply -f - <<'EOF'
apiVersion: net.ectobase.dev/v1alpha1
kind: VPC
metadata:
  name: demo
  namespace: default
spec: {}                      # omit vni to auto-allocate from the central VNI space
---
apiVersion: net.ectobase.dev/v1alpha1
kind: Subnet
metadata:
  name: demo-sn0
  namespace: default
spec:
  vpcRef:
    name: demo
  v4Prefix: 10.10.0.0/24      # optional v6Prefix: fd00:10::/64
EOF
```

Verify the VPC got a VNI and the Subnet went Ready (the allocators drive both
automatically, with no manual status patching):

```sh
khub get vpc demo -o jsonpath='{.status.state} vni={.status.vni}{"\n"}'
# Ready vni=1000

khub get subnet demo-sn0 -o jsonpath='{.status.state} v4Total={.status.v4Total}{"\n"}'
# Ready v4Total=256
```

## 2. Boot a VM in the VPC with an auto-allocated overlay IP

A VM owns its NICs via `interfaceRefs`. Each VM NIC needs a MAC (KubeVirt's virtio
NIC must carry the same MAC). Leave `ips: []` to have the platform allocate an
address from the Subnet, or list an IP inside the Subnet to pin it (BYO).

We use an ephemeral cirros `image:` containerDisk here (no storage tier needed). Pin the
VM to a KubeVirt-capable pool with `clusterName` (use the pool where you ran
`make lab-tier2-up`; `k02` below).

```sh
khub apply -f - <<'EOF'
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata:
  name: app-0-nic0
  namespace: default
  labels:
    app: app                  # (labels are used later by LB/firewall selectors)
spec:
  vpcRef:   { name: demo }
  subnetRef: { name: demo-sn0 }   # optional: inferred when the VPC has one Subnet
  ips: []                     # empty => allocate from demo-sn0
  mac: "52:54:00:00:10:01"    # REQUIRED for a KubeVirt VM NIC
---
apiVersion: compute.ectobase.dev/v1alpha1
kind: VirtualMachine
metadata:
  name: app-0
  namespace: default
spec:
  clusterName: k02
  interfaceRefs:
    - name: app-0-nic0
  image: quay.io/kubevirt/cirros-container-disk-demo:latest
  runStrategy: RerunOnFailure
  resources:
    requests:
      cpu: "1"
      memory: 512Mi
EOF
```

Verify the allocation. The NIC status carries the authoritative
allocated address and the `Allocated` state that gates compilation:

```sh
khub get networkinterface app-0-nic0 \
  -o jsonpath='{.status.state} ips={.status.allocatedIPs}{"\n"}'
# Allocated ips=["10.10.0.1"]
```

Verify it compiled and synced to the pool. The compiled twin is named
`<namespace>-<nic>` and carries the allocated IP as `overlayIPs`; downstream never
sees Subnets or IPAM:

```sh
k02 get compilednic default-app-0-nic0 \
  -o jsonpath='vni={.spec.vni} overlay={.spec.overlayIPs}{"\n"}'
# vni=1000 overlay=["10.10.0.1"]
```

Wait for the VM to run:

```sh
k02 get virtualmachineinstance -n ectobase-system -l workload=app-0
# ... Running
```

> If the NIC shows `state: Invalid`, its IP falls outside every Subnet in the VPC (or
> the VPC has no Subnet). `state: Exhausted` means the Subnet is full. See
> [Troubleshooting](#6-how-ipam-behaves-troubleshooting).

## 3. A second VM behind a LoadBalancer

First register a VIP pool (`LBPool`), then a `LoadBalancer` that draws a VIP from it
and selects backend NICs by label. Create a `web-0` VM whose NIC is labelled
`app: web`.

```sh
khub apply -f - <<'EOF'
apiVersion: net.ectobase.dev/v1alpha1
kind: LBPool
metadata:
  name: demo-vips
  namespace: default
spec:
  v4Prefix: 203.0.113.0/28    # the VIP address space
---
apiVersion: net.ectobase.dev/v1alpha1
kind: NetworkInterface
metadata:
  name: web-0-nic0
  namespace: default
  labels:
    app: web
spec:
  vpcRef:   { name: demo }
  subnetRef: { name: demo-sn0 }
  ips: []                     # allocate from demo-sn0 (=> 10.10.0.2)
  mac: "52:54:00:00:10:02"
---
apiVersion: compute.ectobase.dev/v1alpha1
kind: VirtualMachine
metadata:
  name: web-0
  namespace: default
spec:
  clusterName: k02
  interfaceRefs: [ { name: web-0-nic0 } ]
  image: quay.io/kubevirt/cirros-container-disk-demo:latest
  runStrategy: RerunOnFailure
  resources: { requests: { cpu: "1", memory: 512Mi } }
---
apiVersion: net.ectobase.dev/v1alpha1
kind: LoadBalancer
metadata:
  name: web-lb
  namespace: default
spec:
  vip: ""                     # empty => allocate from poolRef
  poolRef: { name: demo-vips }
  ports:
    - { port: 443, proto: TCP }
  targetSelector:             # selects backends by NIC label (or use targetRefs: [names])
    matchLabels:
      app: web
EOF
```

Verify the VIP was allocated and that the backend NIC's compiled twin records LB
membership with that VIP:

```sh
khub get loadbalancer web-lb -o jsonpath='{.status.state} vip={.status.allocatedVIP}{"\n"}'
# Allocated vip=203.0.113.1

k02 get compilednic default-web-0-nic0 -o jsonpath='{.spec.lb}{"\n"}'
# [{"vip":"203.0.113.1","ports":[{"port":443,"proto":"TCP"}]}]
```

> The edge gap here is the one described in the top callout. IPAM has allocated the VIP
> and wired the backend membership into the datapath's `CompiledNIC`, so E/W traffic to
> the VIP from inside the fabric follows. But driving the North-South edge from this
> `LoadBalancer` CRD is not wired yet, so a WAN client reaching `203.0.113.1:443` today
> still requires programming the edge directly (that's what `lb_test.go`'s
> `AddLbVip` over the dataplane gRPC socket does).

## 4. NAT egress for the VPC

A `NATGateway` is VPC-scoped: it gives every interface in the VPC source-NAT to a
pool of public IPs. The platform deterministically allocates a `(publicIP, portrange)`
block per source.

```sh
khub apply -f - <<'EOF'
apiVersion: net.ectobase.dev/v1alpha1
kind: NATGateway
metadata:
  name: demo-egress
  namespace: default
spec:
  vpcRef: { name: demo }
  publicIPs:
    - 198.51.100.10
    - 198.51.100.11
  portsPerSource: 1024        # optional (default 1024)
EOF
```

Verify the port-block allocations (populated as workloads in the VPC get addresses):

```sh
khub get natgateway demo-egress -o jsonpath='{.status.state}{"\n"}{range .status.allocations[*]}{.source} -> {.publicIP}:{.portMin}-{.portMax}{"\n"}{end}'
# Ready
# 10.10.0.1 -> 198.51.100.10:1024-2047
# 10.10.0.2 -> 198.51.100.10:2048-3071
```

The compiled `CompiledNIC` for each source carries its SNAT mapping (`spec.nat`), so
egress from inside the fabric is programmed. As with the LB, the edge WAN hop for
these public IPs is still driven directly over the dataplane gRPC path
(`nategress_test.go`), not from the `NATGateway` CRD; see the top callout.

## 5. Optional: default-deny with an allow rule

Make the VPC default-deny and open just 443 to the `web` NICs. Set the VPC policy and
attach a `FirewallPolicy` selected by label:

```sh
khub patch vpc demo --type=merge -p '{"spec":{"defaultPolicy":"Deny"}}'

khub apply -f - <<'EOF'
apiVersion: net.ectobase.dev/v1alpha1
kind: FirewallPolicy
metadata:
  name: web-fw
  namespace: default
spec:
  interfaceSelector:
    matchLabels:
      app: web
  ingress:
    - { cidr: 0.0.0.0/0, proto: TCP, port: 443, action: Allow }
  egress:
    - { cidr: 0.0.0.0/0, action: Allow }
EOF
```

(Direction is expressed by placing a rule under `ingress` vs `egress`; the rule field is
`action`, either `Allow` or `Deny`.)

## 6. How IPAM behaves: troubleshooting

- `state: Invalid` on a NIC/LB. The request can't be satisfied against the address
  space: the VPC has no Subnet, the NIC's `subnetRef` is ambiguous (VPC has >1 Subnet
  and none named), or a pinned `ips`/`vip` falls outside the Subnet/Pool prefix.
  Fix the Subnet/LBPool or the pinned address.
- `state: Exhausted`. The Subnet/Pool is full. Widen the prefix or free addresses.
  A freed sibling address triggers a retry automatically, with no wait for resync.
- `state: Pending`. The referenced Subnet/Pool isn't `Ready` yet (transient).
- Allocation is sticky. Editing an unrelated field on a NIC/LB does not
  renumber it; the allocator re-adopts its current `allocatedIPs`/`allocatedVIP`.
- De-gate keeps the last good state. If a NIC later goes `Invalid`/`Pending` (bad edit,
  Subnet deleted), its existing `CompiledNIC` is kept, so the running datapath is not
  torn down by a transient edit. To revoke a workload, delete its NetworkInterface
  (owner-ref GC removes the CompiledNIC); editing it to an invalid state is not a
  revocation path.
- BYO IPs: to pin, put an in-Subnet address in `spec.ips`; the allocator validates
  membership + uniqueness and reserves it. This is also the migration path for
  pre-IPAM NICs (see [ipam-migration.md](../operations/ipam-migration.md)).

## Cleanup

```sh
khub delete firewallpolicy web-fw --ignore-not-found
khub delete natgateway demo-egress --ignore-not-found
khub delete loadbalancer web-lb --ignore-not-found
khub delete virtualmachine app-0 web-0 --ignore-not-found
khub delete networkinterface app-0-nic0 web-0-nic0 --ignore-not-found
khub delete lbpool demo-vips --ignore-not-found
khub delete subnet demo-sn0 --ignore-not-found
khub delete vpc demo --ignore-not-found
```
