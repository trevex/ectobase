# IPAM migration

Central IPAM moved address assignment from the user into the dispatch: overlay addresses come
from a `Subnet`, public addresses from an `IPPool`, and MACs are allocated alongside. This page
covers two one-time migrations for objects created before that, and the rule for what happens
when an allocation goes bad on a live object.

Both migrations are non-disruptive and renumber nothing: the allocators adopt the addresses
already in use. The objects live on the dispatch, so run the commands below against it. How
allocation works in general is in [CRD interactions](../reference/crd-interactions.md#where-addresses-come-from).

## From free-form addresses to Subnets and IPPools

Before central IPAM, `NetworkInterface.spec.ips` and `LoadBalancer.spec.ip` were taken as given,
with nothing checking them. The allocators now treat them as pins: a requested address is
validated and reserved, and an empty one is allocated.

1. For each VPC, create one or more `Subnet`s whose prefixes cover the overlay addresses its
   NICs already use. For the load-balancer addresses in use, create an `IPPool` of
   `type: public` covering them. Wait for each to report `status.state: Ready`.
2. Set `NetworkInterface.spec.subnetRef` (you can skip this when the VPC has exactly one
   `Subnet`) and `LoadBalancer.spec.poolRef`.
3. On the next reconcile, each allocator adopts the existing pin. It checks that the address
   lies in the prefix and that no other object holds it, then writes it to
   `status.allocatedIPs` (NIC) or `status.allocatedIP` (load balancer) and sets `status.state`
   to `Allocated`.

Compilation waits on that status. The compiler emits a NIC's `CompiledNIC` only when the NIC is
`Allocated` for its current generation, and sources the overlay addresses from
`status.allocatedIPs`, never from `spec.ips`. A NIC goes `Invalid` and does not compile when its
pinned address lies outside its `Subnet`, or when it names no `subnetRef` in a VPC that has more
than one `Subnet`. Watch `kubectl get networkinterfaces` and
`kubectl get loadbalancers` for `Invalid`, `Pending` or `Exhausted` before you retire anything
that relied on the old behaviour.

### MACs

`NetworkInterface.spec.mac` follows the same rules. A NIC that pinned a MAC keeps it: the
allocator checks the format and that the MAC is unique in the VPC, then adopts it into
`status.allocatedMAC`. A bad or clashing pin makes the NIC `Invalid`. A NIC with no pin gets a
stable, VPC-unique, locally administered MAC derived from its UID. No NIC changes its L2 address
during the migration. `CompiledNIC.spec.mac`, and so the KubeVirt guest's MAC, comes from
`status.allocatedMAC`.

## From LBPool to IPPool

`LBPool` is gone. A pool only one consumer kind can draw from forces the next consumer to invent
its own pool kind and allocator, and NAT gateways were next. `IPPool` replaces it with the same
`v4Prefix`, `v6Prefix` and `reservedIPs`, plus a required `spec.type`, `public` or `internal`,
that each consumer must match. A `LoadBalancer` pointed at an `internal` pool goes `Invalid`, so
an internal range can't be handed out as a public address by accident.

`LoadBalancer.spec.poolRef` is unchanged; it now resolves to an `IPPool`, so no load balancer
needs editing. The pools themselves must be recreated, because an `LBPool` cannot become an
`IPPool` in place and `type` has no safe default.

!!! warning "These steps need an image that serves both kinds"
    Steps 1 to 3 need a dispatch running an image from `ce7f5cf7`, the commit just before
    `62744b07` retired `LBPool`: the only point in history where the load-balancer allocator
    reads `IPPool` and `LBPool` is still served. On a current image `LBPool` is not served at
    all, so old `LBPool` objects can be neither listed nor deleted; they stay behind as
    unreachable rows in kine.

1. For each `LBPool`, create an `IPPool` with the same name, the same prefixes and
   `reservedIPs`, and `type: public`. Every `LBPool` was a public range. Wait for
   `status.state: Ready`.
2. Make each load balancer reconcile. It will not do so by itself: the allocator skips a load
   balancer that already reports `Allocated` for its current generation, so an address allocated
   under `LBPool` sits in `status.allocatedIP` with no `IPAllocation` behind it, and to the next
   consumer of the pool it looks free. Clear the state to get past that check:

    ```sh
    kubectl patch loadbalancer <name> --subresource=status --type=merge \
      -p '{"status":{"state":""}}'
    ```

    The load balancer then re-adopts the address it already published, because the allocator
    prefers a consumer's current address over the lowest free one, and records it as an
    `IPAllocation` named `<pool>-<encoded address>`. Check that there is exactly one
    `IPAllocation` per live load-balancer address before going on:

    ```sh
    kubectl get ipallocations -l net.ectobase.dev/pool=<pool>
    ```

3. Delete the old `LBPool` objects.

On the dispatch nothing else is needed: the aggregated apiserver serves the `net` group, and the
kind stops being served once the new image rolls out. On a pool, the chart rendered the
`lbpools.net.ectobase.dev` CRD from `templates/crds.yaml`, so the pool-chart upgrade that drops it
deletes it, along with any `LBPool` objects. That holds even when the upgrade goes straight to a
chart whose CRDs carry `helm.sh/resource-policy: keep`: Helm checks for `keep` on the live object
it drops, and the chart stopped rendering `lbpools` before it added the annotation, so no
`lbpools` CRD ever carried it. Only a pool whose CRDs were installed outside the chart
(`installCRDs=false`) needs it removed by hand:

```sh
kubectl delete crd lbpools.net.ectobase.dev
```

## Keep-last-good: a bad edit does not tear down a workload

Compilation is gated on `Allocated` for the current generation, but the gate only stops a new
compile; it never deletes a compiled object. If a NIC or load balancer drops out of `Allocated`
(someone edits in a bad address, deletes its `Subnet` or `IPPool`, or bumps its generation
mid-edit), it goes `Invalid` or `Pending` and its existing `CompiledNIC` stays. The datapath
keeps serving the last good addresses until allocation succeeds again. A transient bad edit
must not cut live connectivity.

The status write that leaves `Allocated` also clears `status.allocatedIPs`, so the allocator no
longer remembers the old address. An unpinned NIC can come back with a different one. Pin the
address in `spec.ips` if it must not change. The MAC is not affected: `status.allocatedMAC` is
kept.

To actually revoke an allocation, delete the `NetworkInterface` or `LoadBalancer`. The source's
finalizer then removes its compiled twin, and garbage collection removes the `IPAllocation`s it
owns. Editing an object into an invalid state is not a way to tear it down.

## Where to go next

- [CRD interactions](../reference/crd-interactions.md): how `Subnet`, `IPPool` and
  `IPAllocation` fit with the rest of the API.
- [Routing and VNIs](../features/routing-vni.md): what the allocated addresses are used for.
- [Load balancing](../features/loadbalancer.md): the consumer `IPPool` was built for first.
