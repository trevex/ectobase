# IPAM migration

Before this change, `NetworkInterface.Spec.IPs` and `LoadBalancer.Spec.LB address` were
free-form and unallocated. Migration is non-disruptive and requires no renumbering:

1. For each VPC, create `Subnet` object(s) whose prefixes cover the overlay IPs
   already in use by that VPC's NICs. Create `IPPool` object(s) of `type: public`
   covering existing LB addresses.
2. Set `NetworkInterface.Spec.SubnetRef` (skip if the VPC has exactly one Subnet)
   and `LoadBalancer.Spec.PoolRef`.
3. On first reconcile, the allocator adopts each existing `Spec.IPs` / `Spec.LB address`
   as a pinned reservation (validated for membership + uniqueness) and writes it to
   `Status.AllocatedIPs` / `Status.AllocatedIP`. Compilation is gated on that
   status, so a NIC whose IP falls outside every Subnet goes `Invalid` and stops
   compiling until corrected; surface these via `kubectl get networkinterface`.

Rollout order: create Subnets/IPPools first (they go `Ready`), then patch the
`Ref` fields. Watch for `State=Invalid`/`Conflict` before removing any legacy path.

## MACs are allocated too

`NetworkInterface.Spec.MAC` follows the same request semantics as `Spec.IPs`. A
pre-IPAM NIC that pinned a MAC keeps it: on first reconcile the allocator adopts
`Spec.MAC` as a validated, VPC-unique reservation and republishes it to
`Status.AllocatedMAC` (a format-invalid or clashing pin goes `Invalid`, like a bad
IP). A NIC that left `Spec.MAC` empty is assigned a stable, VPC-unique,
locally-administered (`02:`-prefixed) MAC derived from its identity — so no NIC
renumbers its L2 address during migration. `CompiledNIC.Spec.MAC` and the KubeVirt
guest are sourced from `Status.AllocatedMAC`, never `Spec.MAC` directly.

## Retiring LBPool for IPPool

`LBPool` is gone. It was LB-specific, and an address pool that only one consumer kind can
draw from forces the next consumer — NAT, then internal LBs — to invent its own pool kind
and its own allocator. `IPPool` replaces it: the same prefixes and `reservedIPs`, plus a
required `spec.type` (`public` or `internal`) that a consumer must match. A `LoadBalancer`
pointed at an `internal` pool is refused with `Invalid`, so an internal range can never be
spent as a public address by accident.

`LoadBalancer.spec.poolRef` is untouched — same field, same shape, it just resolves to an
`IPPool` now — so no LoadBalancer needs editing. The pool objects themselves do have to be
recreated, because an `LBPool` cannot become an `IPPool` in place and the new `type` has no
sensible default to infer:

1. For each `LBPool`, create an `IPPool` of the same name with the same `v4Prefix` /
   `v6Prefix` / `reservedIPs` and `type: public` (every `LBPool` was a public range; that
   was the assumption baked into the kind). Wait for `status.state: Ready`.
2. Make each LoadBalancer reconcile. This does not happen by itself: the allocator
   short-circuits an LB that already reports `Allocated` for its current generation, so an
   address allocated under `LBPool` sits in `status.allocatedIP` with no `IPAllocation`
   backing it, and to a later consumer of the same pool it looks free. Clear the status to
   drop out of that short-circuit:

   ```sh
   kubectl patch loadbalancer <name> --subresource=status --type=merge -p '{"status":{"state":""}}'
   ```

   The LB then re-adopts the address it already published — the allocator prefers the
   current address over the lowest-free one — and records it as an `IPAllocation` named
   `<pool>-<encoded address>`. Confirm with
   `kubectl get ipallocation -l net.ectobase.dev/pool=<pool>` that there is exactly one
   object per live LB address before going further.
3. Delete the old `LBPool` objects.

On a **live** cluster the CRD itself also has to go, explicitly:

```sh
kubectl delete crd lbpools.net.ectobase.dev
```

Helm does not remove a CRD it has stopped templating out, so upgrading the
`ectobase-pool` chart leaves `lbpools.net.ectobase.dev` registered and any surviving
`LBPool` objects readable, with nothing reconciling them — the worst kind of stale: an
object that still answers `kubectl get`. Deleting the CRD deletes every remaining `LBPool`
with it, so do the three steps above first — once it is gone there is nothing left to read
the old prefixes off. On the dispatch there is nothing to delete: the net group is served by the
aggregated apiserver, not by CRDs, and the kind simply stops being served once the new
apiserver image rolls.

## De-gate semantics: keep-last-good

Compilation is gated on `State=Allocated` for the current generation, but that gate
only suppresses re-emission; it never deletes an already-compiled object. If a
NIC or LB regresses out of `Allocated` (edited to a bad IP, its `Subnet`/`IPPool`
deleted, or its `Generation` bumped mid-edit) it goes `Invalid`/`Pending`, yet its
existing `CompiledNIC` is left in place: the running datapath keeps serving the
last successfully-allocated IPs until re-allocation succeeds. This is intentional:
in a PAM tool a transient bad edit must not tear down live connectivity.

To actually revoke an allocation and remove it from the datapath, delete the
`NetworkInterface` (or `LoadBalancer`); owner-ref GC then removes the compiled
object. Editing a resource into an invalid state is not a teardown path.
