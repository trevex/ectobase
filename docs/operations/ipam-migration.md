# IPAM migration

Before this change, `NetworkInterface.Spec.IPs` and `LoadBalancer.Spec.VIP` were
free-form and unallocated. Migration is non-disruptive and requires no renumbering:

1. For each VPC, create `Subnet` object(s) whose prefixes cover the overlay IPs
   already in use by that VPC's NICs. Create `LBPool` object(s) covering existing
   LB VIPs.
2. Set `NetworkInterface.Spec.SubnetRef` (skip if the VPC has exactly one Subnet)
   and `LoadBalancer.Spec.PoolRef`.
3. On first reconcile, the allocator **adopts** each existing `Spec.IPs` / `Spec.VIP`
   as a pinned reservation (validated for membership + uniqueness) and writes it to
   `Status.AllocatedIPs` / `Status.AllocatedVIP`. Compilation is gated on that
   status, so a NIC whose IP falls outside every Subnet goes `Invalid` and stops
   compiling until corrected — surface these via `kubectl get networkinterface`.

Rollout order: create Subnets/LBPools first (they go `Ready`), then patch the
`Ref` fields. Watch for `State=Invalid`/`Conflict` before removing any legacy path.

## De-gate semantics (keep-last-good)

Compilation is gated on `State=Allocated` for the current generation, but that gate
only *suppresses re-emission* — it never deletes an already-compiled object. If a
NIC or LB regresses out of `Allocated` (edited to a bad IP, its `Subnet`/`LBPool`
deleted, or its `Generation` bumped mid-edit) it goes `Invalid`/`Pending`, yet its
existing `CompiledNIC` is **left in place**: the running datapath keeps serving the
last successfully-allocated IPs until re-allocation succeeds. This is intentional —
in a PAM tool a transient bad edit must not tear down live connectivity.

To actually revoke an allocation and remove it from the datapath, **delete the
`NetworkInterface`** (or `LoadBalancer`); owner-ref GC then removes the compiled
object. Editing a resource into an invalid state is not a teardown path.
