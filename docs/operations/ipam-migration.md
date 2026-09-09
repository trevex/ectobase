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
