# ectobase Helm chart

Deploys the netplane control plane + flowplane datapath (eBPF or DPDK) for one compute pool.

## Tier-1 autonomous local failover (`tier1Failover`)

Opt-in, pool-local capability: when a node dies but the cluster is healthy, medik8s
fences the dead node and KubeVirt (`runStrategy: RerunOnFailure`, set by the
vm-materializer) restarts the VM on a surviving node — all in-cluster, with central
unreachable. This chart owns only the *configuration*; the medik8s operators are a
prerequisite.

**Prerequisite:** install the medik8s NHC + SNR operators (dev: `hack/medik8s-up.sh`
or `INSTALL_MEDIK8S=1 hack/install-stack.sh`).

**Enable:**
```
helm upgrade --install ectobase deploy/charts/ectobase \
  --namespace ectobase-system --set tier1Failover.enabled=true
```

**Key values** (all under `tier1Failover.`, e.g. `--set tier1Failover.remediationStrategy=...`):
- `tier1Failover.remediationStrategy` (`Automatic|ResourceDeletion|OutOfServiceTaint`, default
  `OutOfServiceTaint`): `OutOfServiceTaint` applies the k8s `node.kubernetes.io/out-of-service`
  taint so pods are force-deleted and RWO volumes (Ceph RBD boot disks) force-detach and
  reattach on the surviving node. Requires Kubernetes ≥ 1.28.
- `tier1Failover.watchdog.enabled` (default `false`): `false` uses SNR's software-reboot path
  (dev/kind, no `/dev/watchdog`); `true` arms the hardware watchdog for a hard split-brain
  guarantee (prod) and renders a `SelfNodeRemediationConfig` — install the operators first so
  it adopts the chart-provided singleton.
- `tier1Failover.minHealthy` (default `"51%"`): NHC refuses to remediate below this healthy
  quorum, preventing a network blip from cascading into a pool-wide fence storm.

**Caveat:** with `watchdog.enabled=false`, remediation is timeout-based (not a hard fence);
`watchdog.enabled=true` is the hardening answer. Validate end-to-end with
`hack/tier1-failover-e2e.sh` on a dev fabric.
