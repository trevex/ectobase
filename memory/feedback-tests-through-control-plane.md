---
name: feedback-tests-through-control-plane
description: "User (2026-08-08): prefer driving live tests through the FULL control plane — spawn real container/VM workloads via Multus + our CNI — not by poking the dataplane gRPC (AttachInterface) directly."
metadata:
  node_type: memory
  type: feedback
---

**User directive (2026-08-08):** "Preferably we should drive tests through control plane so spawn container/vm deployments with Multus and our CNI to drive tests etc."

**Why:** Direct `dataplaneGRPC(AttachInterface/AddRoute/AddFwRule/ConfigureQoS)` wiring (the dpservice-style low-level poke used by the ported bash e2e) tests the datapath in isolation but bypasses the real attach path (CNI ADD → agent → dataplane) and the compiler/CRD/reflector control loop. Driving a real Pod (or KubeVirt VM) annotated onto our overlay via Multus + our CNI exercises the whole system the way production does, so the test proves the integration, not just the datapath primitive.

**PREREQUISITE GAP (verified live 2026-08-08):** Multus is NOT installed on the `test/lab` kind fabric — the compute-cluster nodes run kindnet as the default CNI (`/etc/cni/net.d/10-kindnet.conflist`) and our `flowplane-cni` binary is installed (the `flowplane-cni-install` DaemonSet + `dataplane-kubeconfig` are present) but INACTIVE for Pods, because nothing delegates to it. The NAD CRD exists (chart applies `test/lab/deploy/nad-crd.yaml`) but there is no Multus meta-plugin to honor `k8s.v1.cni.cncf.io/networks` annotations. So Pod-via-CNI (and KubeVirt-VM-via-flowplane-NAD, which also needs Multus) requires **installing Multus in the lab deploy first** (a new `test/lab` deploy step + config), then proving the attach path end-to-end. Real-VM-on-fabric boot was also never proven (Phase 4 was envtest-only). See [[phase4-kubevirt-vm-lifecycle]].

**How to apply:**
- New/pending live tests in `test/lab/livetest` should, where feasible, create a **workload** (a Pod via a Multus NetworkAttachmentDefinition using our CNI, or a KubeVirt VirtualMachine via the vm-materializer) and let the CNI/agent perform the attach + config, then drive/measure traffic from inside the workload — instead of calling `AttachInterface` directly and hand-addressing a netns.
- Prefer CRD-driven config (VPC/NetworkInterface/FirewallPolicy/LoadBalancer/InterfaceQoS + VPCPeering) so the netplane compiler → CompiledNIC → broker → agent → dataplane loop is what programs the datapath — like `TestCrossClusterOverlayPing` already does for routes/firewall.
- Existing green tests (DHCP/NAT/underlay/QoS) use direct gRPC; retrofitting them is a judgment call — going-forward is control-plane-driven; retrofit is a tracked follow-up unless the user asks to redo them now.
- Related: [[feedback-dont-skip-tests]], [[agent-reads-only-compilednic]], [[kubevirt-vm-primary-network-tap]], [[phase4-kubevirt-vm-lifecycle]] (the vm-materializer + Multus tap binding), [[retire-bash-clab-datapath-to-go]] (the effort this steer lands in).
