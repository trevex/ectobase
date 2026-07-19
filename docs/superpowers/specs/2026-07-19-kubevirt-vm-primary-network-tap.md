# Design: KubeVirt VM primary network via a tap + network binding plugin

**Date:** 2026-07-19
**Status:** Proposed design, pre-implementation (refined)
**Author:** Niklas Voss (with Claude)

## 1. Background & motivation

ectobase targets **containers and KubeVirt VMs** on the shared `flowplane` eBPF overlay. Containers
work: the CNI (`cni/plugin`, a Multus default delegate) calls `DataplaneNode.AttachInterface`, which
creates a **veth** into the pod netns and attaches `tc_guest_tx` to the **root-netns host end**;
overlay→guest delivery works because `uplink_rx` (root netns) `devmap`-redirects the decapped frame to
that root-netns host-veth ifindex, and the kernel veth carries it into the pod netns.

A KubeVirt VM differs: qemu drives a **tap**, and the guest OS **self-configures** from the network
(DHCP/SLAAC/RA). We want the VM to use our overlay as its **primary** network, self-configuring against
**our** responders.

**Already done (this is mostly wiring + one topology decision, not new datapath):**
- Guest self-config surface complete: DHCPv4 (IP + gateway + DNS + classless route + **MTU opt-26**),
  DHCPv6, the **RA responder** (default router + **MTU option** + SLLA, Managed), ARP/ND — all in
  `tc_guest_tx` (`flowplane-core/src/{dhcp,arp_nd}.rs`, `flowplane-ebpf/src/{tc,dhcp}.rs`).
- **tc-on-tap datapath proven**: `flowplane TcBringup --tap` and `bringup --guest` attach `tc_guest_tx`
  to a real tun/tap; `test/tap-vm-smoke.sh` boots a **real CirrOS VM** on a `vnet_hdr` tap (gate: the
  datapath answers the VM's ARP in-kernel). `test/tap-dhcp-probe.py` DHCP-probes a real tap.
- Overlay datapath (routing/NAT/LB/firewall, jumbo via `#[xdp(frags)]`), guest-MTU derivation +
  link-MTU + PLPMTUD, and `AttachInterface.mac` (proto field, unused) all exist.
- The CNI is a Multus default delegate resolving `{vni, ips}` from the `NetworkInterface` CR;
  `interface_id` is already `VMI-uid + ifname`.

## 2. Goal & success criteria

A KubeVirt VMI whose **primary** network is a `flowplane` overlay: qemu drives a tap our dataplane
serves; the guest boots, **self-configures via our DHCPv4/DHCPv6/RA** (IP, gateway, DNS, MTU, routes),
and reaches the overlay (E/W cross-node ping + iperf) and N/S — with **no double-NAT and no
KubeVirt-internal DHCP** in the path.

**Done when:** a VMI referencing our binding comes up and the guest DHCP/SLAAC-configures its assigned
overlay IP + gateway + MTU from our responders, then passes the same connectivity a container endpoint
does on the clab fabric.

## 3. Topology: a lean tap directly in our overlay (no veth/bridge stacking)

**Principle (hard requirement).** The VM must live **directly** in our overlay — **one** tap in our
datapath, **no** stacking a tap on a bridge on a veth like other CNI integrations. The virt-launcher
pod's Cilium / cluster-pod network is **separate** (kubelet + health only); our overlay is the VM's
primary NIC via Multus `default: true`, orthogonal to Cilium.

**The symmetry that makes it lean.** Containers already get a **root-netns host-veth** (its peer sits in
the pod netns; our `tc_guest_tx` + `uplink_rx` devmap-delivery run on the root-netns end). A VM gets the
exact analogue: a **root-netns host-tap** whose **fd is handed to qemu**. Both are single root-netns
devices in the *same* datapath — no bridge, no second veth:

```
 container:  overlay ⇄ tc_guest_tx / uplink_rx on  root-netns host-veth  ⇄ (veth peer) ⇄ pod app
 VM:         overlay ⇄ tc_guest_tx / uplink_rx on  root-netns host-TAP   ⇄ (tap fd)    ⇄ qemu/VM
```

- **Datapath unchanged and already proven.** `test/tap-vm-smoke.sh` boots a real qemu VM on a
  root-netns tap with `tc_guest_tx` on it — that *is* this model. `AttachInterface` gains a device type
  `veth|tap`; **tap** mode creates a root-netns tap (simpler than veth — no netns move, no peer), sets
  the VM MAC + guest MTU, disables offloads (`ethtool -K … off`), attaches `tc_guest_tx`, programs the
  maps. `uplink_rx` delivers to it via the same devmap path (the tap is a normal root-netns ifindex).
- **Why not a pod-netns tap.** `uplink_rx` (root netns) delivers via devmap to a **root-netns** ifindex;
  `bpf_redirect` can't cross netns and a tap has no veth-peer for `bpf_redirect_peer`. So a tap in the
  *pod* netns could only receive overlay traffic by adding a veth (to span netns) **+** a bridge — the
  stacking we reject. Keeping the tap in the **root netns** eliminates that entirely.
- **`domainAttachmentType: tap`, never `managedTap`.** managedTap builds a **bridge + tap** (core-bridge
  shape, likely DHCP-hijacking) — precisely the stacked, DHCP-shadowing anti-pattern. We use `tap`: we
  create + own the tap (MAC/MTU), and the VM self-configures against our responders.

**The one real integration question (spike this).** How the **root-netns tap fd reaches qemu** through
the KubeVirt binding. qemu/libvirt accept a pre-opened tap fd (`-netdev tap,fd=,vhost=on,vhostfd=`); the
flowplane node agent (root netns, hostNetwork DaemonSet) creates + owns the tap and must hand its fd to
virt-launcher (pod netns) — via the binding plugin's sidecar/hooks + an `SCM_RIGHTS` pass over a shared
socket, or a device-plugin-style hand-off. This replaces "build a bridge" as the KubeVirt-side work and
is what keeps the datapath lean. **Fallback (only if fd-passing proves infeasible):** a pod-netns
veth+bridge — the stacked model — which we adopt **only if forced**, never as the default.

## 4. Full scope (workstreams)

1. **Root-netns tap in `AttachInterface`**: `device_type = veth|tap`; tap mode creates a root-netns
   tap (multi-queue + `vnet_hdr`), sets the **VM MAC** + guest MTU, disables offloads
   (`ethtool -K … off`, cf. the guest-veth csum artifact), attaches `tc_guest_tx`, programs the maps —
   `attach.rs` factors `setup_veth` → device-agnostic + `setup_tap`, reusing `Control::create_interface`.
   No bridge, no second veth.
2. **VM MAC threading**: CNI reads the VMI/pod MAC → `AttachInterface.mac`; `PORT_META.guest_mac` +
   the tap MAC must equal the VM MAC (`attach.rs` currently derives a MAC — must accept the passed one
   for `tap`).
3. **Tap-fd hand-off to qemu** (the lean-keeping integration): the node agent owns the root-netns tap;
   its fd reaches virt-launcher/qemu via the KubeVirt binding plugin (sidecar/hooks + `SCM_RIGHTS` over
   a shared socket, or device-plugin hand-off). qemu uses `-netdev tap,fd=,vhost=on,vhostfd=`.
4. **KubeVirt binding plugin**: register in the `KubeVirt` CR
   (`spec.configuration.network.binding.ectobase`) with `networkAttachmentDefinition` (our binding NAD)
   + `domainAttachmentType: tap` (+ `migration.method: link-refresh`). Never `managedTap` (bridge+DHCP).
5. **Primary network**: Multus `default: true` (our CNI already is the default delegate), keeping the
   VM's primary NIC = our overlay, separate from the pod's Cilium network. Genuine primary-UDN is
   OVN-K-specific today — future alignment.
6. **Performance**: vhost-net + `spec.domain.devices.networkInterfaceMultiqueue` (multi-queue tap);
   validate tc/eBPF coexistence with the qemu tap fd + GSO/checksum offload.
7. **Live migration**: `link-refresh`; recreate the tap + re-attach on the destination, move the
   underlay `/128`, re-`AttachInterface`/`Detach`, conntrack handling (tie into DecentralizedLiveMigration).
8. **Lifecycle**: detach + release IPAM + delete the tap on VMI stop/migrate.

## 5. Vertical slice (build first): a real VM self-configures off our dataplane

Prove the **lean model end-to-end**: a real guest OS on a **root-netns tap** in our datapath,
self-configuring via DHCP/SLAAC — before any CNI/binding code. Two parts:

**5a. Real-VM DHCP self-config e2e (extend `test/tap-vm-smoke.sh`).** Today the smoke statically
configures the VM and only gates on ARP. Extend it to a genuine e2e:
- Two endpoints on one host (like `flowplane-sim`'s two-node fabric but with a real VM on one side):
  a CirrOS VM on tap `smg0` + a second guest (netns or second tap) as the ping target, same VNI.
- The VM does **DHCP** (`sudo udhcpc -i eth0`, CirrOS default) instead of static `ip addr add`.
- **Gate:** the VM obtains its assigned overlay IP + **gateway** + **MTU (opt-26)** from our DHCPv4
  responder (and, for a v6 pass, an address via DHCPv6 + gateway/MTU via our RA), then **pings/iperfs
  the second endpoint over the overlay** (encap/decap + routing). This exercises `tc_guest_tx` on a
  real tap, DHCPv4/DHCPv6/RA/ARP/ND, the MTU path, and overlay forwarding — with a real guest.
- Reuses the proven `bringup`/tap attach — **no new attach code required for 5a**.

**5b. Tap-fd hand-off spike (the KubeVirt integration gate, ~1 day).** The lean model hinges on getting
a **root-netns tap fd to qemu in the virt-launcher pod netns**. Spike it: with a tap in one netns and
qemu in another, hand the fd across (`SCM_RIGHTS` over a unix socket) and boot qemu with
`-netdev tap,fd=,vhost=on,vhostfd=`; confirm the VM runs on the cross-netns tap. Then map this onto
KubeVirt's binding plugin (sidecar/hooks — how a binding passes an fd; how virt-launcher receives it).
Output: a proven fd-hand-off mechanism (or, if infeasible, the documented fallback to the stacked
veth+bridge). This — not a bridge — is the KubeVirt-side design gate.

**Explicitly out of the slice:** the KubeVirt binding plugin + CR registration, Multus wiring, MAC
threading through the CNI, vhost/multiqueue tuning, migration. Those are §6 follow-ons, unblocked by 5b.

## 6. Follow-on slices (outlined)

- **Slice 2 — KubeVirt binding:** the binding NAD + `KubeVirt` CR registration (or plain `managedTap`
  per 5b), the pod-netns bridge+tap in the binding CNI, VM-MAC threading, Multus `default: true`. Gate:
  a real VMI on the clab fabric self-configures + gets overlay connectivity.
- **Slice 3 — performance:** vhost-net + multiqueue; tc + GSO/offload validation on the tap.
- **Slice 4 — live migration:** `link-refresh`, dest re-attach, underlay `/128` + conntrack move.
- **Slice 5 — primary-UDN alignment** as the upstream API generalizes beyond OVN-K.

## 7. Testing & validation

- **Slice 5a gate:** extended `tap-vm-smoke.sh` — real VM DHCP-self-configures + overlay ping/iperf
  (single host; needs `/dev/kvm`, `cargo build -p flowplane`, the CirrOS image, `nix develop`).
- **Regression:** container scenarios (nat-egress, lb-ingress, multicluster) unchanged.
- **Slice 2 e2e:** a KubeVirt VMI on the clab fabric — requires adding a minimal KubeVirt install to the
  kind clusters in the harness (new).

## 8. Fresh-session kickoff (start here next session)

**State (as of commits up to `d5b6490` on `main`, all pushed):**
- MTU + frags + IPv6 RA responder landed and unit/verifier-validated (commits `133977f`, `0ed9c3b`);
  see memory `cilium-mtu-model` + `kubevirt-vm-primary-network-tap`. Working tree clean.
- **clab is torn down** — recreate on demand with `sudo -E env "PATH=$HOME/go/bin:$PATH" bash
  hack/clab-up.sh` (needs kind+containerlab on PATH, docker, passwordless sudo; ~10 min).

**Read first:** this spec; `flowplane/flowplane/src/attach.rs` (the veth attach seam —
`setup_veth`/`attach`/`Control::create_interface`); `test/tap-vm-smoke.sh` (the VM harness to extend);
`flowplane-ebpf/src/tc.rs` (`tc_guest_tx` dispatch); memory `kubevirt-vm-primary-network-tap`.

**Do, in order:**
1. **Slice 5a** (datapath confidence, no KubeVirt): extend `tap-vm-smoke.sh` to a real VM doing DHCP
   self-config on a **root-netns tap** + a second endpoint + overlay ping. This is exactly the lean
   model (host-tap in our datapath), so it directly validates the target — no new attach code.
2. **Slice 5b** (the KubeVirt integration gate): spike the **root-netns tap fd → qemu** hand-off
   (`SCM_RIGHTS` cross-netns + `-netdev tap,fd=`), then map it onto a KubeVirt binding plugin. Decides
   the lean fd-passing path (fallback to stacked veth+bridge only if infeasible).
3. Then `device_type=tap` in `AttachInterface` (§4.1) + slice 2 (the binding) per the 5b outcome.

No half-finished code is in the tree — the next session starts from a clean, green `main`.

## 9. Open questions / risks

- **THE gate — does a root-netns tap work with KubeVirt's namespacing?** The lean model needs the tap
  to live in the flowplane/root netns (for `uplink_rx` delivery) while qemu runs in the virt-launcher
  **pod** netns. KubeVirt normally creates/opens the tap **in the launcher netns**. So we must verify:
  can a binding plugin hand qemu a **foreign-netns (root) tap fd**, or does virt-launcher insist the
  netdev be in its own netns? If a root-netns tap can't be plumbed through KubeVirt, lean-in-root-netns
  fails and we fall back to the stacked pod-netns veth+bridge. **Resolve empirically first** (spike 5b +
  KubeVirt source) — the whole topology choice hinges on it. **We do not assume it works.**
- **tc + vhost-net + multiqueue** coexistence on the tap; GSO/checksum-offload on the tap (disable, per
  the smoke + the guest-veth artifact).
- **VM MAC source** — explicit VMI `macAddress` vs KubeVirt copying the pod-interface MAC; our tap +
  `PORT_META` must match.
- **Migration** conntrack + underlay `/128` movement + dest re-attach ordering.
