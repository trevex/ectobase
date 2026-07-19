# Design: KubeVirt VM primary network via a managed tap + network binding plugin

**Date:** 2026-07-19
**Status:** Proposed design, pre-implementation
**Author:** Niklas Voss (with Claude)

## 1. Background & motivation

ectobase targets **containers and KubeVirt VMs** on the shared `flowplane` eBPF overlay. Containers
work today: the CNI (`cni/plugin`, a Multus default delegate) calls `DataplaneNode.AttachInterface`,
which creates a **veth** into the pod netns and attaches `tc_guest_tx` to the host side.

A KubeVirt VM is different: qemu drives a **tap** device, and the guest OS **self-configures** its NIC
from the network (DHCP/SLAAC/RA) rather than being handed config by a CNI. We want the VM to use our
overlay as its **primary** network, self-configuring against **our** dataplane responders.

**What already exists (so this is mostly wiring, not new datapath):**
- The guest self-configuration surface is complete: **DHCPv4** (IP + gateway + DNS + classless-static
  route + **MTU opt-26**), **DHCPv6** (IP + DNS), the **IPv6 RA responder** (default router + **MTU
  option** + SLLA, Managed), and ARP/ND gateway responders — all in `tc_guest_tx`.
- The **tc-on-tap datapath is proven**: `flowplane TcBringup --tap` attaches `tc_guest_tx` to a real
  tun/tap by ifindex, `test/tap-dhcp-probe.py` DHCP-probes a real tap, and **`test/tap-vm-smoke.sh`
  boots an actual qemu VM on a `vnet_hdr` tap** against the datapath.
- The overlay datapath (routing / NAT / LB / firewall, jumbo via `#[xdp(frags)]`), guest-MTU
  derivation + link-MTU + PLPMTUD, and `AttachInterface.mac` (proto field, currently unused) all exist.
- The CNI is already a **Multus default delegate** and resolves the VM's overlay `{vni, ips}` from the
  `NetworkInterface` CR; `interface_id` is already `VMI-uid + ifname`.

**The gap** is: (a) `AttachInterface` is **veth-only** — no tap device mode; (b) no **KubeVirt network
binding plugin** ties our network to the VM's domain; (c) the **VM MAC** isn't threaded; plus
production concerns (vhost/multiqueue, live migration).

## 2. Goal & success criteria

A KubeVirt VMI whose **primary** network is a `flowplane` overlay: qemu drives a tap our dataplane
owns; the guest boots, **self-configures via our DHCPv4/DHCPv6/RA** (IP, gateway, DNS, MTU, routes),
and reaches the overlay (E/W cross-node ping + iperf) and N/S (egress + LB), with **no double-NAT and
no KubeVirt-internal DHCP** in the path.

**Done when:** a VMI referencing our binding comes up, the guest DHCP/SLAAC-configures its assigned
overlay IP + gateway + MTU from our responders, and passes the same connectivity a container endpoint
does on the clab fabric.

## 3. Full scope (target architecture)

```
 VMI (spec.domain.devices.interfaces[].binding: {name: ectobase}, networks[]: primary)
   │  KubeVirt CR spec.configuration.network.binding.ectobase =
   │     { networkAttachmentDefinition: <our binding NAD>, domainAttachmentType: tap,
   │       migration: {method: link-refresh} }
   ▼
 virt-launcher pod (Multus default = our CNI → VM's PRIMARY network)
   ├─ our binding CNI (tap mode): AttachInterface{device=tap, mac=<VM MAC>, vni, ips}
   │     → dataplane creates a TAP, sets MAC + guest MTU, attaches tc_guest_tx, programs maps
   ▼
 qemu opens the tap (virtio-net, vhost-net, optional multiqueue)
   ▼
 GUEST OS: DHCPv4 / DHCPv6 / RS → answered by tc_guest_tx responders (IP, gw, MTU, DNS, routes)
   ▼
 overlay: encap/decap + routing/NAT/LB/firewall (unchanged)
```

Deliberately **NOT `managedTap`**: it inserts a Linux bridge between the pod interface and the tap and
mirrors the core-bridge behaviour (incl. KubeVirt's internal DHCP hijack, DHCPv6-less) — both defeat a
tc-on-tap dataplane whose own responders must serve the VM. We use `domainAttachmentType: tap` and
**own the tap** in our binding CNI.

Full-scope workstreams:
1. **Tap attach in the dataplane** — `AttachInterface` device-type (`veth` | `tap`); tap mode creates
   a tun/tap, sets MAC + MTU, attaches `tc_guest_tx` (the proven `TcBringup` path), programs maps.
2. **VM MAC threading** — CNI reads the VMI/pod MAC → `AttachInterface.mac`; `PORT_META.guest_mac` and
   the tap MAC must equal the VM MAC.
3. **KubeVirt binding plugin** — a binding NAD + `KubeVirt` CR registration (`domainAttachmentType:
   tap`); our binding CNI runs in tap mode; optional sidecar only if domain-XML mutation is needed.
4. **Primary network** — Multus `default: true` (our CNI as the VM's primary delegate). Primary-UDN
   (OVN-K's `UserDefinedNetwork`, `role: primary`) is OVN-Kubernetes-specific today; track as a future
   alignment as the upstream primary-UDN API generalizes.
5. **Performance** — vhost-net + `networkInterfaceMultiqueue` (multi-queue tap `IFF_MULTI_QUEUE`);
   validate `tc`/eBPF coexistence with the qemu tap fd + GSO/checksum-offload (cf. the guest-veth
   csum-offload artifact).
6. **Live migration** — `migration.method: link-refresh`; recreate the tap + re-attach `tc` on the
   destination node, move the underlay `/128`, re-`AttachInterface` on dest / `Detach` on source,
   conntrack handling (tie into KubeVirt DecentralizedLiveMigration).
7. **Lifecycle** — detach `tc` + release IPAM + delete the tap on VMI stop/migrate.

## 4. Vertical slice (build now): a proper tap in `AttachInterface`, validated with a real VM

Prove the **tap datapath + VM self-configuration end-to-end**, decoupled from KubeVirt orchestration.
This de-risks the one code gap (tap in the attach path) by reusing the proven `TcBringup` tc-on-tap
logic and the `tap-vm-smoke.sh` qemu harness.

**Scope of the slice:**
- **Proto:** `AttachInterfaceRequest` gains `device_type` (`""`/`veth` default, `tap`). For `tap`,
  `mac` is **required** (the VM owns its MAC; we don't derive it).
- **`attach.rs`:** factor `setup_veth` into a device-agnostic attach; add `setup_tap` that
  `ip tuntap add dev <name> mode tap multi_queue vnet_hdr`, sets the MAC (from the request) + the
  derived guest MTU, brings it up, and leaves it in the target netns for qemu. Then reuse the existing
  `Control::create_interface` seam (it already attaches `tc_guest_tx` to a device by name and programs
  `PORT_META`/`INTERFACES`/`UNDERLAY`) — the tap is just the device, same as the veth host side.
- **No CNI/KubeVirt changes in this slice.**

**Success gate (extends `test/tap-vm-smoke.sh`):** on a netns with a host-run `flowplane serve`,
`AttachInterface{device=tap, mac=M, vni, ips}` creates the tap; a real qemu VM opens it and **DHCP/
SLAAC-configures** its assigned overlay IP + gateway + **MTU (opt-26 + RA MTU option)** from our
responders, then **pings/iperfs across the overlay** to a second endpoint. That single test exercises:
tap creation, `tc_guest_tx` on the tap, DHCPv4/DHCPv6/RA/ARP/ND, encap/decap, and MTU — i.e. the whole
VM-facing datapath minus KubeVirt.

**Explicitly out of the slice:** the KubeVirt binding plugin + CR registration, Multus-default wiring,
vhost/multiqueue tuning, and live migration (all in §5 follow-ons).

## 5. Follow-on slices (outlined, not built now)

- **Slice 2 — KubeVirt binding plugin:** the binding NAD + `KubeVirt` CR registration
  (`domainAttachmentType: tap`), our binding CNI invoked in tap mode (reads the network name from
  `cni-args`, the VM MAC from the VMI/pod), Multus `default: true`. Gate: a real VMI on the clab fabric
  gets overlay connectivity self-configured.
- **Slice 3 — performance:** vhost-net + multiqueue; validate tc + GSO/offload on the tap.
- **Slice 4 — live migration:** `link-refresh`, re-attach on dest, underlay `/128` + conntrack move.
- **Slice 5 — primary-UDN alignment:** track the upstream primary-UDN API; provide a UDN-shaped NAD if
  it generalizes beyond OVN-K.

## 6. Testing & validation

- **Unit:** `attach.rs` device-type dispatch; the tap setup helper.
- **Slice gate:** the extended `tap-vm-smoke.sh` (real qemu VM self-configures + overlay ping/iperf).
- **Regression:** existing container scenarios (nat-egress, lb-ingress, multicluster) unchanged —
  `device_type` defaults to veth.
- **Follow-on e2e:** a KubeVirt VMI on the clab fabric (add a minimal KubeVirt install to the harness).

## 7. Open questions / risks

- **tc + vhost-net + multiqueue coexistence** on the tap (fd owned by qemu; tc-clsact is netdev-layer —
  expected to work, but validate on our kernel, incl. GSO/checksum-offload like the guest-veth artifact).
- **VM MAC source** — explicit VMI `spec…interfaces[].macAddress` vs KubeVirt copying the pod-interface
  MAC; our tap + `PORT_META` must match whichever KubeVirt uses.
- **Confirm `managedTap` is avoided** (its bridge + DHCP behaviour); we use `tap` + no DHCP sidecar so
  the guest's DHCP/RA reach our responders — the single hardest thing to keep correct.
- **Migration** conntrack + underlay `/128` movement semantics (destination re-attach ordering).
- **Primary-UDN vs Multus-default** — Multus `default: true` is the concrete path for a non-OVN CNI;
  genuine primary-UDN is a moving upstream target.
