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

## 3. The netns topology decision (the crux — resolve first)

**The delivery constraint.** `uplink_rx` runs in the **root netns** (the fabric uplink is there) and
delivers overlay→guest via `GUEST_DEV.redirect(tap_ifindex)` to a **root-netns** ifindex.
`bpf_redirect`/devmap **cannot target another netns**. A qemu tap lives in the **virt-launcher pod
netns**. So a program can't just be put "on the pod-netns tap" and receive overlay traffic — the
delivery hop must land on a root-netns device that spans into the pod netns (a veth), exactly as the
container path already does. Three candidate topologies:

- **Topology A — reuse the veth datapath + a pod-netns bridge (RECOMMENDED default).** Keep the
  existing root-host-veth datapath unchanged (tc + devmap delivery). In the pod netns, a **bridge**
  joins the guest-veth-end and the **VM tap**; qemu opens the tap. VM frames:
  `qemu → tap → bridge → guest-veth → (veth span) → root-host-veth (tc_guest_tx responders) → overlay`.
  This is KubeVirt bridge-binding's *topology* but with **our** bridge and **no KubeVirt DHCP**, so the
  VM's DHCP/RA reach our responders. **Zero datapath change** — only new pod-netns plumbing (bridge +
  tap + MAC) and the binding.
- **Topology B — tc directly on the pod-netns tap.** Purer (no bridge) but requires solving cross-netns
  overlay→tap delivery (a real datapath change: per-pod delivery, or `bpf_redirect` into the pod via a
  spanning device anyway). Higher risk; **deferred**.
- **Topology C — root-netns tap, fd passed to qemu.** qemu accepts an already-open tap fd (`-netdev
  tap,fd=`), so the tap can live in the root netns (existing single-netns datapath works) while qemu
  runs in the pod netns. Clean datapath, but **KubeVirt creates the tap in the launcher netns** (per
  the binding model), so this needs a fully custom fd-passing binding — off the beaten path. Note as a
  possible optimization.

**PIVOTAL OPEN QUESTION (resolve before building the binding):** does KubeVirt **`managedTap`** run its
own internal DHCP (like core `bridge`), or does it let the guest DHCP against the network?
- If `managedTap` does **NOT** run DHCP → `managedTap` builds the bridge+tap for us and our **existing
  veth datapath serves the VM with zero custom binding** (Topology A for free).
- If it **DOES** hijack DHCP → we need a **custom binding** (`domainAttachmentType: tap`) whose CNI
  builds our own bridge+tap **without** DHCP (Topology A, our bridge).
Resolve by reading `kubevirt/kubevirt` virt-handler/virt-launcher source for the managedTap path (PR
#13024) — this decides whether the KubeVirt-integration slice is "config only" or "custom binding".

## 4. Full scope (workstreams)

1. **Pod-netns bridge + tap plumbing** (Topology A): create a bridge + tap in the pod netns, enslave
   the guest-veth-end + tap, set the **VM MAC** on the tap/veth and the guest MTU, disable offloads
   (cf. `tap-vm-smoke.sh` `ethtool -K … off` + the guest-veth csum-offload artifact). Lives in the
   binding CNI (or the dataplane, if we extend `AttachInterface`).
2. **VM MAC threading**: CNI reads the VMI/pod MAC → `AttachInterface.mac`; `PORT_META.guest_mac` +
   the veth/tap MAC must equal the VM MAC (`attach.rs` currently derives a MAC — must accept the
   passed one for VMs).
3. **KubeVirt binding plugin**: register in the `KubeVirt` CR
   (`spec.configuration.network.binding.ectobase`) with `networkAttachmentDefinition` (our binding NAD)
   + `domainAttachmentType: tap` (+ `migration.method: link-refresh`); our binding CNI runs in the pod
   netns. (Or: plain `managedTap` if the DHCP question resolves favorably.)
4. **Primary network**: Multus `default: true` (our CNI already is the default delegate). Genuine
   primary-UDN is OVN-K-specific today — track as future alignment.
5. **Performance**: vhost-net + `spec.domain.devices.networkInterfaceMultiqueue` (multi-queue tap);
   validate tc/eBPF coexistence with the qemu tap fd + GSO/checksum offload.
6. **Live migration**: `link-refresh`; recreate bridge+tap + re-attach on the destination, move the
   underlay `/128`, re-`AttachInterface`/`Detach`, conntrack handling (tie into DecentralizedLiveMigration).
7. **Lifecycle**: detach + release IPAM + delete bridge/tap on VMI stop/migrate.

## 5. Vertical slice (build first): a real VM self-configures off our dataplane

Prove the **VM-facing datapath + all responders end-to-end with a real guest OS doing DHCP/SLAAC** — the
actual unproven thing — and resolve the topology question, before any CNI/binding code. Two parts:

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

**5b. Topology spike (design gate, ~½ day).** Resolve §3's pivotal question: read the KubeVirt
managedTap source to determine DHCP behaviour, and prototype the **Topology A** pod-netns bridge+tap by
hand (`ip link add br0 type bridge`, enslave a veth-end + a tap, boot qemu on the tap) to confirm the
VM reaches our responders through the bridge→veth→root-host-veth path. Output: a go/no-go on
`managedTap` vs a custom binding, and a validated topology for slice 2.

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
1. **Slice 5b spike first** (cheap, unblocks everything): read KubeVirt managedTap source for the DHCP
   question; hand-prototype the Topology A bridge+tap and confirm a VM reaches our responders. Decide
   managedTap-vs-custom-binding.
2. **Slice 5a**: extend `tap-vm-smoke.sh` to real DHCP self-config + a second endpoint + overlay ping
   (no `/dev/kvm`-less CI — it's a host smoke). This is the datapath confidence gate.
3. Then slice 2 (binding) per the 5b decision.

No half-finished code is in the tree — the next session starts from a clean, green `main`.

## 9. Open questions / risks

- **`managedTap` DHCP behaviour** (§3) — the single decision that shapes the binding work.
- **tc + vhost-net + multiqueue** coexistence on the tap; GSO/checksum-offload on the tap (disable, per
  the smoke + the guest-veth artifact).
- **VM MAC source** — explicit VMI `macAddress` vs KubeVirt copying the pod-interface MAC; our
  tap/veth + `PORT_META` must match.
- **Migration** conntrack + underlay `/128` movement + dest re-attach ordering.
- **Bridge in the path (Topology A)** adds a hop; acceptable (KubeVirt bridge binding does the same),
  revisit with Topology B/C only if throughput demands it.
