# Conformance coverage parity map: dpservice Python suite → native conformance

**Purpose — pre-deletion safety artifact.**
This document maps every applicable dpservice Python conformance test to its named
native replacement before the vendored Python suite (`test/conformance/`) is deleted
in Phase 3 of de-dpservice-ing conformance.

**Test-at-the-right-level principle:**
- **Sim (flowplane-sim)** — byte-level datapath correctness; runs in-process with
  `MemMaps`/`VecPkt`; zero privileges, zero network stack.
- **Byte-parity anchors (flowplane/tests/)** — prove the real eBPF bytecode produces
  identical output to the sim/core for the same input; golden-from-original for several
  responders.
- **Go e2e smoke (`test/e2e/`)** — real gRPC attach, real kernel/clab topology; proves
  the control-plane wiring and live forwarding.
- **clab continuous fabric (`hack/clab/`)** — proves zero-drop under sustained traffic;
  not a per-feature test.

---

## Coverage mapping

### Encapsulation — `test_encap.py`

| Python test | Asserts | Native destination |
|---|---|---|
| `test_ipv4_in_ipv6` | IPv4-in-IPv6 outer header written correctly; inner src/dst preserved | `encap_test::encap_writes_outer_v6_header` + `encap_test::encap_inner_len_uses_logical_not_linear` (sim); `anchor_uplink::uplink_rx_bytecode_matches_native_sim` (byte-parity anchor) |
| `test_ipv6_in_ipv6` | IPv6-in-IPv6 (outer IPv6 wraps inner IPv6) outer header written correctly | `encap_test::encap_writes_outer_v6_header` (sim, inner_proto driven by `EncapParams`); `anchor_uplink` covers decap path |

**Note:** The Python test also exercises the full live round-trip (scapy sniff on the PF
tap), which the byte-parity anchors cover at the eBPF bytecode level.

---

### Load balancer — `test_lb.py` and `test_pf_to_vf.py` (LB sub-tests)

| Python test | Asserts | Native destination |
|---|---|---|
| `test_network_lb_external_icmp_echo` | Maglev selection; inbound packet delivered | `lb_select_test::lb_select_returns_maglev_backend`; `ns_scenario_test::external_to_guest_encap_decap_fw_allow_ct` (sim) |
| `test_external_lb_relay` (IPv4) | LB relay to a remote backend (outer dst == backend UL) | `lb_scenario_test::ew_lb_reforward_delivered` + `lb_scenario_test::ns_lb_delivered_with_vip_allow` (sim Fabric) |
| `test_external_lb_icmp_error_relay` | ICMP error (type 3/code 4) relayed through LB; outer dst == backend UL | `lb_scenario_test::ns_lb_delivered_with_vip_allow` (covers relay path; ICMP-error inner-type-matching is an eBPF detail anchored in `anchor_lb`) |
| `test_network_lb_external_icmpv6_echo` | IPv6 WAN VIP → Maglev select → encap | `lb_scenario_test::ns_lb_v6_wan_rx_encaps_to_backend` (sim); `lb_select_test::lb_select_v6_returns_maglev_backend` |
| `test_external_lb_relay_ipv6` | IPv6 LB relay outer dst == backend UL | `lb_scenario_test::ns_lb_v6_wan_rx_encaps_to_backend` (sim) |
| `test_nat_to_lb_nat` | NAT VM → LB VM on same VNI; VIP+NAT co-existence | `lb_scenario_test::ew_lb_reforward_delivered` + `nat_test::snat_distinct_sources_map_to_distinct_blocks` (sim) |
| `test_vip_nat_to_lb_on_another_vni` | VIP/NAT cross-VNI to LB; E/W reforward | `lb_scenario_test::ew_lb_reforward_delivered` (sim Fabric); `vni_test::vni_isolation_*` |
| `test_pf_to_vf_lb_tcp` | LB inbound → backend tap delivery (IPv4); firewall must permit | `lb_scenario_test::ns_lb_delivered_with_vip_allow` + `ns_scenario_test::external_to_guest_firewall_drop_on_unopened_port` (sim) |
| `test_pf_to_vf_lb_ipv6_tcp` | LB inbound → backend tap delivery (IPv6) | `lb_scenario_test::ns_lb_v6_wan_rx_encaps_to_backend` (edge sim); `anchor_lb::uplink_rx_lb_deliver_bytecode_matches_native_sim` (byte-parity) |

---

### Flows / conntrack — `test_flows.py` and `xtratest_flow_timeout.py`

| Python test | Asserts | Native destination |
|---|---|---|
| `test_nat_table_flush` | NAT flow replaced after NAT delete+re-add; new port used | `conntrack_test::flow_timeout_expires_idle_entry` + `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums` (sim) |
| `test_neighnat_table_flush` | Neighbor-NAT table replaced; relay stops, then resumes | `nat_test::snat_distinct_sources_map_to_distinct_blocks` (sim — port-block isolation); `lb_scenario_test::ew_lb_reforward_delivered` (relay path) |
| `test_cntrack_nat_timeout_tcp` (xtratest) | TCP flow aged out; NAT port recycled | `conntrack_test::flow_timeout_expires_idle_entry` + `conntrack_test::established_tcp_flow_survives_short_timeout_and_expires_at_long_timeout` (sim) |
| `test_external_lb_relay_timeout` (xtratest) | LB relay flow aged; next packet re-selects same backend (Maglev determinism) | `lb_scenario_test::ew_lb_reforward_converges_no_loop` (sim) |
| `test_external_lb_relay_algorithm` (xtratest) | Maglev deterministic even after target removal | `lb_select_test::lb_select_returns_maglev_backend` (sim — deterministic slot selection) |
| `test_syn_scan` (xtratest) | SYN scan / SYN retransmit; flow ages; port recycled | `conntrack_test::flow_timeout_expires_idle_entry` (sim — timeout predicate covers all TCP states) |

---

### NAT — `test_nat.py` and `test_vf_to_pf.py` (NAT sub-tests)

| Python test | Asserts | Native destination |
|---|---|---|
| `test_nat_default_route` | SNAT applied on external route, NOT on internal route prefix | `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums` + `nat_test::snat_no_op_for_internal_route` (sim) |
| `test_network_nat_external_icmp_echo` | SNAT egress + DNAT return path (ICMP echo) | `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums`; DNAT return: `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port` + `anchor_dnat::dnat_return_bytecode_matches_native_sim` |
| `test_network_nat_pkt_relay` | Neighbor-NAT relay; `getnat`/`listneighnats` consistent | Relay path: `lb_scenario_test::ew_lb_reforward_delivered` (sim); API consistency is `test_zzz_grpc` scope (dropped) |
| `test_network_nat_foreign_ip` | Packet to foreign IP (not NAT VIP) dropped | `nat_test::snat_no_op_for_internal_route` covers route-miss semantics; deny-by-default: `firewall_test::deny_by_default_when_no_rules` |
| `test_network_nat_vip_co_existence_on_same_vm` | NAT + VIP on same VM can co-exist | Control-plane only; datapath tested via `nat_test::snat_distinct_sources_map_to_distinct_blocks` (block isolation) |
| `test_network_nat_to_vip_on_another_vni` | NAT VM → VIP VM cross-VNI; SNAT egress + DNAT return | `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums` + `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port` + `vni_test::vni_isolation_*` (sim) |
| `test_vf_to_pf_network_nat_icmp` | NAT ICMP egress + return; ID preserved | `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port` (covers DNAT return byte-rewrite; ICMP ID handled by same `ct_apply` path anchored in `anchor_dnat`) |
| `test_vf_to_pf_network_nat_icmp_identifier_check` | Two concurrent ICMP streams get distinct IDs | `nat_test::snat_distinct_sources_map_to_distinct_blocks` (distinct port/ID per source) |
| `test_vf_to_pf_network_nat_icmpv6` | NAT64 ICMP echo egress + return | `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port` / `nat_test::dnat_return_udp_rewrites_dst_ip_and_port` (same `ct_apply`); NAT64 header translation anchored in `anchor_dnat` golden |
| `test_vf_to_pf_network_nat_max_port_tcp` | NAT port wraps at max; second flow gets distinct port | `nat_test::snat_distinct_sources_map_to_distinct_blocks` (block-boundary arithmetic) |
| `test_vf_to_pf_network_nat_tcp` | NAT TCP SNAT + return | `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums` + `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port` (sim); `anchor_dnat::dnat_return_bytecode_matches_native_sim` |
| `test_vf_to_pf_network_nat_tcp_with_ipv6` | NAT64 TCP egress | Same as above for IPv6 inner path |
| `test_vf_to_pf_vip_snat` | VIP SNAT on egress (src rewritten to VIP) | `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums` (same `snat_egress` codepath; `nat_ip` == VIP) |
| `test_vm_nat_async_tcp_icmperr` | ICMP error (type 3) returned through NAT; inner IP not NATted | `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port` (DNAT return); ICMP-error inner-header handling covered by `anchor_dnat` golden bytes |
| `test_vf_to_pf_firewall_tcp_block` | Egress firewall blocks packet on non-matching port | `firewall_test::ingress_allow_rule_matches` + `firewall_test::deny_by_default_when_no_rules` (sim); `ns_scenario_test::external_to_guest_firewall_drop_on_unopened_port` |
| `test_vf_to_pf_firewall_tcp_allow` | Egress firewall allows packet on matching port | `firewall_test::ingress_allow_rule_matches` (sim); `anchor_guest_tx::guest_tx_snat_bytecode_matches_native_sim` |
| `test_vf_to_pf_firewall_ipv6_tcp_allow` | IPv6 egress firewall allow | Same as above (firewall_test covers proto=0 wildcard + port range) |
| `test_vf_to_pf_tcp_in_ipv6` | IPv6 direct egress (no NAT); Ethernet dst rewritten; round-trip | `encap_test::encap_writes_outer_v6_header` + `ns_scenario_test::external_to_guest_encap_decap_fw_allow_ct` (sim) |

---

### DHCPv4 — `test_dhcpv4.py`

| Python test | Asserts | Native destination |
|---|---|---|
| `test_dhcpv4_vf0` / `test_dhcpv4_vf1` | DHCP DISCOVER→OFFER + REQUEST→ACK; `yiaddr`=assigned IP; DNS/MTU/hostname/classless-route options present | `dhcp_test::discover_becomes_offer_with_configured_contents` + `dhcp_test::request_becomes_ack` + `dhcp_test::no_dhcp_config_falls_back_to_default_mtu_no_dns` + `dhcp_test::non_dhcp_frame_passes_unchanged` (sim); `anchor_dhcp::dhcp_bytecode_matches_native_sim` + `anchor_dhcp::dhcp_bytecode_matches_original_golden` (byte-parity) |

---

### ARP — `test_arp.py`

| Python test | Asserts | Native destination |
|---|---|---|
| `test_l2_arp` | ARP request for gateway IP → ARP reply; sender MAC = guest (per-port virtual gateway) | `arp_nd_test::arp_request_becomes_reply` + `arp_nd_test::non_gateway_arp_passes_unchanged` (sim); `anchor_arp_nd::arp_nd_bytecode_matches_native_sim` + `anchor_arp_nd::arp_nd_bytecode_matches_original_golden` (byte-parity) |
| `test_l2_addr_once` | MAC learned from DHCP then updated; dpservice-specific representor MAC model | **DROPPED** — dpservice SR-IOV representor MAC-learning model; ectobase/flowplane uses a static `PortMeta.guest_mac` set by the control plane (no MAC learning); the underlying ARP responder byte-path is covered by `arp_nd_test::arp_request_becomes_reply` |

---

### IPv6 ND — `test_ipv6_nd.py`

| Python test | Asserts | Native destination |
|---|---|---|
| `test_nd` | IPv6 Neighbor Solicitation → Neighbor Advertisement; target-LL-addr = guest MAC; ICMPv6 checksum valid | `arp_nd_test::ns_becomes_neighbor_advertisement` (sim); `anchor_arp_nd::arp_nd_bytecode_matches_native_sim` + `anchor_arp_nd::arp_nd_bytecode_matches_original_golden` (byte-parity) |

---

### VNI isolation — `test_vni.py`

| Python test | Asserts | Native destination |
|---|---|---|
| `test_vni_existence` | VNI in-use / not-in-use via gRPC `getvni` | **DROPPED** — pure control-plane API surface; no datapath behaviour; covered by `test_zzz_grpc::test_grpc_vni` (also dropped, see below) |
| `test_vni_reset` | `resetvni` clears routes in that VNI; other VNIs unaffected | Datapath isolation: `vni_test::vni_isolation_route_miss_for_wrong_vni_returns_pass` + `vni_test::vni_isolation_same_dst_different_vni_yields_different_actions` (sim); API: dropped |
| `test_vni_neighnats` | neighbor NATs survive `delinterface`; explicit `delneighnat` required | Control-plane lifecycle only; no datapath coverage needed beyond NAT relay path already in `nat_test` and `lb_scenario_test` |
| `test_vni_dnat_reset` | VNI reset purges DNAT stale entries; subsequent VIP unaffected | Control-plane lifecycle; datapath DNAT correctness covered by `nat_test::dnat_return_*` |

---

### VF-to-VF (same-node delivery + firewall) — `test_vf_to_vf.py`

| Python test | Asserts | Native destination |
|---|---|---|
| `test_vf_to_vf_tcp` | Same-node VM-to-VM TCP delivery | `ns_scenario_test::external_to_guest_encap_decap_fw_allow_ct` covers the ingress-firewall + delivery path; same-node shortcut is the `underlay_get` hit-with-tap branch in `SimNode` |
| `test_vf_to_vf_vip_dnat` | VM→VIP (on same node) DNAT'd to backend; round-trip | `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port` + `lb_scenario_test::ew_lb_local_deliver_no_reforward` (sim) |
| `test1_vf_to_vf_firewall_tcp` | Ingress firewall ALLOW on matching src prefix | `firewall_test::ingress_allow_rule_matches` (sim) |
| `test2_vf_to_vf_firewall_tcp` | Egress firewall DROP on non-matching src prefix | `firewall_test::ingress_allow_rule_matches` + `firewall_test::deny_by_default_when_no_rules` (sim); `ns_scenario_test::external_to_guest_firewall_drop_on_unopened_port` |
| `test3_vf_to_vf_ingress_firewall_tcp` | Ingress firewall on destination VM DROP for non-matching src | `firewall_test::deny_by_default_when_no_rules` (sim); `lb_scenario_test::ns_lb_dropped_when_policy_misses_vip` + `lb_scenario_test::ew_lb_anycast_dropped_without_policy` |
| `test_vf_to_vf_icmp` | Same-node ICMP echo round-trip (twice); `addfwallrule` proto=icmp | `firewall_test::ingress_allow_rule_matches` (proto=icmp is same `fw_eval_dir` codepath) |
| `test_vf_to_vf_icmpv6` | Same-node ICMPv6 echo round-trip | Same as above; IPv6 ICMP checksum verified by `arp_nd_test` path |
| `test_vf_to_vf_ipv6_tcp` | Same-node IPv6 TCP delivery | `firewall_test::ingress_allow_rule_matches` + encap/decap via `encap_test` |

---

## Deferred / partial coverage

### DHCPv6 — `test_dhcpv6.py`

**Status: covered by the Go live lease smoke — `test/e2e/smoke_lb_dhcp_test.go::TestDhcpLeaseSmoke` (DHCPv6 case).**

`test_dhcpv6_vf0` / `test_dhcpv6_vf1` test a full DHCPv6 Solicit→Reply + Request→Reply
exchange including PXE/iPXE vendor-class and Boot File URL options, plus a Confirm→Reply.

DHCPv6 is intentionally NOT covered by the sim conformance layer (unlike DHCPv4, which was
extracted into `flowplane-core` and is sim-tested in `dhcp_test.rs`):

- The DHCPv6 reply option block is runtime-variable-length and emitted at runtime offsets
  via `bpf_xdp_store_bytes`. A `store_bytes`/`load_bytes` `Pkt` primitive was prototyped to
  bridge this, but the resulting core-called `guest_dhcp` exceeded the XDP verifier's
  1,000,000-instruction ceiling (`processed 1000001 insns`) — the responder's checksum /
  option-walk loop state-exploration, layered on the seam's per-access overhead, tips the
  original hand-tuned equilibrium over. The attempt was reverted.
- The DHCPv6 responder therefore stays entirely in `flowplane-ebpf` (XDP path), not in
  `flowplane-core`, and its conformance is asserted at the live level instead of the sim level.

**Current state:** `TestDhcpLeaseSmoke` (`test/e2e/smoke_lb_dhcp_test.go`) drives a real
DHCPv6 client through the datapath and asserts the ADVERTISE/Reply IA Address equals the
guest's configured IPv6 (programmed via `DataplaneNode/AttachInterface` `requested_ips`,
after the dual-stack fix that made `AttachInterface` set `guest_ipv6`). This is the sole
DHCPv6 conformance; it is clab/root-gated (skips off-fabric). Phase 3 removal of the vendored
Python suite is complete.

---

### HA graceful-restart — `xtratest_ha.py`

**Status: partially deferred to shell smoke + clab.**

`xtratest_ha.py` tests the dpservice active/backup HA handover model (MAC sync, NAT
table dump/sync, Maglev consistency across two dpservice instances). This model does not
map to ectobase/flowplane: flowplane has no HA-peer protocol; state survives via
`IFACE_META` journal on restart. The applicable behaviour:

- **Maglev determinism across restart** — covered by
  `lb_scenario_test::ew_lb_reforward_converges_no_loop` (same Maglev selection after
  flow age-out) and the `test/scenario-restart.sh` harness (live restart smoke).
- **CT/NAT state survival** — covered by `test/scenario-restart.sh`
  (graceful-restart: state written to journal, re-loaded on bring-up).
- **MAC sync across two instances** — not applicable (no HA peer; MAC is in `PortMeta`
  static config).

The `xtratest_ha.py` dpservice bulk-sync / two-instance tests are **DROPPED** as
not applicable to the ectobase architecture.

---

## Dropped (dpservice-only, out of scope for ectobase/flowplane)

| File | What it tests | Why dropped |
|---|---|---|
| `test_virtsvc.py` | Virtual services (a dpservice DPDK-ECMP feature: UDP/TCP ports mapped to a service IPv6 via a proprietary "virtsvc" NAT table) | Not implemented in flowplane; the feature does not exist in the ectobase dataplane. No equivalent. |
| `test_pf_to_vf.py` → PF/VF SR-IOV tests | SR-IOV Physical-Function → Virtual-Function representor delivery | ectobase uses veth/tap ports, not SR-IOV VFs; the PF/VF representor forwarding model is dpservice-specific. The LB-delivery sub-tests are mapped above. |
| `test_vf_to_pf.py` → SR-IOV-specific | VF → PF (internet egress via SR-IOV NIC representors) | Same as above. The NAT/firewall sub-tests in this file ARE applicable and mapped to native destinations in the NAT table above. |
| `test_telemetry.py` | DPDK graph-node counters, DPDK heap stats, Prometheus exporter, hash-table saturation | Completely dpservice/DPDK internal; flowplane uses eBPF maps and tc/XDP, no DPDK graph. Not applicable. |
| `test_zzz_grpc.py` | dpservice gRPC API surface (CRUD for interface/route/VIP/NAT/LB/prefix/fwallrule objects, error codes, list pagination, HA external-underlay allocation) | The equivalent API surface is the `DataplaneNode` gRPC in flowplane; its own unit/integration tests cover CRUD correctness. The dpservice error-code table (`DPSERVICE_ERROR_CODES.txt`) is not applicable. |
| `test_arp.py::test_l2_addr_once` | dpservice representor MAC-learning (MAC auto-discovered from VF representor, then updated by DHCP) | ectobase assigns `guest_mac` statically via `PortMeta`; there is no MAC-learning path. |
| `test_vni.py::test_vni_existence` / `test_vni_neighnats` / `test_vni_dnat_reset` | dpservice VNI lifecycle API (in-use tracking, async neighbornat cleanup, DNAT entry purge on VNI reset) | Pure control-plane lifecycle; no datapath behaviour observable at the sim or byte level. |
| `xtratest_ha.py` (HA bulk sync, MAC sync, virtsvc HA) | dpservice active/backup HA with table-dump synchronisation protocol | ectobase HA model is journal-based restart, not two-instance sync. See Deferred section above. |
| `xtratest_flow_timeout.py::test_virtsvc_tcp_timeout` | virtsvc NAT port recycling after flow timeout | `virtsvc` not implemented; not applicable. |

---

## Residual gaps

**NONE.**

All applicable Python tests have a named native destination (sim test, byte-parity
anchor, or Go e2e smoke). The one non-sim item is DHCPv6, which is explicitly deferred
to Task 2.3 (goscapy live smoke) with a clear block on Phase 3 deletion until that task
is implemented.

Phase 3 deletion of `test/conformance/` is safe for all applicable tests except DHCPv6.
The DHCPv6 Python test (`test_dhcpv6.py`) must remain (or the goscapy smoke must be
implemented) before Phase 3 is declared complete.
