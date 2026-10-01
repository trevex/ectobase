# Conformance map

flowplane started out measured against dpservice's Python conformance suite. That suite has been
removed from the tree; every test in it that applies to flowplane now has a named native
replacement: a sim test, a byte-parity anchor, or a live test. This page is the record of that
mapping, so you can see where each behaviour the old suite checked is asserted today, and which
ones were dropped and why.

!!! note "Test names on the left are dpservice's own"
    The left-hand column quotes dpservice's test names exactly, including ones with `vip` in them.
    ectobase has no object called a VIP: a load balancer has an address, and the 1:1
    bidirectional address is a `FloatingIP`. Renaming the upstream tests would break the mapping
    this page exists to record.

Native tests are named `module::function`. Sim tests live in `flowplane/flowplane-sim/src/`,
anchors in `flowplane/flowplane/tests/`, live tests in `test/lab/livetest/`. See
[Testing strategy](strategy.md) for what each tier can observe.

## Encapsulation (`test_encap.py`)

| dpservice test | Asserts | Native test |
|---|---|---|
| `test_ipv4_in_ipv6` | IPv4 guest traffic is tunnelled with the inner frame intact | `encap_test::guest_tx_v4_emits_tunnel_encap_and_leaves_inner_bytes_unchanged`, `encap_test::guest_tx_v4_local_delivery_emits_no_tunnel_decision`; anchor `anchor_guest_tx::guest_tx_encap_redirect_inner_unchanged_matches_native_sim` |
| `test_ipv6_in_ipv6` | IPv6 guest traffic is tunnelled | `guest_tx_v6_test::native_v6_egress_encaps_ipv6_in_ipv6_and_tracks_conntrack6` |

The outer header is the kernel Geneve device's job under `collect_md`, so the tests assert the
encap decision (`TunnelEncap`) and the unchanged inner frame. The decap side is covered by the
sim; its anchor can only show that the program fails safe without a tunnel key.

## Load balancing (`test_lb.py`, and the LB cases of `test_pf_to_vf.py`)

| dpservice test | Asserts | Native test |
|---|---|---|
| `test_network_lb_external_icmp_echo` | Maglev selection; the inbound packet is delivered | `lb_select_test::lb_select_returns_maglev_backend`, `ns_scenario_test::external_to_guest_encap_decap_fw_allow_ct` |
| `test_external_lb_relay` | relay to a remote backend | `lb_scenario_test::ew_lb_reforward_delivered`, `lb_scenario_test::ns_lb_delivered_with_lb_ip_allow` |
| `test_external_lb_icmp_error_relay` | an ICMP error about a load-balanced flow is relayed to its backend | `icmp_error_relay_test::icmp_error_to_lb_ip_relays_to_backend`, `icmp_error_relay_test::icmp_error_selects_on_embedded_inner_not_outer` |
| `test_network_lb_external_icmpv6_echo` | IPv6 WAN load-balancer address, Maglev selection, encap | `lb_scenario_test::ns_lb_v6_wan_rx_dsr_encode`, `lb_select_test::lb_select_v6_returns_maglev_backend` |
| `test_external_lb_relay_ipv6` | IPv6 relay to the backend | `lb_scenario_test::ns_lb_v6_wan_rx_dsr_encode` |
| `test_nat_to_lb_nat` | a NAT'd guest reaches a load balancer in the same VNI | `lb_scenario_test::ew_lb_reforward_delivered`, `nat_test::snat_distinct_sources_map_to_distinct_blocks` |
| `test_vip_nat_to_lb_on_another_vni` | east-west reforward to a load balancer across VNIs | `lb_scenario_test::ew_lb_reforward_delivered`, `vni_test::vni_isolation_*` |
| `test_pf_to_vf_lb_tcp` | delivery to a backend tap, IPv4; the firewall must admit it | `lb_scenario_test::ns_lb_delivered_with_lb_ip_allow`, `ns_scenario_test::external_to_guest_firewall_drop_on_unopened_port` |
| `test_pf_to_vf_lb_ipv6_tcp` | delivery to a backend tap, IPv6 | `lb_scenario_test::ns_lb_v6_wan_rx_dsr_encode`; anchor `anchor_lb::uplink_rx_lb_deliver_bytecode_fails_safe_without_tunnel_key` |

## Flows and conntrack (`test_flows.py`, `xtratest_flow_timeout.py`)

| dpservice test | Asserts | Native test |
|---|---|---|
| `test_nat_table_flush` | after a NAT delete and re-add, a new port is used | `conntrack_test::flow_timeout_expires_idle_entry`, `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums` |
| `test_neighnat_table_flush` | the neighbour-NAT relay stops, then resumes | `nat_test::snat_distinct_sources_map_to_distinct_blocks`, `lb_scenario_test::ew_lb_reforward_delivered` |
| `test_cntrack_nat_timeout_tcp` | a TCP flow ages out and its NAT port is recycled | `conntrack_test::flow_timeout_expires_idle_entry`, `conntrack_test::established_tcp_flow_survives_short_timeout_and_expires_at_long_timeout` |
| `test_external_lb_relay_timeout` | after a relayed flow ages out, the next packet picks the same backend | `lb_scenario_test::ew_lb_reforward_converges_no_loop` |
| `test_external_lb_relay_algorithm` | Maglev stays deterministic after a backend is removed | `lb_select_test::lb_select_returns_maglev_backend` |
| `test_syn_scan` | a SYN scan's flows age out and ports are recycled | `conntrack_test::flow_timeout_expires_idle_entry` |

## NAT (`test_nat.py`, and the NAT cases of `test_vf_to_pf.py`)

| dpservice test | Asserts | Native test |
|---|---|---|
| `test_nat_default_route` | SNAT on an external route, not on an internal prefix | `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums`, `nat_test::snat_no_op_for_internal_route` |
| `test_network_nat_external_icmp_echo` | SNAT out and DNAT back for ICMP echo | `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums`, `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port`; anchor `anchor_dnat::dnat_return_bytecode_fails_safe_without_tunnel_key` |
| `test_network_nat_pkt_relay` | a NAT return relayed to the port block's owner | `neighbor_nat_test`; anchor `anchor_wan_rx::nat_return_relay_matches_native_sim` |
| `test_network_nat_foreign_ip` | a packet to an address that is not a NAT address is dropped | `nat_test::snat_no_op_for_internal_route`, `firewall_test::deny_by_default_when_no_rules` |
| `test_network_nat_vip_co_existence_on_same_vm` | NAT and a load-balancer address on one VM | control plane only; datapath block isolation in `nat_test::snat_distinct_sources_map_to_distinct_blocks` |
| `test_network_nat_to_vip_on_another_vni` | SNAT out and DNAT back across VNIs | `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums`, `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port`, `vni_test::vni_isolation_*` |
| `test_vf_to_pf_network_nat_icmp` | NAT of ICMP out and back, identifier kept | `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port` (the same `ct_apply` path) |
| `test_vf_to_pf_network_nat_icmp_identifier_check` | two concurrent ICMP streams get distinct identifiers | `nat_test::snat_distinct_sources_map_to_distinct_blocks` |
| `test_vf_to_pf_network_nat_icmpv6` | NAT64 ICMP echo out and back | `nat64_test::nat64_egress_icmpv6_echo_becomes_icmpv4_echo`, `nat64_test::nat64_ingress_icmpv4_reply_becomes_icmpv6` |
| `test_vf_to_pf_network_nat_max_port_tcp` | the NAT port wraps; a second flow gets a distinct port | `nat_test::snat_distinct_sources_map_to_distinct_blocks` |
| `test_vf_to_pf_network_nat_tcp` | NAT TCP out and back | `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums`, `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port`; anchor `anchor_dnat::dnat_return_bytecode_fails_safe_without_tunnel_key` |
| `test_vf_to_pf_network_nat_tcp_with_ipv6` | NAT64 TCP egress | `nat64_test::nat64_egress_tcp_translates_snats_and_encaps`, `nat64_test::nat64_ingress_tcp_expands_to_ipv6` |
| `test_vf_to_pf_vip_snat` | egress SNAT to a configured address | `nat_test::snat_rewrites_src_ip_and_port_with_valid_checksums` (the same `snat_egress` path) |
| `test_vm_nat_async_tcp_icmperr` | an ICMP error comes back through NAT to the right guest | `nat_icmp_error_test::owner_delivers_the_icmp_error_to_the_guest_rewritten_for_its_socket`, `nat_icmp_error_test::edge_relays_the_icmp_error_to_the_port_block_owner` |
| `test_vf_to_pf_firewall_tcp_block` | the egress firewall blocks a non-matching port | `firewall_test::ingress_allow_rule_matches`, `firewall_test::deny_by_default_when_no_rules`, `ns_scenario_test::external_to_guest_firewall_drop_on_unopened_port` |
| `test_vf_to_pf_firewall_tcp_allow` | the egress firewall allows a matching port | `firewall_test::ingress_allow_rule_matches`; anchor `anchor_guest_tx::classifier_v4_verdicts_match_native_sim` |
| `test_vf_to_pf_firewall_ipv6_tcp_allow` | the IPv6 egress firewall allows | `firewall_test::v6_explicit_allow_matches`; anchor `anchor_guest_tx::classifier_v6_verdicts_match_native_sim` |
| `test_vf_to_pf_tcp_in_ipv6` | direct IPv6 egress, no NAT, round trip | `guest_tx_v6_test::native_v6_egress_encaps_ipv6_in_ipv6_and_tracks_conntrack6`, `ns_scenario_test::external_to_guest_encap_decap_fw_allow_ct` |

IPv6 NAT (NAT66), which dpservice did not have, is covered by `nat6_test` and live by
`TestNatEgressSmoke6` and `TestNatEgressReturn6`.

## DHCPv4 (`test_dhcpv4.py`)

| dpservice test | Asserts | Native test |
|---|---|---|
| `test_dhcpv4_vf0`, `test_dhcpv4_vf1` | DISCOVER to OFFER and REQUEST to ACK, with the assigned address and the DNS, MTU, hostname and classless-route options | `dhcp_test::discover_becomes_offer_with_configured_contents`, `dhcp_test::request_becomes_ack`, `dhcp_test::no_dhcp_config_falls_back_to_default_mtu_no_dns`, `dhcp_test::non_dhcp_frame_passes_unchanged`; anchors `anchor_dhcp::dhcp_bytecode_matches_native_sim`, `anchor_dhcp::dhcp_bytecode_matches_original_golden`; live `TestDhcpLeaseSmoke` |

## ARP and ND (`test_arp.py`, `test_ipv6_nd.py`)

| dpservice test | Asserts | Native test |
|---|---|---|
| `test_l2_arp` | an ARP request for the gateway gets a reply | `arp_nd_test::arp_request_becomes_reply`, `arp_nd_test::non_gateway_arp_passes_unchanged` |
| `test_nd` | a neighbour solicitation gets an advertisement with a valid checksum | `arp_nd_test::ns_becomes_neighbor_advertisement` |
| `test_l2_addr_once` | the guest MAC is learned, then updated | dropped, see below |

The ARP and ND responders have no anchor; they are asserted in the sim only. Router
advertisements, which dpservice did not test, are covered by
`arp_nd_test::rs_becomes_router_advertisement`.

## VNI isolation (`test_vni.py`)

| dpservice test | Asserts | Native test |
|---|---|---|
| `test_vni_reset` | resetting a VNI clears its routes and leaves others alone | datapath isolation in `vni_test::vni_isolation_route_miss_for_wrong_vni_returns_pass`, `vni_test::vni_isolation_same_dst_different_vni_yields_different_actions`; the reset API was dropped |
| `test_vni_existence`, `test_vni_neighnats`, `test_vni_dnat_reset` | dpservice's VNI lifecycle API | dropped, see below |

## Same-node delivery and firewall (`test_vf_to_vf.py`)

| dpservice test | Asserts | Native test |
|---|---|---|
| `test_vf_to_vf_tcp` | guest to guest on one node | `same_node_dest_fw_test::a_flow_the_destination_allows_is_delivered`; the same-node branch is `flowplane_core::egress::deliver`, which delivers locally when the interface entry is marked local |
| `test_vf_to_vf_vip_dnat` | guest to a load-balancer address on the same node, round trip | `lb_scenario_test::ew_lb_local_deliver_no_reforward`, `nat_test::dnat_return_tcp_rewrites_dst_ip_and_port` |
| `test1_vf_to_vf_firewall_tcp` | ingress allow on a matching source prefix | `firewall_test::ingress_allow_rule_matches` |
| `test2_vf_to_vf_firewall_tcp` | a drop on a non-matching source prefix | `firewall_test::deny_by_default_when_no_rules`, `same_node_dest_fw_test::a_flow_the_destination_denies_stays_denied` |
| `test3_vf_to_vf_ingress_firewall_tcp` | the destination's ingress firewall drops a non-matching source | `same_node_dest_fw_test::a_flow_the_destination_denies_stays_denied`, `lb_scenario_test::ns_lb_dropped_when_policy_misses_lb_ip`, `lb_scenario_test::ew_lb_anycast_dropped_without_policy` |
| `test_vf_to_vf_icmp` | same-node ICMP echo | `firewall_test::ingress_allow_rule_matches` (the same classifier path) |
| `test_vf_to_vf_icmpv6`, `test_vf_to_vf_ipv6_tcp` | same-node IPv6 | `same_node_dest_fw_test::v6_a_flow_the_destination_allows_is_delivered`, `firewall_test::v6_explicit_allow_matches` |

## Covered live, not in the sim

### DHCPv6 (`test_dhcpv6.py`)

`test_dhcpv6_vf0` and `test_dhcpv6_vf1` run a full Solicit, Request and Confirm exchange with
PXE vendor-class and boot-file URL options. DHCPv6 is not in the sim: its reply has a
runtime-variable option block written at runtime offsets, which the `Pkt` trait cannot express, so
the responder stays in `flowplane-ebpf` (`tc_dhcpv6_respond`). Its conformance is the live
`TestDhcpLeaseSmoke` (`test/lab/livetest/dhcp_test.go`), which runs the `tap-dhcp-probe` client
(`test/e2e/cmd/tap-dhcp-probe`) inside a guest's namespace and checks that the leased IA address
is the guest's configured IPv6 address and the client ID is echoed. It needs the lab.

### Restart (`xtratest_ha.py`)

dpservice's HA tests check an active and a backup instance synchronising MACs, NAT tables and
Maglev state. flowplane has no HA peer; it survives a restart by adopting its pinned maps and
rebuilding its bookkeeping from the `IFACE_META` journal. The applicable behaviour is covered by:

- `make ha` (`adopt_test`): maps re-bound, journal replayed, guest links re-pointed;
- `TestRestartContinuity`: forwarding continues across a live `flowplane` restart, with the same
  pinned guest link;
- `lb_scenario_test::ew_lb_reforward_converges_no_loop`: the same Maglev choice after a flow ages
  out.

The two-instance synchronisation tests themselves are dropped.

## Dropped

| dpservice test | What it tests | Why dropped |
|---|---|---|
| `test_virtsvc.py`, `xtratest_flow_timeout.py::test_virtsvc_tcp_timeout` | dpservice's virtual services, a DPDK-specific port-to-service NAT table | flowplane has no such feature. |
| The SR-IOV cases of `test_pf_to_vf.py` and `test_vf_to_pf.py` | physical-function to virtual-function representor forwarding | dpservice's representor model. The load-balancer, NAT and firewall cases in these files are mapped above. |
| `test_telemetry.py` | DPDK graph counters, heap stats, the Prometheus exporter | DPDK internals. |
| `test_zzz_grpc.py` | dpservice's gRPC API surface and error codes | flowplane's `DataplaneNode` API has its own handler tests (`flowplane/flowplane/src/handlers.rs` runs against an in-memory `ControlCore`). |
| `test_arp.py::test_l2_addr_once` | MAC learned from the representor, then updated by DHCP | dpservice's representor model. flowplane takes the guest MAC from the control plane, and its DHCPv4 responder updates `PORT_META` and the interface entries when a request arrives from a different MAC (`learn_mac`, called from `tc_guest_dhcp`). That update is eBPF glue with no sim or anchor test. |
| `test_vni.py::test_vni_existence`, `test_vni_neighnats`, `test_vni_dnat_reset` | dpservice's VNI lifecycle API | control-plane API only, with no datapath behaviour to observe. |
| `xtratest_ha.py`, the synchronisation tests | active and backup table synchronisation | flowplane restarts by adoption, not by peer sync. |

## Known gaps

Every applicable dpservice test has a native home, but not every native path has every kind of
test. These have no byte-parity anchor today:

- the DHCPv6 replies (covered live);
- the DHCP fallback MTU, when no DHCP configuration is set (covered by the sim);
- the ARP and ND replies (covered by the sim);
- the NAT64 translation in both directions (covered by the sim);
- the DHCPv4 responder's MAC learning (no test).

The first four are the list the `sim-anchor` target in the `Makefile` keeps.

## Where to go next

- [Testing strategy](strategy.md): the tiers and what each can observe.
- [The in-process sim](sim.md): how the sim tests above are built.
- [Firewall](../../features/firewall.md) and [NAT gateway](../../features/nat.md): the features
  most of these tests exercise.
