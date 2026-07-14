#!/usr/bin/env bash
# hack/clab/wan-up.sh — create the `clabwan` egress bridge + host-agnostic NAT so the N-S egress
# fabric reaches the REAL internet. Adapted from ../icn/sandbox/scripts/wan-up.sh. Idempotent,
# needs root. No uplink interface is named — masquerade is keyed on the lab's public source range,
# so it works over WiFi/eth/VPN alike.
#
# The WAN edge (a VyOS node + xdp-dp sidecar) attaches to this bridge at 172.29.0.11. The datapath
# SNATs overlay sources to the `nat_ip` pool 203.0.113.0/28 on their own hypervisor and encaps to
# the edge; the edge decaps + forwards the plain nat_ip packet out here; THIS host masquerades the
# nat_ip range to the real uplink (the "clabwan trick"). Returns to a nat_ip route back to the edge,
# where `wan_rx` re-encaps them to the owning hypervisor.
set -euo pipefail

BR=clabwan
V4=172.29.0.1/24
V6=fd00:29::1/64
NAT_POOL=203.0.113.0/28   # the SNAT nat_ip pool (must differ from every test target)
EDGE1_V4=172.29.0.11      # edge1's clabwan address
EDGE2_V4=172.29.0.12      # edge2's clabwan address (HA: returns ECMP across both edges)

if ! ip link show "$BR" >/dev/null 2>&1; then
  ip link add name "$BR" type bridge
fi
ip link set "$BR" up
ip addr replace "$V4" dev "$BR"
ip addr replace "$V6" dev "$BR"

sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1

# Prefix-scoped masquerade. Only the nat_ip pool is masqueraded to the real uplink; the fabric
# underlay stays inside the lab. `iptables` is the iptables-nft wrapper on NixOS (no bare `nft`);
# the -C guard keeps re-runs idempotent (no duplicate rule).
iptables -t nat -C POSTROUTING -s "$NAT_POOL" ! -o "$BR" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$NAT_POOL" ! -o "$BR" -j MASQUERADE

# Return route: replies to a nat_ip come back to this host (un-NAT'd by conntrack) and must be
# routed to an edge, where wan_rx catches them. The host runs no BGP, so this is static — ECMP
# across both HA edges (either edge re-encaps any return; the neighbor-NAT table is on both).
ip route replace "$NAT_POOL" \
  nexthop via "$EDGE1_V4" dev "$BR" \
  nexthop via "$EDGE2_V4" dev "$BR"

echo "clabwan up: $V4 / $V6 ; masquerade $NAT_POOL -> real uplink ; return $NAT_POOL ECMP via $EDGE1_V4,$EDGE2_V4"
