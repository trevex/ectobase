#!/bin/sh
# flowplane WAN-edge bring-up. This runs in the VyOS edge1 netns (the sidecar joins it via
# `network-mode: container:clab-<name>-edge1`) and attaches the eBPF datapath IN that netns:
# `uplink_rx` on the fabric uplinks (eth1/eth2) and `wan_rx` on the WAN uplink (eth3). XDP runs
# before the netns stack, so flowplane intercepts N/S traffic ahead of VyOS/FRR — giving the kind
# fabric a real N/S LoadBalancer edge (VyOS alone cannot run the eBPF datapath).
#
# SKB mode (kind veths are MTU 1500) => --pin-links false: generic-XDP silently drops the FIRST
# program when the SECOND attaches with pinned links, and the edge attaches two (uplink_rx + wan_rx).
# A dedicated --pin-dir keeps the edge's map pins off the node DaemonSet's shared bpffs.
set -e
UPLINK=eth1; EXTRA=eth2; WAN=eth3
UL="${EDGE_UNDERLAY:-fd00:ffff::e1}"
PIN_DIR="/sys/fs/bpf/flowplane-edge"

# Wait for clab to attach the uplink + WAN veths into the shared netns.
for i in $(seq 1 90); do
  if ip link show "$UPLINK" >/dev/null 2>&1 && ip link show "$WAN" >/dev/null 2>&1; then break; fi
  echo "edge-wrapper: waiting for $UPLINK + $WAN ($i)"; sleep 1
done

# Resolve the fabric next-hop (ToR) MAC so the edge can encap to backend nodes. Prefer the router
# neighbour; fall back to any resolved lladdr on the uplink.
GW_MAC=""
for i in $(seq 1 90); do
  GW_MAC=$(ip -6 neigh show dev "$UPLINK" | awk '/router/{for(j=1;j<=NF;j++) if($j=="lladdr"){print $(j+1); exit}}')
  [ -z "$GW_MAC" ] && GW_MAC=$(ip -6 neigh show dev "$UPLINK" | awk '/lladdr/{print $5; exit}')
  [ -n "$GW_MAC" ] && break
  echo "edge-wrapper: waiting for fabric neighbour on $UPLINK ($i)"; sleep 1
done
[ -z "$GW_MAC" ] && { echo "edge-wrapper FATAL: no fabric neighbour MAC on $UPLINK" >&2; exit 1; }
echo "edge-wrapper: uplink=$UPLINK extra=$EXTRA wan=$WAN underlay=$UL gw_mac=$GW_MAC"

exec flowplane serve --addr unix:///run/flowplane/dataplane.sock --role edge \
  --uplink "$UPLINK" --extra-uplink "$EXTRA" --wan-uplink "$WAN" \
  --local-underlay "$UL" --gateway 169.254.0.1 --gateway-mac "$GW_MAC" \
  --pin-dir "$PIN_DIR" --pin-links false
