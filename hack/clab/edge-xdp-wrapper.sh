#!/bin/sh
# hack/clab/edge-xdp-wrapper.sh — entrypoint for the edge flowplane sidecar. Runs in the VyOS edge's
# netns (clab `network-mode: container:<edge>`), so it sees the edge's eth1 (fabric uplink) + eth2
# (WAN / clabwan). Waits for both links + the fabric ToR neighbour (the "router" on eth1, learned
# via the ToR's RA — sw{1,2}:eth5 have `no ipv6 nd suppress-ra`), then runs `serve --role edge`.
# SKB/generic XDP (clab veths have no native XDP). Mirrors config/deploy/flowplane.yaml's wrapper.
set -e
UPLINK=eth1          # fabric uplink (uplink_rx decaps egress here)
WAN=eth2             # clabwan uplink (wan_rx re-encaps nat_ip returns here)
UL=fd00:db8:0:9::e   # anycast edge underlay /128 (both edges; LOCAL + local-deliver key)

for i in $(seq 1 60); do
  ip link show "$UPLINK" >/dev/null 2>&1 && ip link show "$WAN" >/dev/null 2>&1 && break
  echo "edge-xdp: waiting for $UPLINK + $WAN ($i)"; sleep 1
done

GW_MAC=""
for i in $(seq 1 60); do
  # The ToR is the "router" neighbour on the fabric uplink (outer eth dst for redirected returns).
  GW_MAC=$(ip -6 neigh show dev "$UPLINK" | grep -m1 router | grep -o 'lladdr [0-9a-f:]*' | cut -d' ' -f2 || true)
  [ -n "$GW_MAC" ] && break
  echo "edge-xdp: waiting for fabric router neighbour on $UPLINK ($i)"; sleep 1
done
[ -z "$GW_MAC" ] && { echo "FATAL: no fabric router neighbour on $UPLINK" >&2; exit 1; }

echo "edge-xdp: uplink=$UPLINK wan=$WAN underlay=$UL gateway_mac=$GW_MAC"
export FLOWPLANE_SKB_MODE=1
exec flowplane serve --addr 127.0.0.1:1337 --role edge \
  --uplink "$UPLINK" --wan-uplink "$WAN" \
  --local-underlay "$UL" --gateway 169.254.0.1 --gateway-mac "$GW_MAC"
