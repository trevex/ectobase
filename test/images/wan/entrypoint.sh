# shellcheck shell=bash
#
# wan-simulator: recreate the lab WAN egress inside this container's netns.
#
# Container-local port of the former host-side WanUp: bridge the lab-facing links
# into one L2 segment, hold the gateway addresses, enable forwarding, program the
# NAT masquerade, and install the ECMP return routes into the fabric. Everything
# lives in this netns, so N labs run side by side without host-global collisions.
#
# writeShellApplication supplies the shebang and `set -o errexit -o nounset -o
# pipefail`; this file is the body only.

BRIDGE="${WAN_BRIDGE:-br0}"
UPLINK="${WAN_UPLINK:-eth0}"
NFT_TABLE="${WAN_NFT_TABLE:-wan}"
MTU="${WAN_MTU:-1500}"

log() { printf '[wan] %s\n' "$*"; }

read -ra lan_ifaces <<< "${WAN_LAN_IFACES:-eth1 eth2 eth3 eth4}"
read -ra masq_v4 <<< "${WAN_MASQ_V4:-}"
read -ra masq_v6 <<< "${WAN_MASQ_V6:-}"

# --- shared L2 segment: bridge the lab-facing interfaces -------------------
# containerlab attaches the veth links into this netns shortly AFTER the
# container starts, so wait for each interface to appear before enslaving it —
# skipping absent ones leaves the bridge (and thus egress) dead until redeploy.
ip link add name "$BRIDGE" type bridge 2>/dev/null || true
ip link set "$BRIDGE" mtu "$MTU" up
for ifc in "${lan_ifaces[@]}"; do
  waited=0
  while ! ip link show "$ifc" >/dev/null 2>&1; do
    if (( waited >= 300 )); then
      log "lab interface $ifc did not appear after 30s — skipping"
      break
    fi
    sleep 0.1
    waited=$((waited + 1))
  done
  ip link show "$ifc" >/dev/null 2>&1 || continue
  ip link set "$ifc" master "$BRIDGE" mtu "$MTU" up
done

# --- gateway addresses on the segment --------------------------------------
if [[ -n "${WAN_V4_ADDR:-}" ]]; then ip -4 addr replace "$WAN_V4_ADDR" dev "$BRIDGE"; fi
if [[ -n "${WAN_V6_ADDR:-}" ]]; then ip -6 addr replace "$WAN_V6_ADDR" dev "$BRIDGE"; fi

# --- forwarding (namespaced /proc — no procps needed) ----------------------
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# --- NAT masquerade toward the uplink (mirrors the former nftRuleset) ------
nft delete table inet "$NFT_TABLE" 2>/dev/null || true
{
  printf 'table inet %s {\n' "$NFT_TABLE"
  printf '  chain postrouting {\n'
  printf '    type nat hook postrouting priority srcnat;\n'
  for p in "${masq_v4[@]}"; do
    printf '    ip saddr %s oifname != "%s" masquerade\n' "$p" "$BRIDGE"
  done
  if (( ${#masq_v6[@]} )); then
    printf -v v6list '%s, ' "${masq_v6[@]}"
    printf '    ip6 saddr { %s } oifname != "%s" masquerade\n' "${v6list%, }" "$BRIDGE"
  fi
  printf '  }\n}\n'
} | nft -f -

# --- return routes into the fabric (ECMP via the edges) --------------------
# WAN_ROUTES: ';'-separated entries, each "PREFIX NH1,NH2,...".
IFS=';' read -ra route_entries <<< "${WAN_ROUTES:-}"
for entry in "${route_entries[@]}"; do
  read -r prefix nexthops <<< "$entry"
  [[ -n "$prefix" ]] || continue
  ipargs=(-6 route replace "$prefix")
  IFS=',' read -ra nhs <<< "$nexthops"
  for nh in "${nhs[@]}"; do
    ipargs+=(nexthop via "$nh" dev "$BRIDGE")
  done
  ip "${ipargs[@]}"
done

log "WAN up — bridge=$BRIDGE uplink=$UPLINK table=$NFT_TABLE"
exec sleep infinity
