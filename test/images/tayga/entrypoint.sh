#!/bin/sh
# Userspace NAT64 gateway. Translates 64:ff9b::/96 -> IPv4 pool, MASQUERADEs the
# pool out eth2 (clabwan). Return v6 goes back to the fabric via the edge (V6_GW).
set -e

: "${V6_ADDR:?}"      # this node's addr on the edge link, e.g. fd00:64:1::2/64
: "${V6_GW:?}"        # the edge's addr on that link, e.g. fd00:64:1::1
: "${WAN_ADDR:?}"     # this node's addr on clabwan, e.g. 172.29.0.21/24
: "${WAN_GW:=172.29.0.1}"
: "${POOL:?}"         # v4 dynamic pool, e.g. 172.29.64.0/24
: "${POOL_ADDR:?}"    # tayga's own v4 addr inside the pool, e.g. 172.29.64.1

sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1
[ -e /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

# containerlab attaches the data veths AFTER the container starts — wait for
# eth1 (edge side) and eth2 (clabwan side) to appear before configuring them.
for _ in $(seq 1 120); do
  if ip link show eth1 >/dev/null 2>&1 && ip link show eth2 >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Interfaces (containerlab brings the links up; we address them).
ip addr replace "$V6_ADDR" dev eth1
ip link set eth1 up
ip addr replace "$WAN_ADDR" dev eth2
ip link set eth2 up
ip -6 route replace default via "$V6_GW"
ip route replace default via "$WAN_GW"

cat > /etc/tayga.conf <<EOF
tun-device nat64
ipv4-addr $POOL_ADDR
ipv6-addr ${V6_ADDR%%/*}
prefix 64:ff9b::/96
dynamic-pool $POOL
data-dir /var/lib/tayga
EOF

tayga --mktun
ip link set nat64 up
ip route replace 64:ff9b::/96 dev nat64
ip route replace "$POOL" dev nat64
iptables -t nat -C POSTROUTING -s "$POOL" -o eth2 -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$POOL" -o eth2 -j MASQUERADE

exec tayga -d
