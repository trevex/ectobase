#!/usr/bin/env bash
# hack/clab/wan-down.sh — tear down the `clabwan` egress bridge + its nft masquerade (the inverse
# of wan-up.sh). Idempotent, needs root.
set -uo pipefail

BR=clabwan
NAT_POOL=203.0.113.0/28
iptables -t nat -D POSTROUTING -s "$NAT_POOL" ! -o "$BR" -j MASQUERADE 2>/dev/null || true
ip route del "$NAT_POOL" dev "$BR" 2>/dev/null || true
ip link del "$BR" 2>/dev/null || true
echo "clabwan down: bridge + masquerade removed"
