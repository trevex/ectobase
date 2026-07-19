#!/bin/sh
# hack/clab/sw-pass-wrapper.sh — attach the trivial xdp_pass program to a ToR's edge-facing port.
# The WAN edge's wan_rx does bpf_redirect(fabric_uplink) for NAT returns; containerlab veth
# XDP_REDIRECT only delivers if the PEER (this ToR port) has an XDP program attached (veth
# ndo_xdp_xmit requirement — real NICs don't need this). Runs in the ToR's netns (shared via
# clab network-mode); waits for the port, then attaches. Native XDP (the loader prefers native and
# falls back to SKB); the fabric links are MTU 3000 so native attaches — see ipv6-fabric.clab.yml.
set -e
IFACE="${SW_PASS_IFACE:-eth5}"
for i in $(seq 1 60); do
  ip link show "$IFACE" >/dev/null 2>&1 && break
  echo "sw-pass: waiting for $IFACE ($i)"; sleep 1
done
echo "sw-pass: attaching xdp_pass to $IFACE"
exec flowplane pass --iface "$IFACE"
