#!/usr/bin/env bash
# fabric-preboot.sh — make a kind node's kubelet Node InternalIP its BGP-fabric
# address, established BEFORE kubelet starts. Runs as a systemd oneshot ordered
# Before=kubelet.service (see fabric-preboot.service).
#
# The per-node underlay /64 is read from /etc/fabric/prefix (injected via kind
# extraMounts), e.g. "fd00:db8:0:1::/64". The node's own address is <prefix>::1
# on dummy0 (the same /64 xdp-dp infers and allocates endpoint /128s from), and
# kubelet's --node-ip is set to it.
#
# node-ip is injected via KUBELET_EXTRA_ARGS in /etc/default/kubelet, NOT by
# rewriting kubeadm-flags.env: kind runs `kubeadm init/join` AFTER kubelet.service
# has already started, so kubeadm-flags.env does not exist at preboot time. But
# kind's kubelet unit runs `kubelet … $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS`,
# and a repeated --node-ip flag lets the LAST (ours) win over kubeadm's docker IP.
# /etc/default/kubelet persists and is read on every (re)start, so this survives
# kubelet crash-loops during bootstrap and the entrypoint's kubeadm-flags sed.
set -eu

PREFIX_FILE=/etc/fabric/prefix
if [ ! -r "$PREFIX_FILE" ]; then
  echo "fabric-preboot: no $PREFIX_FILE — leaving node on its default IP"
  exit 0
fi

PREFIX="$(tr -d '[:space:]' < "$PREFIX_FILE")"   # e.g. fd00:db8:0:1::/64
BASE="${PREFIX%/*}"                              # fd00:db8:0:1::
PLEN="${PREFIX#*/}"                              # 64
NODEIP="${BASE}1"                                # fd00:db8:0:1::1

# 1) The underlay /64 lives on dummy0 (next-hop-independent, up instantly — no BGP
#    peer required for the address to exist, which is what kubelet needs at start).
ip link show dummy0 >/dev/null 2>&1 || ip link add dummy0 type dummy
ip -6 addr replace "${NODEIP}/${PLEN}" dev dummy0
ip link set dummy0 up

# 2) kubelet --node-ip = the fabric address, via KUBELET_EXTRA_ARGS (last wins).
KF=/etc/default/kubelet
extra=""
if [ -f "$KF" ] && grep -q '^KUBELET_EXTRA_ARGS=' "$KF"; then
  extra="$(sed -n 's/^KUBELET_EXTRA_ARGS=//p' "$KF")"
  # drop any prior --node-ip we (or anyone) added, to stay idempotent
  extra="$(printf '%s' "$extra" | sed 's/--node-ip=[^ ]*//g')"
fi
printf 'KUBELET_EXTRA_ARGS=%s --node-ip=%s\n' "$extra" "$NODEIP" > "$KF"

echo "fabric-preboot: dummy0=${NODEIP}/${PLEN} ; kubelet --node-ip=${NODEIP}"
