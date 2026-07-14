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

# The node routes underlay/overlay and runs FRR — enable IPv6 forwarding (this
# used to be a clab `exec`; the node owns it now).
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

# NB: the k8s pod overlay is handled by Cilium in TUNNEL (VXLAN) mode — cross-node
# pod traffic is encapsulated to the peer NODE IP (reachable via the underlay BGP),
# so pod-CIDR routes NEVER enter this kernel FIB as `via <peer>` nor the underlay
# BGP fabric. (This replaced kindnet, whose naive `ip -6 route add <peer-pod-CIDR>
# via <peer-InternalIP>` EHOSTUNREACHes on our per-node /64 fabric because the peer
# InternalIP is a BGP-recursive, non-on-link gateway — no covering route or blackhole
# fixes that, since kindnet adds the route unconditionally and treats the error as
# fatal.) So preboot does NOT touch pod routing at all — Cilium owns it.

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

# 3) FRR: announce the node's /64 over unnumbered eBGP on the fabric uplink(s).
#    The node is now the BGP speaker (no sidecar). Uplinks are the clab fabric
#    links (eth1, and eth2 when dual-homed); they appear once clab wires them, so
#    FRR simply retries until the session establishes (identity is already local).
#    UPLINKS overridable via /etc/fabric/uplinks (space-separated); default eth1.
UPLINKS="eth1"
[ -r /etc/fabric/uplinks ] && UPLINKS="$(tr -d '\n' < /etc/fabric/uplinks)"
ROUTERID="10.0.2.$(printf '%s' "$BASE" | sed 's/.*:\([0-9a-f]*\)::$/\1/' | tr -cd '0-9')"
[ -n "$ROUTERID" ] || ROUTERID="10.0.2.1"
{
  echo "frr defaults datacenter"
  echo "hostname $(hostname)"
  echo "bfd"
  echo " profile fabric-fast"
  echo "  transmit-interval 150"
  echo "  receive-interval 150"
  echo "  detect-multiplier 3"
  echo " exit"
  echo "exit"
  for u in $UPLINKS; do echo "interface $u"; echo " no ipv6 nd suppress-ra"; done
  echo "router bgp 65100"
  echo " bgp router-id ${ROUTERID}"
  echo " bgp bestpath as-path multipath-relax"
  for u in $UPLINKS; do
    echo " neighbor $u interface remote-as external"
    echo " neighbor $u bfd profile fabric-fast"
  done
  echo " address-family ipv6 unicast"
  echo "  maximum-paths 64"
  echo "  network ${PREFIX}"
  for u in $UPLINKS; do echo "  neighbor $u activate"; echo "  neighbor $u allowas-in 1"; done
  echo " exit-address-family"
} > /etc/frr/frr.conf
systemctl restart frr || systemctl start frr || true

# 4) Best-effort wait for BGP convergence (underlay reachability) before kubelet.
#    Ensures the underlay (peer /64s, the reflector/apiserver loopbacks, and the
#    control-plane API server the Cilium agents reach via k8sServiceHost) is routable
#    by the time kubelet + the agents come up. BOUNDED: the uplink is wired by clab
#    shortly after boot and FRR converges within seconds; if not, proceed after the
#    timeout — NEVER hard-block kubelet. Keep it under systemd's TimeoutStartSec (90s)
#    and clab's k8s-kind deploy wait (120s).
CONVERGE_TIMEOUT="${FABRIC_BGP_TIMEOUT:-60}"
i=0
while [ "$i" -lt "$CONVERGE_TIMEOUT" ]; do
  if ip -6 route show proto bgp 2>/dev/null | grep -q .; then
    echo "fabric-preboot: BGP converged after ${i}s (peer routes in FIB)"
    break
  fi
  i=$((i + 1)); sleep 1
done
[ "$i" -ge "$CONVERGE_TIMEOUT" ] && \
  echo "fabric-preboot: BGP not converged in ${CONVERGE_TIMEOUT}s — proceeding (CNI will self-heal)"

echo "fabric-preboot: dummy0=${NODEIP}/${PLEN} ; kubelet --node-ip=${NODEIP} ; FRR announces ${PREFIX} on ${UPLINKS}"
