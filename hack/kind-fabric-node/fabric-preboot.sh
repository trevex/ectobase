#!/usr/bin/env bash
# fabric-preboot.sh — make a kind node's kubelet Node InternalIP its BGP-fabric
# address, established BEFORE kubelet starts. Runs as a systemd oneshot ordered
# Before=kubelet.service (see fabric-preboot.service).
#
# The per-node underlay /64 is read from /etc/fabric/prefix (injected via kind
# extraMounts), e.g. "fd00:db8:0:1::/64". The node's own address is <prefix>::1
# on dummy0 (the same /64 flowplane infers and allocates endpoint /128s from), and
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

# Mount bpffs at /sys/fs/bpf so the flowplane dataplane can create its BPF pin dir
# (/sys/fs/bpf/flowplane). Cilium used to mount this (its mount-bpf-fs init container);
# with the kindnet CNI nothing does, so the node owns it. Idempotent.
mountpoint -q /sys/fs/bpf 2>/dev/null || mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

# NB: the k8s pod overlay is handled by Cilium in TUNNEL (VXLAN) mode — cross-node
# pod traffic is encapsulated to the peer NODE IP (reachable via the underlay BGP),
# so pod-CIDR routes NEVER enter this kernel FIB as `via <peer>` nor the underlay
# BGP fabric. (This replaced kindnet, whose naive `ip -6 route add <peer-pod-CIDR>
# via <peer-InternalIP>` EHOSTUNREACHes on our per-node /64 fabric because the peer
# InternalIP is a BGP-recursive, non-on-link gateway — no covering route or blackhole
# fixes that, since kindnet adds the route unconditionally and treats the error as
# fatal.) So preboot does NOT touch pod routing at all — Cilium owns it.

# 1) The node identity lives on dummy0 as a /128 — the Geneve VTEP. Under the pure
#    /128-VTEP fabric the ToR does NOT re-originate a /64; every ToR relays this /128
#    with ECMP, so it is reachable fabric-wide (including from the edges, for return
#    traffic + WAN masq of NodeAggr fd00:cafe::/32). WAN-bound egress therefore sources
#    from this /128 directly — no SLAAC /64 source is needed or created. It is a /128,
#    NOT the /64: it is up instantly (no BGP peer required) which is what kubelet needs
#    at start. flowplane still infers the underlay /64 from this address (within
#    --underlay-within fd00:cafe::/32).
ip link show dummy0 >/dev/null 2>&1 || ip link add dummy0 type dummy
ip -6 addr replace "${NODEIP}/128" dev dummy0
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

# The fabric default (::/0) arrives via BGP (the edges default-originate; the ToR
# re-advertises it to this host). No RA default, no SLAAC source — the /128 above is
# the egress source. (eth0 here is kind's own bridge — the fabric routers, not the
# compute nodes, are the ones detached from clab mgmt in P3b; kind's bridge default is
# demoted below so the fabric BGP default is preferred.)
# Demote the kind-bridge default (eth0, kind's own docker network — NOT clab mgmt,
# which the fabric routers drop via `network-mode: none`) below the fabric default so
# the BGP-learned ::/0 wins once FRR converges. eth0 stays as the pre-convergence
# image-pull fallback (kubeadm/CNI); steady-state egress + the in-fabric registry
# (fd00:29::5, via the containerd mirror hosts.toml) go over the fabric. One-shot:
# docker sets this default once at container start.
MGMTGW="$(ip -6 route show default dev eth0 2>/dev/null | awk '/via/{print $3; exit}')"
if [ -n "${MGMTGW:-}" ]; then
  ip -6 route del default via "$MGMTGW" dev eth0 2>/dev/null || true
  ip -6 route add default via "$MGMTGW" dev eth0 metric 4096 2>/dev/null || true
fi

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
  # Advertise the node's /128 VTEP identity (dummy0). The ToR relays it fabric-wide
  # with ECMP (no /64 re-origination); overlay traffic reaches this node by Geneve
  # encap to this /128, so no underlay /64 need be advertised.
  echo "  network ${NODEIP}/128"
  for u in $UPLINKS; do echo "  neighbor $u activate"; echo "  neighbor $u allowas-in 1"; done
  echo " exit-address-family"
} > /etc/frr/frr.conf
systemctl restart frr || systemctl start frr || true

# 4) Best-effort BRIEF wait for BGP convergence (underlay reachability) before kubelet.
#    Ensures the underlay (peer /64s, the reflector/apiserver loopbacks, and the
#    control-plane API server the Cilium agents reach via k8sServiceHost) is routable
#    by the time kubelet + the agents come up. CRITICAL: this oneshot gates
#    multi-user.target (WantedBy) via kubelet, and clab/kind abort the node if the
#    "Reached target Multi-User System" marker doesn't appear within kind's own
#    ~30s "Preparing nodes" wait. In the Go lab the fabric (VyOS switches/edges)
#    boots CONCURRENTLY with the kind clusters, so BGP is NOT converged at node boot
#    and a long wait here delays multi-user past that marker -> the node is deleted.
#    So keep this SHORT (well under kind's marker wait); Cilium/kubelet self-heal
#    once FRR converges. Override with FABRIC_BGP_TIMEOUT if a node needs longer.
CONVERGE_TIMEOUT="${FABRIC_BGP_TIMEOUT:-5}"
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
