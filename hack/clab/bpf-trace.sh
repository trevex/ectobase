#!/usr/bin/env bash
# bpf-trace.sh — WAN↔node XDP visibility for the clab fabric.
#
# THE PROBLEM this solves: flowplane's datapath is XDP. When a program returns
# XDP_REDIRECT / XDP_TX / XDP_DROP the packet is CONSUMED before the AF_PACKET tap,
# so plain `tcpdump` never sees it — a redirect that silently fails looks identical
# to "no packet". And the production image has no dlog. So packets "vanish into XDP".
#
# THE INSIGHT: XDP tracepoints (xdp:xdp_redirect{,_err}, xdp:xdp_devmap_xmit,
# xdp:xdp_exception) are KERNEL-GLOBAL — one kernel backs every clab container — so a
# single bpftrace on the host observes XDP redirects/drops across EVERY netns (kind
# nodes, VyOS edges, ToR switches) at once. bpf prog IDs are global too, so we can map
# each event back to a named program (uplink_rx / wan_rx / guest_tx / xdp_pass …).
#
# USAGE
#   hack/clab/bpf-trace.sh                 # live-trace all XDP redirects/drops (Ctrl-C to stop)
#   hack/clab/bpf-trace.sh -d 15           # trace for 15s then print a per-program summary
#   hack/clab/bpf-trace.sh legend          # just print the prog-id/ifindex → name map
#   hack/clab/bpf-trace.sh pcap <ctr> <if> # xdpdump one interface (sees XDP-consumed pkts + action)
#
# Reading the output:
#   REDIRECT ok   — a program redirected a packet (map-based, e.g. devmap) — success
#   REDIRECT ERR  — redirect FAILED (err<0). THIS is the "silently dropped" case tcpdump hides.
#   DEVMAP xmit   — a devmap actually transmitted; drops>0 / err<0 = the redirect landed nowhere.
#   XDP EXCEPTION — the program hit an abort/exception.
# A NAT-return that dies at the edge shows here as a wan_rx REDIRECT ERR or a DEVMAP drop.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$(id -u)" -eq 0 ]; then SUDO=""; elif [ -x /run/wrappers/bin/sudo ]; then SUDO=/run/wrappers/bin/sudo; else SUDO=sudo; fi

# bpftool, xdpdump and bpftrace all come from the devShell; resolve absolute paths so they survive
# the sudo/nsenter re-exec below. Run this script inside `nix develop`.
# Container name filter for the clab fabric (kind nodes + clab nodes).
CTR_RE='^(clab-xdp-ipv6-fabric-|k[0-9]+-(control-plane|worker))'

build_legend() {
  # prog_id → name and (container,ifindex) → iface, harvested from every container's
  # `ip -d link`. Emits two kinds of lines: "PROG <id> <name>" and "IF <ctr> <ifindex> <iface>".
  for c in $(docker ps --format '{{.Names}}' | grep -E "$CTR_RE"); do
    docker exec "$c" ip -d -o link show 2>/dev/null | awk -v c="$c" '
      { # ifindex is field 1 like "7:"; iface is field 2 like "eth1@if9:"
        idx=$1; sub(/:$/,"",idx); ifn=$2; sub(/[@:].*/,"",ifn);
        print "IF", c, idx, ifn
      }
      match($0, /prog\/xdp id [0-9]+ name [a-zA-Z0-9_]+/) {
        s=substr($0,RSTART,RLENGTH); split(s,a," "); print "PROG", a[3], a[5]
      }'
  done | sort -u
}

case "${1:-trace}" in
  legend)
    echo "== XDP program id → name (global) + interface map =="
    build_legend
    exit 0 ;;
  pcap)
    ctr="${2:?usage: bpf-trace.sh pcap <container> <iface>}"; ifc="${3:?need iface}"
    XDPDUMP=$(command -v xdpdump) || { echo "no xdpdump (run inside nix develop)" >&2; exit 1; }
    echo "== xdpdump $ctr:$ifc (Ctrl-C to stop) — shows packets entering XDP incl. those it consumes =="
    exec $SUDO nsenter -t "$(docker inspect -f '{{.State.Pid}}' "$ctr")" -n "$XDPDUMP" -i "$ifc" -x ;;
  map)
    # Dump + DECODE a flowplane state map on one node. bpf map ids are global, so we resolve the
    # node's map from its uplink_rx prog (attached to the node's fabric uplink) and dump from the host.
    node="${2:?usage: bpf-trace.sh map <node-container> [UNDERLAY|CONNTRACK|NAT_IPS|NEIGHBOR_NAT]}"
    want="${3:-UNDERLAY}"
    BPFTOOL=$(command -v bpftool) || { echo "no bpftool (run inside nix develop)" >&2; exit 1; }
    # prog id of uplink_rx on this node (from any fabric ethN carrying it)
    pid=$(docker exec "$node" sh -c 'for i in $(ls /sys/class/net|grep -E "^eth"); do ip -d link show $i 2>/dev/null|grep -oE "prog/xdp id [0-9]+ name uplink_rx"|grep -oE "[0-9]+"|head -1; done' 2>/dev/null | head -1)
    [ -z "$pid" ] && { echo "no uplink_rx prog on $node (is flowplane up there?)" >&2; exit 1; }
    mids=$($SUDO "$BPFTOOL" prog show id "$pid" 2>/dev/null | grep -oE "map_ids [0-9,]+" | cut -d' ' -f2 | tr ',' ' ')
    mid=""; for id in $mids; do [ "$($SUDO "$BPFTOOL" map show id "$id" 2>/dev/null | grep -oE 'name [A-Z_0-9]+' | cut -d' ' -f2)" = "$want" ] && mid=$id && break; done
    [ -z "$mid" ] && { echo "map $want not found on $node (prog $pid)" >&2; exit 1; }
    echo "== $node $want (map id $mid, via uplink_rx prog $pid) =="
    PYF=$(mktemp --suffix=.py); cat > "$PYF" <<'PY'
import sys, json
want = sys.argv[1]
def b(a):  # bpftool -j byte arrays are ["0x64",...]; return list[int]
    return [int(x,16) for x in a]
def le(bs): return int.from_bytes(bytes(bs), 'little')
def ip4(bs): return ".".join(str(x) for x in bs)
def ip6(bs):
    import ipaddress; return str(ipaddress.IPv6Address(bytes(bs)))
def mac(bs): return ":".join("%02x"%x for x in bs)
rows = json.load(sys.stdin)
if not rows: print("  (empty)"); sys.exit()
CT_FLAGS=[(0x01,"REWRITE_SRC"),(0x02,"REWRITE_DST"),(0x04,"SRC_NAT"),(0x08,"DST_LB"),(0x10,"DEFAULT"),(0x20,"FIREWALL"),(0x40,"NAT64")]
for r in rows:
    k=b(r["key"]); v=b(r.get("value",[]))
    if want=="UNDERLAY":
        print(f"  underlay={ip6(k[:16])}  vni={le(v[0:4])} tap_ifindex={le(v[4:8])} guest_mac={mac(v[8:14])}")
    elif want=="CONNTRACK":
        fl=v[20]; names="|".join(n for m,n in CT_FLAGS if fl&m)
        print(f"  vni={le(k[0:4])} {ip4(k[4:8])}:{int.from_bytes(k[12:14],'little')} -> {ip4(k[8:12])}:{int.from_bytes(k[14:16],'little')} proto={k[16]}  =>  xlate_ip={ip4(v[8:12])} xlate_port={int.from_bytes(v[12:14],'little')} flags=0x{fl:02x}({names})")
    elif want=="NAT_IPS":
        print(f"  vni={le(k[0:4])} nat_ip={ip4(k[4:8])}")
    elif want=="NEIGHBOR_NAT":
        print(f"  slot={le(k[0:4])} raw_value={' '.join('%02x'%x for x in v[:16])}")
    else:
        print("  key="+" ".join("%02x"%x for x in k)+"  value="+" ".join("%02x"%x for x in v))
PY
    $SUDO "$BPFTOOL" map dump id "$mid" -j 2>/dev/null | python3 "$PYF" "$want"
    rm -f "$PYF"
    exit 0 ;;
esac

DUR=0
[ "${1:-}" = "-d" ] && { DUR="${2:?-d needs seconds}"; }

echo "== building prog-id → name legend =="
LEGEND=$(build_legend)
echo "$LEGEND" | awk '$1=="PROG"{printf "  prog %-5s = %s\n",$2,$3}' | sort -u
# awk map file for annotating the live stream: "prog=<id>" → append (name)
NAMEMAP=$(mktemp); echo "$LEGEND" | awk '$1=="PROG"{print $2, $3}' | sort -u > "$NAMEMAP"

BT=$(command -v bpftrace) || { echo "ERROR: bpftrace not found (run inside nix develop)" >&2; exit 1; }
# Each tracepoint gets its OWN block (their arg structs differ — devmap_xmit has no prog_id).
BTPROG=$(mktemp --suffix=.bt)
cat > "$BTPROG" <<'BT'
tracepoint:xdp:xdp_redirect     { printf("REDIRECT ok   prog=%d if=%d -> to_if=%d map=%d idx=%d\n", args->prog_id, args->ifindex, args->to_ifindex, args->map_id, args->map_index); @redir_ok[args->prog_id]=count(); }
tracepoint:xdp:xdp_redirect_err { printf("REDIRECT ERR  prog=%d if=%d -> to_if=%d err=%d\n", args->prog_id, args->ifindex, args->to_ifindex, args->err); @redir_err[args->prog_id]=count(); }
tracepoint:xdp:xdp_devmap_xmit  { printf("DEVMAP xmit   from_if=%d -> to_if=%d sent=%d drops=%d err=%d\n", args->from_ifindex, args->to_ifindex, args->sent, args->drops, args->err); @devmap_sent+=args->sent; @devmap_drops+=args->drops; }
tracepoint:xdp:xdp_exception    { printf("XDP EXCEPTION prog=%d if=%d act=%d\n", args->prog_id, args->ifindex, args->act); @excep[args->prog_id]=count(); }
BT
[ "$DUR" -gt 0 ] && echo "interval:s:$DUR { exit(); }" >> "$BTPROG"

echo "== tracing XDP redirects/drops across ALL clab netns (kernel-global) =="
[ "$DUR" -gt 0 ] && echo "   (for ${DUR}s; a REDIRECT ERR or DEVMAP drops>0 = a silently-dropped packet)" || echo "   (Ctrl-C to stop)"

# annotate prog=<id> with (name) from the legend as the stream flows
annotate() { awk -v mf="$NAMEMAP" 'BEGIN{while((getline l<mf)>0){split(l,a," ");n[a[1]]=a[2]}}
  { if (match($0,/prog=[0-9]+/)){id=substr($0,RSTART+5,RLENGTH-5); if(id in n) sub(/prog=[0-9]+/,"prog="id"("n[id]")")} print; fflush() }'; }

$SUDO "$BT" "$BTPROG" 2>/tmp/bpf-trace.err | annotate
[ -s /tmp/bpf-trace.err ] && grep -iE "error|cannot|failed" /tmp/bpf-trace.err | head -3
rm -f "$NAMEMAP" "$BTPROG"
