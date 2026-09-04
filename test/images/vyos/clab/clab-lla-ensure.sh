#!/bin/sh
# Ensure every containerlab-attached unnumbered data interface (eth1..eth9) has
# an EUI-64 IPv6 link-local. containerlab moves the veths into this netns AFTER
# the container has booted and can leave addr_gen_mode=none (a race the udev rule
# does not always win — observed on one interface of one edge). Re-assert
# addr_gen_mode=0 for a bounded window and regenerate the LLA on any straggler.
#
# Safe to run alongside live BGP: writing addr_gen_mode=0 when already 0 is a
# no-op, and we only bounce an interface that is MISSING its link-local — an
# interface that already has one (and thus a working unnumbered session) is left
# untouched, so established sessions never flap.
n=0
while [ "$n" -lt 60 ]; do
  for p in /sys/class/net/eth[1-9]; do
    [ -e "$p" ] || continue
    i=${p##*/}
    echo 0 > "/proc/sys/net/ipv6/conf/$i/addr_gen_mode" 2>/dev/null
    if ! ip -6 addr show dev "$i" scope link 2>/dev/null | grep -q 'inet6 fe80'; then
      ip link set "$i" down 2>/dev/null
      ip link set "$i" up 2>/dev/null
    fi
  done
  n=$((n + 1))
  sleep 1
done
