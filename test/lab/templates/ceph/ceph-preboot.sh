#!/bin/sh
# Generated from templates/ceph/ceph-preboot.sh — do not edit by hand.
# ceph-frr sidecar preboot: runs in the ceph netns (clab network-mode:
# container:clab-<name>-ceph-net). Creates the announced /64 on dummy0, then
# hands off to the FRR image's normal entrypoint so bgpd advertises the ceph /64
# (see ceph/frr.conf). ceph/demo joins this netns AFTER dummy0 carries the /64,
# so MON_IP binds cleanly.
#
# The Talos hosts create their /64 via their image's fabric-preboot oneshot;
# ceph is a plain container with no such oneshot, so this sidecar mirrors the
# edge shared-netns pattern instead.
set -e

# dummy0 = the origin prefix. Idempotent (2>/dev/null || true) so a sidecar
# restart on an already-wired netns does not fail the preboot.
ip link add dummy0 type dummy 2>/dev/null || true
ip -6 addr add {{ .CephMonAddr }}/64 dev dummy0 2>/dev/null || true
ip link set dummy0 up

# Hand off to the frrouting/frr:latest default entrypoint
# (`/sbin/tini -- /usr/lib/frr/docker-start`), which sources frr/daemons +
# frr/frr.conf (bind-mounted at /etc/frr) and starts watchfrr/bgpd/bfdd.
exec /sbin/tini -- /usr/lib/frr/docker-start
