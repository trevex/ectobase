#!/bin/sh
# ceph-frr sidecar preboot: runs in the ceph container's netns (clab network-mode:
# container:clab-xdp-ipv6-fabric-ceph). Creates the announced /64 on dummy0, then hands off
# to the FRR image's normal entrypoint so bgpd advertises fd00:db8:0:5::/64 (see frr/ceph.conf).
#
# The kind hosts do this via their image's fabric-preboot oneshot; ceph is a plain container
# with no such oneshot, so this sidecar mirrors the edge*-xdp shared-netns pattern instead.
set -e

# dummy0 = the origin prefix. Idempotent (|| true) so a sidecar restart on an already-wired
# netns does not fail the preboot.
ip link add dummy0 type dummy 2>/dev/null || true
ip -6 addr add fd00:db8:0:5::1/64 dev dummy0 2>/dev/null || true
ip link set dummy0 up

# Hand off to the frrouting/frr:latest default entrypoint (`/sbin/tini -- /usr/lib/frr/docker-start`),
# which sources frr/daemons + frr/ceph.conf (bind-mounted at /etc/frr) and starts watchfrr/bgpd/bfdd.
exec /sbin/tini -- /usr/lib/frr/docker-start
