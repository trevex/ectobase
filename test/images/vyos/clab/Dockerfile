# VyOS packaged as a containerlab-native container node: the official clab
# packaging (mask getty/audit/kea, add a healthcheck, init as PID 1) plus the
# link-local fixes for unnumbered fabric interfaces. rootfs-<arch>.tar and the
# clab/ files live at the build-context root; buildx sets TARGETARCH per platform.
FROM scratch
ARG TARGETARCH
ADD rootfs-${TARGETARCH}.tar /

# Unnumbered fabric interfaces need an EUI-64 IPv6 link-local. The sysctl default
# gives one to interfaces as they are created; clab-lla-ensure re-asserts it and
# regenerates the LLA for any interface containerlab attaches post-boot that
# still ended up with addr_gen_mode=none (a race).
COPY clab/90-clab-addr-gen-mode.conf /etc/sysctl.d/90-clab-addr-gen-mode.conf
COPY clab/clab-lla-ensure.sh /usr/local/sbin/clab-lla-ensure
COPY clab/clab-lla-ensure.service /etc/systemd/system/clab-lla-ensure.service

RUN chmod +x /usr/local/sbin/clab-lla-ensure \
    && systemctl enable clab-lla-ensure.service \
    && for s in getty.target auditd.service kea-dhcp4-server.service kea-dhcp6-server.service; do \
         systemctl mask "$s" || true; \
       done

HEALTHCHECK --start-period=10s CMD systemctl is-system-running
CMD ["/sbin/init"]
