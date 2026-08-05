# Package the Talos rootfs (extracted from the imager initramfs by
# scripts/extract-rootfs.sh) as the node container image -- the image
# `talosctl cluster create --provisioner docker` runs. Equivalent to the
# upstream ghcr.io/siderolabs/talos image, built locally from the pinned
# version. The per-arch rootfs-${TARGETARCH}.tar lives at the build-context root.
#
# In the rootfs, `sbin` is a symlink to `usr/bin` and the init binary is
# `usr/bin/init`, so /sbin/init is the correct entrypoint (matching upstream).
#
# The rootfs extracted from the initramfs is the *metal* rootfs. Talos switches
# to container-mode behavior (host kernel, no disk install) when
# /usr/etc/in-container is "true" -- upstream bakes this into its container image,
# so we add the same marker. (extract-rootfs.sh already strips usr/lib/modules and
# usr/lib/firmware, which are inert under the docker provisioner, matching
# upstream's lean node image.)
FROM scratch
# TARGETARCH is set by buildx per target platform (amd64/arm64), matching the
# rootfs-<arch>.tar names produced by scripts/extract-rootfs.sh.
ARG TARGETARCH
ADD rootfs-${TARGETARCH}.tar /
COPY container/in-container /usr/etc/in-container
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENTRYPOINT ["/sbin/init"]
