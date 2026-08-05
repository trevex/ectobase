#!/usr/bin/env bash
# Extract the Talos root filesystem as a tar from the pinned imager image.
#
# Talos ships its rootfs as a squashfs (rootfs.sqsh) embedded in the initramfs;
# the imager image carries that initramfs at /usr/install/<arch>/initramfs.xz
# (a zstd-compressed cpio, despite the .xz name). We copy it out, unpack the
# cpio, and sqfs2tar the squashfs -- a userspace-only flow (no root, no loop
# mounts), mirroring the vyos repo's extract-rootfs.sh.
#
# We also drop usr/lib/modules and usr/lib/firmware: under the docker provisioner
# Talos uses the host kernel, so they are inert (upstream's node image strips them
# too). The filtering is archive-to-archive via bsdtar --exclude, so device nodes,
# ownership, and symlinks are preserved exactly (no extract-to-disk, no root).
#
# The resulting rootfs-<arch>.tar is packaged FROM scratch by container/Dockerfile
# into the Talos node container image (entrypoint /sbin/init -> usr/bin/init).
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$repo_root/versions.env"
: "${TALOS_IMAGER_IMAGE:?TALOS_IMAGER_IMAGE not set in versions.env}"

# Arch is the first arg (amd64 default for local runs); CI passes both. The amd64
# imager image carries /usr/install/{amd64,arm64}/ payloads, so extraction is pure
# userspace for either arch — no --platform, no emulation.
arch="${1:-amd64}"
out="${2:-rootfs-${arch}.tar}"

work="$(mktemp -d)"
cid=""
cleanup() {
  [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

echo ">> copying initramfs out of $TALOS_IMAGER_IMAGE ($arch)"
cid="$(docker create "$TALOS_IMAGER_IMAGE")"
docker cp "$cid:/usr/install/${arch}/initramfs.xz" "$work/initramfs.xz"

echo ">> decompressing initramfs (zstd) and extracting rootfs.sqsh"
zstd -d -f "$work/initramfs.xz" -o "$work/initramfs.cpio"
( cd "$work" && cpio -idm rootfs.sqsh < initramfs.cpio ) 2>/dev/null
[ -f "$work/rootfs.sqsh" ] || { echo "ERROR: rootfs.sqsh not found in initramfs" >&2; exit 1; }

echo ">> converting squashfs -> $out (stripping kernel modules + firmware)"
sqfs2tar "$work/rootfs.sqsh" \
  | bsdtar -c -f "$out" \
      --exclude 'usr/lib/modules' --exclude 'usr/lib/modules/*' \
      --exclude 'usr/lib/firmware' --exclude 'usr/lib/firmware/*' \
      @-
echo ">> wrote $out ($(du -h "$out" | cut -f1))"
