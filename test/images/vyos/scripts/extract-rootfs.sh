#!/usr/bin/env bash
# Extract live/filesystem.squashfs from a VyOS ISO and convert it to a rootfs
# tar using userspace tools only (no root, no loop mount).
set -euo pipefail
iso="${1:?usage: extract-rootfs.sh <iso> <out-tar>}"
out="${2:?usage: extract-rootfs.sh <iso> <out-tar>}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo ">> extracting squashfs from $iso"
bsdtar -xf "$iso" -C "$work" live/filesystem.squashfs

echo ">> converting squashfs -> $out"
sqfs2tar "$work/live/filesystem.squashfs" > "$out"
echo ">> wrote $out ($(du -h "$out" | cut -f1))"
