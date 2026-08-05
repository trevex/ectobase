#!/usr/bin/env bash
# Download a VyOS ISO and (optionally) verify its minisign signature.
#
#   fetch-iso.sh <url> <out> [<minisign-pubkey>]
#
# When a pubkey is given, the matching "<url>.minisig" is fetched and the ISO is
# verified with minisign before the download is accepted. Idempotent: skips the
# download if <out> already exists (but always re-verifies when a key is given).
set -euo pipefail
url="${1:?usage: fetch-iso.sh <url> <out> [minisign-pubkey]}"
out="${2:?usage: fetch-iso.sh <url> <out> [minisign-pubkey]}"
pubkey="${3:-}"

if [ ! -f "$out" ]; then
  echo ">> fetching $url"
  curl -fL --retry 3 --retry-delay 5 -o "$out.part" "$url"
  mv "$out.part" "$out"
fi

if [ -n "$pubkey" ]; then
  echo ">> fetching signature $url.minisig"
  curl -fL --retry 3 --retry-delay 5 -o "$out.minisig" "$url.minisig"
  echo ">> verifying $out with minisign"
  minisign -Vm "$out" -p "$pubkey" -x "$out.minisig"
  echo ">> signature OK"
fi
echo ">> ready: $out"
