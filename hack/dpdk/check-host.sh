#!/usr/bin/env bash
# DPDK host-capability probe. Reports what this host can run and the exact remediation.
# Exit 0 if functional/CI testing (net_pcap/net_null + --no-huge) is possible — which is
# essentially always. Perf backends (af_xdp) additionally need reserved hugepages.
set -euo pipefail

say() { printf '%-22s %s\n' "$1" "$2"; }

echo "== DPDK host capability =="
say "kernel" "$(uname -r)"

hp_total=$(awk '/HugePages_Total/{print $2}' /proc/meminfo)
hp_size=$(awk '/Hugepagesize/{print $2" "$3}' /proc/meminfo)
say "hugepage size" "$hp_size"
say "hugepages reserved" "$hp_total"
mount | grep -q hugetlbfs && say "hugetlbfs" "mounted" || say "hugetlbfs" "NOT mounted"

[ -d /sys/kernel/iommu_groups ] && [ -n "$(ls -A /sys/kernel/iommu_groups 2>/dev/null)" ] \
  && say "IOMMU" "enabled" || say "IOMMU" "disabled/none"
[ -e /dev/vfio/vfio ] && say "vfio" "present" || say "vfio" "absent"

# Physical NICs (have a /device symlink) that are DOWN (candidate to bind); wlan/virtual excluded.
bindable=""
for n in /sys/class/net/*; do
  d=$(basename "$n")
  [ -e "$n/device" ] || continue
  case "$d" in lo|docker*|veth*|tailscale*|wlan*) continue;; esac
  bindable="$bindable $d"
done
say "bindable NICs" "${bindable:-<none — use vdev PMDs>}"

echo
echo "== verdict =="
echo "functional/CI (net_pcap + net_null, --no-huge): SUPPORTED (no setup needed)"
if [ "${hp_total:-0}" -gt 0 ]; then
  echo "af_xdp/perf backends (need hugepages): READY ($hp_total pages reserved)"
else
  echo "af_xdp/perf backends (need hugepages): reserve first ->"
  echo "    sudo sysctl -w vm.nr_hugepages=1024   # 2 GiB of 2M pages, runtime, no reboot"
  echo "    (persist on NixOS: boot.kernel.sysctl.\"vm.nr_hugepages\" = 1024;)"
fi
[ -z "$bindable" ] && echo "no spare NIC to bind -> vdev-only local dev (as designed)"
