# DPDK development (nfkit / flowplane-dpdk)

All tooling is in the nix devShell (`nix develop`): DPDK, `pkg-config`, `clang`
(bindgen), `libpcap`/`libbpf`/`numactl`. Check the host with `make dpdk-check`.

## Testing without a smartNIC (the normal case)

There is usually no spare NIC to bind to DPDK on a dev laptop (and none is needed).
Use DPDK **vdev** PMDs, selected by EAL args — same binary, no code change:

- **CI / functional:** `net_pcap` or `net_null` with `--no-huge` (DPDK allocates from
  the malloc heap instead of hugepages). Requires **zero host setup**. This is the
  `BPF_PROG_TEST_RUN` analogue: feed a pcap, assert the emitted pcap.
- **Laptop full-stack:** `net_af_xdp` on a `veth`/`netns` (real kernel datapath).
  Needs hugepages (below).

## Hugepages (only for af_xdp / perf, not for --no-huge CI)

Reserve at runtime (no reboot; non-persistent):

    sudo sysctl -w vm.nr_hugepages=1024      # 2 GiB of 2M pages

Persist on NixOS (`configuration.nix`):

    boot.kernel.sysctl."vm.nr_hugepages" = 1024;

hugetlbfs is already mounted at `/dev/hugepages` on this host.

## Building DPDK (dpdk-sys is self-contained)

`dpdk-sys/build.rs` downloads the pinned DPDK release (`25.11.2`) and builds it with
meson/ninja — no system/nix DPDK needed. Source + build are cached under
`~/.cache/dpdk-sys/` (override with `DPDK_CACHE_DIR`), so the ~2–5 min build happens
**once**; later builds (even after `cargo clean`) are a cache hit. To use a prebuilt
DPDK instead, set `DPDK_PREFIX=/path/to/install` (build.rs then skips download+build —
the escape hatch for a future `nix build` / CI derivation).

## Binding a real NIC (production / perf on a box with a spare NIC)

Needs IOMMU + vfio (this host has both). Bind a spare NIC to `vfio-pci` with
`dpdk-devbind.py`. Never bind your only/uplink NIC. Not applicable to laptop dev.

## EAL arg cheat-sheet

- No hugepages, no PCI, null port:  `-l 0 --no-huge -m 512 --no-pci --vdev net_null0 --file-prefix nfkit`
- pcap replay/record:               `--vdev net_pcap0,rx_pcap=in.pcap,tx_pcap=out.pcap`
- af_xdp on veth end `vv0`:         `--vdev net_af_xdp0,iface=vv0`
