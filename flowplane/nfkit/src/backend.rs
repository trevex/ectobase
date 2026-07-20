//! Backend selection: the same datapath runs on any of these by producing the right EAL args.
//! Each `--vdev` makes the port appear as ethdev port 0 regardless of backend.

/// Which DPDK port backing to run on.
pub enum Backend {
    /// A real NIC by PCI address (multi-queue/RSS on real HW).
    Nic { pci: String },
    /// AF_XDP on a kernel netdev (needs hugepages + CAP_NET_ADMIN).
    AfXdp { iface: String, queues: u16 },
    /// pcap replay/record (functional/CI; no hugepages).
    Pcap { rx: String, tx: String },
    /// Kernel TAP.
    Tap { name: String },
    /// Null sink/source.
    Null,
}

impl Backend {
    /// Build the full EAL argv (argv[0] = `prog`). Software backends get `--no-huge`; vdev backends
    /// get their `--vdev`. Port 0 is always the configured backend.
    #[must_use]
    pub fn eal_args(&self, prog: &str) -> Vec<String> {
        let mut v = vec![prog.to_string(), "-l".into(), "0-3".into()];
        match self {
            Backend::Nic { pci } => {
                v.push("-a".into());
                v.push(pci.clone());
            }
            Backend::AfXdp { iface, queues } => {
                v.push("--vdev".into());
                v.push(format!(
                    "net_af_xdp0,iface={iface},start_queue=0,queue_count={queues}"
                ));
            }
            Backend::Pcap { rx, tx } => {
                push_soft(&mut v);
                v.push("--vdev".into());
                v.push(format!("net_pcap0,rx_pcap={rx},tx_pcap={tx}"));
            }
            Backend::Tap { name } => {
                push_soft(&mut v);
                v.push("--vdev".into());
                v.push(format!("net_tap0,iface={name}"));
            }
            Backend::Null => {
                push_soft(&mut v);
                v.push("--vdev".into());
                v.push("net_null0".into());
            }
        }
        v
    }
}

fn push_soft(v: &mut Vec<String>) {
    v.push("--no-huge".into());
    v.push("-m".into());
    v.push("512".into());
    v.push("--no-pci".into());
}
