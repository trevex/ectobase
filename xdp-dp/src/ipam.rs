//! Minimal per-network IPv4 allocator for sub-project ① (no CRD/state store yet).
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

pub struct Ipam {
    base: u32,    // network address (host order)
    hosts: u32,   // number of usable host addresses
    gateway: u32, // reserved
    used: BTreeSet<u32>,
}

impl Ipam {
    /// Build an allocator over `net`'s usable host range, reserving `gateway`.
    ///
    /// "Usable" excludes the network address and the broadcast address, matching the
    /// classic IPv4 convention (so a /30 yields 2 usable hosts, a /24 yields 254).
    pub fn new(net: ipnet::Ipv4Net, gateway: Ipv4Addr) -> anyhow::Result<Ipam> {
        let base = u32::from(net.network());
        let broadcast = u32::from(net.broadcast());
        // Usable hosts sit strictly between network and broadcast. For /31 and /32 there is no
        // such range, so `hosts` is 0 and every allocate() returns None.
        let hosts = broadcast.saturating_sub(base).saturating_sub(1);
        Ok(Ipam {
            base,
            hosts,
            gateway: u32::from(gateway),
            used: BTreeSet::new(),
        })
    }

    /// Return the lowest free host address that is neither the network, the broadcast, nor the
    /// gateway; `None` when the pool is exhausted.
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        // Usable hosts are base+1 ..= base+hosts (i.e. everything except network & broadcast).
        for offset in 1..=self.hosts {
            let addr = self.base + offset;
            if addr == self.gateway || self.used.contains(&addr) {
                continue;
            }
            self.used.insert(addr);
            return Some(Ipv4Addr::from(addr));
        }
        None
    }

    /// Mark `ip` free again so a later `allocate()` may hand it back out.
    pub fn release(&mut self, ip: Ipv4Addr) {
        self.used.remove(&u32::from(ip));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allocates_sequential_skipping_gateway() {
        let mut ipam =
            Ipam::new("10.0.0.0/24".parse().unwrap(), "10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(
            ipam.allocate().unwrap(),
            "10.0.0.2".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            ipam.allocate().unwrap(),
            "10.0.0.3".parse::<Ipv4Addr>().unwrap()
        );
    }
    #[test]
    fn release_makes_ip_reusable() {
        let mut ipam =
            Ipam::new("10.0.0.0/24".parse().unwrap(), "10.0.0.1".parse().unwrap()).unwrap();
        let a = ipam.allocate().unwrap();
        ipam.release(a);
        assert_eq!(ipam.allocate().unwrap(), a);
    }
    #[test]
    fn exhaustion_returns_none() {
        // /30 => 2 usable, minus gateway => 1 allocatable
        let mut ipam =
            Ipam::new("10.0.0.0/30".parse().unwrap(), "10.0.0.1".parse().unwrap()).unwrap();
        assert!(ipam.allocate().is_some());
        assert!(ipam.allocate().is_none());
    }
}
