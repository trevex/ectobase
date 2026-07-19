# Summary

[Introduction](./introduction.md)

# Architecture

- [Overview: the two planes](./architecture/overview.md)
- [The overlay: IPv6 underlay + IP-in-IPv6](./architecture/overlay.md)
- [Repository layout & crates](./architecture/layout.md)

# Dataplane (flowplane)

- [Datapath programs](./dataplane/programs.md)
- [XDP / tc / bpf kernel behaviour](./dataplane/kernel-xdp-tc.md)
- [The pure-core seam (Pkt / Maps traits)](./dataplane/pure-core.md)
- [BPF maps & state model](./dataplane/maps.md)
- [The flowplane CLI](./dataplane/cli.md)

# Control plane (netplane)

- [Control/data split & the route bus](./controlplane/route-bus.md)
- [The CRD API](./controlplane/crd-api.md)
- [Compilers: CompiledNIC](./controlplane/compilers.md)
- [CNI plugin](./controlplane/cni.md)

# Datapath features

- [Routing & multi-VNI tenancy](./features/routing-vni.md)
- [Distributed firewall](./features/firewall.md)
- [NAT gateway](./features/nat.md)
- [Load balancing (Maglev + DSR)](./features/loadbalancer.md)
- [VPC peering](./features/vpc-peering.md)
- [North-South WAN edge](./features/ns-edge.md)
- [QoS: EDT shaping & policing](./features/qos.md)
- [DHCP / ARP / IPv6 ND responders](./features/dhcp-arp-nd.md)

# Testing & conformance

- [Strategy: test at the right level](./testing/strategy.md)
- [The in-process sim](./testing/sim.md)
- [Conformance coverage map](./testing/conformance-map.md)

# Operations

- [Getting started (Nix + make)](./ops/getting-started.md)
- [The clab + kind fabric](./ops/clab-fabric.md)
- [HA & graceful restart](./ops/ha-restart.md)
- [Runbook & known gotchas](./ops/runbook.md)

# Contributing

- [Dev environment & workflows](./contributing/dev.md)
- [Design history (specs & plans archive)](./contributing/design-archive.md)
