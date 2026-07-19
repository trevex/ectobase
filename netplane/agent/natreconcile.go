package agent

import (
	"context"

	"github.com/trevex/ectobase/netplane/routebus"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// nat64WellKnownPrefix is the RFC 6052 well-known NAT64 prefix.
const nat64WellKnownPrefix = "64:ff9b::/96"

// PublicVNI is the reserved, control-plane-only aggregation VNI (dpservice ALL_VNI=0). The WAN edge
// originates the external default routes into it; egress-needing tenant nodes subscribe to it and
// import the defaults into their own tenant VNIs. It is NOT a wire/dataplane VNI.
const PublicVNI uint32 = 0

// NatBlock is a NAT block this node ANNOUNCES on the routebus (so every other node can return-route
// to us). It carries the owning NIC's underlay as the owner. It aliases the shared routebus.NatBlock
// so the agent and reflector use one canonical representation. The agent derives the blocks to
// announce from the CompiledNICs scheduled to this node (CompiledNIC.NAT), not from NATGateway.
type NatBlock = routebus.NatBlock

// ExternalRoute is an external (egress-SNAT) default route this node ANNOUNCES on the routebus. The
// WAN edge originates a default (0.0.0.0/0, ::/0, and 64:ff9b::/96 for NAT64) into the public VNI so
// source hypervisors SNAT + encap egress toward the edge's underlay.
type ExternalRoute struct {
	Vni      uint32
	Prefix   string // CIDR, e.g. "0.0.0.0/0" or nat64WellKnownPrefix
	Nexthop  string // the edge underlay /128
	External bool   // always true for these
}

// DesiredExternalRoutes returns the external default routes THIS node should announce. A node only
// originates them when it IS a WAN edge, i.e. it was started with --edge-loopback (edgeLoopback !=
// ""); non-edge nodes originate nothing. The edge is tenant-agnostic: it originates the external
// defaults ONCE into the public VNI (PublicVNI), nexthop = this edge's own anycast underlay.
// Egress-needing tenant nodes subscribe to the public VNI and import the defaults into their own VNIs.
func DesiredExternalRoutes(ctx context.Context, c client.Client, underlay, edgeLoopback string) ([]ExternalRoute, error) {
	if edgeLoopback == "" {
		return nil, nil // not a WAN edge: originate nothing
	}
	return []ExternalRoute{
		{Vni: PublicVNI, Prefix: "0.0.0.0/0", Nexthop: underlay, External: true},
		{Vni: PublicVNI, Prefix: nat64WellKnownPrefix, Nexthop: underlay, External: true},
		{Vni: PublicVNI, Prefix: "::/0", Nexthop: underlay, External: true},
	}, nil
}
