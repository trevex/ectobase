package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Reconciler reads NetworkInterfaces scheduled to this node and derives the
// VNIs to subscribe to plus the local routes to announce.
type Reconciler struct {
	client       client.Client
	nodeID       string
	underlay     string
	edgeLoopback string    // if set, this node is a WAN edge; value = its UNIQUE control-plane loopback
	dp           Dataplane // local flowplane; used to program egress SNAT sources
	// appliedFw tracks the last set of firewall rules pushed to the dataplane so
	// ReconcileFirewall can diff and delete stale rules.
	appliedFw map[string]map[string]FwRule // interfaceID -> ruleID -> rule
	// appliedLbVips tracks the LB VIPs (id == VIP) this edge has AddLbVip'd, so ReconcileLB adds new
	// ones, deletes removed ones, and never re-adds (create_lb rejects duplicate ids).
	appliedLbVips map[string][]LbPort
	// appliedQoS tracks the last per-interface QoS pushed so ReconcileQoS only calls ConfigureQoS
	// when a NIC's QoS spec changes (level-triggered convergence).
	appliedQoS map[string]netv1.InterfaceQoS // interfaceID -> last-applied QoS
}

// Deps carries the runtime dependencies wired into a Reconciler at construction.
type Deps struct {
	// Underlay is this node's underlay IPv6 (used as the announced nexthop).
	Underlay string
	// Dataplane is the local flowplane so the reconciler can program egress SNAT.
	Dataplane Dataplane
	// EdgeLoopback marks this node as a WAN edge with the given UNIQUE
	// control-plane loopback (empty = not an edge).
	EdgeLoopback string
}

// NewReconciler builds a Reconciler from a kubeconfig path (empty = in-cluster).
func NewReconciler(kubeconfig, nodeID string, deps Deps) (*Reconciler, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig %q: %w", kubeconfig, err)
	}
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register scheme: %w", err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	return &Reconciler{
		client:       c,
		nodeID:       nodeID,
		underlay:     deps.Underlay,
		dp:           deps.Dataplane,
		edgeLoopback: deps.EdgeLoopback,
	}, nil
}

// Desired returns the VNIs to subscribe to, the local routes to announce, the local egress-NAT
// blocks to announce, the egress VNIs, and the peering-import map for this node — derived SOLELY
// from the CompiledNICs scheduled to this node (the agent reads no raw NetworkInterface, VPC, or
// NATGateway). As a side effect it programs local egress SNAT sources on the dataplane (idempotent:
// AddNatSource delete-then-adds).
func (r *Reconciler) Desired(ctx context.Context) (subs []uint32, announce []Route, announceNat []NatBlock, egressVNIs []uint32, peeringImports map[uint32][]PeerImport, err error) {
	var cnics netv1.CompiledNICList
	if err := r.client.List(ctx, &cnics); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("list compilednics: %w", err)
	}
	vniSet := map[uint32]struct{}{PublicVNI: {}} // always subscribe to the public VNI to learn defaults
	for i := range cnics.Items {
		c := &cnics.Items[i]
		if c.Spec.NodeName != r.nodeID || c.Spec.VNI == 0 {
			continue // only program/announce NICs scheduled to THIS node with an allocated VNI
		}
		vni := uint32(c.Spec.VNI)
		vniSet[vni] = struct{}{}
		// The route nexthop / NAT-block owner is the NIC's own underlay /128 (remote nodes encap to
		// it; the local UNDERLAY map resolves it to the tap). Fall back to the node underlay only
		// when the NIC hasn't been attached yet (CompiledNIC.UnderlayRoute empty).
		nexthop := c.Spec.UnderlayRoute
		if nexthop == "" {
			nexthop = r.underlay
		}
		for _, ip := range c.Spec.OverlayIPs {
			prefix, err := hostPrefix(ip)
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("compilednic %s/%s ip %q: %w", c.Namespace, c.Name, ip, err)
			}
			// Endpoint host routes are internal; egress-NAT default routes (external=true)
			// are distributed separately by a controller.
			announce = append(announce, Route{Vni: vni, Prefix: prefix, Nexthop: nexthop, External: false})
		}
		// Egress SNAT: program each local source and announce its NAT block (owner = the NIC's
		// underlay) so peers learn the neighbor-nat return route to us.
		for _, src := range c.Spec.NAT {
			if r.dp != nil {
				if err := r.dp.AddNatSource(ctx, vni, src.SourceIP, src.NATIP, uint32(src.PortMin), uint32(src.PortMax)); err != nil {
					log.Printf("AddNatSource %s->%s vni=%d: %v", src.SourceIP, src.NATIP, vni, err)
				}
			}
			announceNat = append(announceNat, NatBlock{
				Vni: vni, SourceIP: src.SourceIP, NatIP: src.NATIP,
				PortMin: uint32(src.PortMin), PortMax: uint32(src.PortMax), OwnerUnderlay: nexthop,
			})
		}
	}

	// WAN edge: if THIS node is a WAN edge (started with --edge-loopback), originate the
	// external default routes (0.0.0.0/0 and NAT64 64:ff9b::/96) into every NATGateway's
	// VPC VNI, nexthop'd at our own anycast underlay, so source hypervisors SNAT + encap
	// egress toward us. Non-edge nodes get nothing here.
	extRoutes, err := DesiredExternalRoutes(ctx, r.client, r.underlay, r.edgeLoopback)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	for _, er := range extRoutes {
		vniSet[er.Vni] = struct{}{} // subscribe to the VNI we originate into
		announce = append(announce, Route{Vni: er.Vni, Prefix: er.Prefix, Nexthop: er.Nexthop, External: er.External})
	}

	// LB backends: announce each backed VIP as an anycast overlay route (nexthop = this NIC's /128).
	// Multiple backend NICs announcing the same VIP → the fabric ECMPs across them. This is the E/W
	// load-balancer path; it reuses the plain route channel and needs no LB-specific datapath state.
	lbs, err := r.desiredLB(ctx)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	for _, lb := range lbs {
		prefix, err := hostPrefix(lb.VIP)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("lb vip %q: %w", lb.VIP, err)
		}
		announce = append(announce, Route{Vni: lb.Vni, Prefix: prefix, Nexthop: lb.NicUnderlay, External: false})
	}

	egressVNIs, err = r.desiredEgressVNIs(ctx)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// VPC peering: collect peer imports for local VNIs and union every peer VNI into the
	// subscription set so the Bus receives its routes and can import them.
	peeringImports, err = r.desiredPeeringImports(ctx)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	for _, imports := range peeringImports {
		for _, pi := range imports {
			if pi.PeerVNI != 0 {
				vniSet[pi.PeerVNI] = struct{}{}
			}
		}
	}

	// Re-materialize subs after all VNIs (local, egress, external, peer) have been added to vniSet.
	subs = subs[:0]
	for v := range vniSet {
		subs = append(subs, v)
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i] < subs[j] })

	return subs, announce, announceNat, egressVNIs, peeringImports, nil
}

// hostPrefix turns an overlay IP into its host CIDR ("/32" for v4, "/128" for v6).
func hostPrefix(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP")
	}
	if parsed.To4() != nil {
		return ip + "/32", nil
	}
	return ip + "/128", nil
}
