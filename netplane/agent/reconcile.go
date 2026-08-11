package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	corev1 "k8s.io/api/core/v1"
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
	if err := compiledv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register compiled scheme: %w", err)
	}
	// corev1 for StampNodePrefix's Node get/patch (the /64 underlay annotation the broker reads).
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register corev1 scheme: %w", err)
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

// ipKey is the unique index key for a locally-attached interface: within a VNI overlay IPs are
// unique, and across VNIs the VNI disambiguates, so (VNI, overlay IP) is a globally sound join key.
// This is critical for overlapping VPC subnets: two VPCs can both use 10.0.0.1, so keying by IP
// alone causes last-writer-wins collisions.
type ipKey struct {
	vni uint32
	ip  string
}

// Desired returns the VNIs to subscribe to, the local routes to announce, the local egress-NAT
// blocks to announce, the egress VNIs, and the peering-import map for this node — derived SOLELY
// from the CompiledNICs locally attached on this node (the agent reads no raw NetworkInterface, VPC,
// or NATGateway). A CompiledNIC is "local" iff the dataplane's ListInterfaces reports a locally
// attached interface with a matching (VNI, overlayIP) pair, regardless of any pre-declared nodeName.
// As a side effect it programs local egress SNAT sources on the dataplane (idempotent:
// AddNatSource delete-then-adds).
func (r *Reconciler) Desired(ctx context.Context) (subs []uint32, announce []Route, announceNat []NatBlock, egressVNIs []uint32, peeringImports map[uint32][]PeerImport, err error) {
	// Node-local facts: the interfaces attached on this node and their underlay /128s come from the
	// local dataplane (the underlay is node-local state the dataplane allocates, not central config).
	// Overlay host routes announce from these; ulByKey indexes (VNI, overlay IP) -> node-local
	// underlay so central NAT policy can be joined to the correct node-local nexthop.
	var locals []LocalInterface
	if r.dp != nil {
		locals, err = r.dp.ListInterfaces(ctx)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("list interfaces: %w", err)
		}
	}
	vniSet := map[uint32]struct{}{PublicVNI: {}} // always subscribe to the public VNI to learn defaults
	// ulByKey: (VNI, overlay IP) -> node-local underlay nexthop, sound under overlapping VPC subnets.
	ulByKey := map[ipKey]string{}
	// localSet: set of (VNI, overlay IP) pairs attached on this node, used to decide if a CompiledNIC
	// is local without relying on a pre-declared nodeName.
	localSet := map[ipKey]struct{}{}
	for li := range locals {
		iface := &locals[li]
		if iface.Vni == 0 {
			continue
		}
		vniSet[iface.Vni] = struct{}{}
		nexthop := iface.Underlay
		if nexthop == "" {
			nexthop = r.underlay // attached without an underlay yet; fall back to the node underlay
		}
		for _, ip := range iface.OverlayIPs {
			k := ipKey{iface.Vni, ip}
			ulByKey[k] = nexthop
			localSet[k] = struct{}{}
			prefix, err := hostPrefix(ip)
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("interface %s ip %q: %w", iface.InterfaceID, ip, err)
			}
			// Endpoint host routes are internal; egress-NAT default routes (external=true)
			// are distributed separately by a controller.
			announce = append(announce, Route{Vni: iface.Vni, Prefix: prefix, Nexthop: nexthop, External: false})
		}
	}

	// Central egress-SNAT policy: each CompiledNIC.NAT allocation for a source attached on THIS node,
	// joined to that source's node-local underlay. Program the local SNAT source and announce its NAT
	// block (owner = the source's node-local underlay) so peers learn the neighbor-nat return route.
	// A NIC is "local" iff its (VNI, overlayIP) is present in localSet — no nodeName dependency.
	var cnics compiledv1.CompiledNICList
	if err := r.client.List(ctx, &cnics); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("list compilednics: %w", err)
	}
	for i := range cnics.Items {
		c := &cnics.Items[i]
		if !localNIC(c, localSet) {
			continue
		}
		for _, src := range c.Spec.NAT {
			k := ipKey{uint32(c.Spec.VNI), src.SourceIP}
			owner, ok := ulByKey[k]
			if !ok || k.vni == 0 {
				continue // source not attached locally yet; skip until ListInterfaces reports it
			}
			if r.dp != nil {
				if err := r.dp.AddNatSource(ctx, k.vni, src.SourceIP, src.NATIP, uint32(src.PortMin), uint32(src.PortMax)); err != nil {
					log.Printf("AddNatSource %s->%s vni=%d: %v", src.SourceIP, src.NATIP, k.vni, err)
				}
			}
			announceNat = append(announceNat, NatBlock{
				Vni: k.vni, SourceIP: src.SourceIP, NatIP: src.NATIP,
				PortMin: uint32(src.PortMin), PortMax: uint32(src.PortMax), OwnerUnderlay: owner,
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
	lbs, err := r.desiredLB(ctx, ulByKey, localSet)
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

// localNIC reports whether any of the CompiledNIC's overlay IPs is locally attached on this node,
// matched by the unique (VNI, overlayIP) key. This is sound under overlapping VPC subnets: two VPCs
// may share the same overlay IP, but they have distinct VNIs, so (VNI, IP) is globally unique.
func localNIC(c *compiledv1.CompiledNIC, local map[ipKey]struct{}) bool {
	for _, ip := range c.Spec.OverlayIPs {
		if _, ok := local[ipKey{uint32(c.Spec.VNI), ip}]; ok {
			return true
		}
	}
	return false
}

// listLocalIfaces returns the dataplane's locally-attached interfaces, or nil if dp is unset.
func (r *Reconciler) listLocalIfaces(ctx context.Context) ([]LocalInterface, error) {
	if r.dp == nil {
		return nil, nil
	}
	locals, err := r.dp.ListInterfaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	return locals, nil
}

// underlayByKey asks the local dataplane for its attached interfaces and returns a map from
// (VNI, overlay IP) to the node-local underlay /128 the dataplane allocated. Used to join central
// NAT/LB policy to the correct node-local nexthop without any central round-trip. Keying by
// (VNI, overlayIP) — not overlayIP alone — is sound under overlapping VPC subnets.
func (r *Reconciler) underlayByKey(ctx context.Context) (map[ipKey]string, map[ipKey]struct{}, error) {
	out := map[ipKey]string{}
	localSet := map[ipKey]struct{}{}
	locals, err := r.listLocalIfaces(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, li := range locals {
		if li.Vni == 0 {
			continue
		}
		nexthop := li.Underlay
		if nexthop == "" {
			nexthop = r.underlay
		}
		for _, ip := range li.OverlayIPs {
			k := ipKey{li.Vni, ip}
			out[k] = nexthop
			localSet[k] = struct{}{}
		}
	}
	return out, localSet, nil
}

// interfaceIDByKey asks the local dataplane for its attached interfaces and returns a map from
// (VNI, overlay IP) to the REAL interface id the dataplane knows it by (the id the CNI attached
// with), plus a localSet of all (VNI, IP) pairs attached here. Used to target per-NIC config
// (firewall) at the actual fabric interface. Keyed by (VNI, IP) for VPC-overlap safety.
func (r *Reconciler) interfaceIDByKey(ctx context.Context) (map[ipKey]string, map[ipKey]struct{}, error) {
	out := map[ipKey]string{}
	localSet := map[ipKey]struct{}{}
	locals, err := r.listLocalIfaces(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, li := range locals {
		if li.Vni == 0 {
			continue
		}
		for _, ip := range li.OverlayIPs {
			k := ipKey{li.Vni, ip}
			out[k] = li.InterfaceID
			localSet[k] = struct{}{}
		}
	}
	return out, localSet, nil
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
