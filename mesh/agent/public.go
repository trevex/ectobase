package agent

import (
	"context"
	"fmt"
	"log"
	"strings"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"github.com/trevex/ectobase/mesh/routebus"
)

// PublicPrefix is a typed public-address record this node ANNOUNCES on the
// routebus PublicPrefix channel (mirrors rbv1.PublicPrefix). For an EDGE_UNDERLAY
// record, Prefix is the edge's anycast datapath /128 and OwnerUnderlay is the
// edge's UNIQUE control-plane loopback.
type PublicPrefix struct {
	Kind          rbv1.PublicKind
	Prefix        string
	OwnerUnderlay string
	Vni           uint32
	PortMin       uint32
	PortMax       uint32
	// OverlayIP is set for LB_IP records: the backend guest's overlay IP, forwarded to
	// AddLbBackend so the edge can Geneve-encap to the right VNI+overlay-IP tuple.
	OverlayIP string
	// Ports is set for LB_IP records: the load balancer's service tuples, forwarded to AddLoadBalancer so
	// a bus-only edge (no API server) can register the LB address itself before adding this backend to it.
	Ports []LbPort
}

// DesiredPublic returns the public-address records THIS node should announce on
// the PublicPrefix channel. A WAN edge (edgeLoopback != "") announces one
// EDGE_UNDERLAY record mapping its anycast datapath /128 (the underlay) to its
// unique control-plane loopback (the owner). Non-edge nodes announce nothing.
// Only EDGE_UNDERLAY records are announced today; the channel also carries NAT_IP records.
func (r *Reconciler) DesiredPublic(ctx context.Context) ([]PublicPrefix, error) {
	var recs []PublicPrefix
	if r.edgeLoopback != "" {
		recs = append(recs, PublicPrefix{
			Kind:          rbv1.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY,
			Prefix:        r.underlay + "/128",
			OwnerUnderlay: r.edgeLoopback,
			Vni:           0,
		})
	}
	// LB backends on this node: one LB_IP record per backed LB address, carrying BOTH halves the edge
	// needs — the LB address's service Ports (for AddLoadBalancer) and this backend's identity (for AddLbBackend).
	// Vni/OverlayIP here are the BACKEND NIC's VPC VNI + overlay IP (not the edge's WAN VNI, which
	// the edge supplies itself at AddLoadBalancer) — AddLbBackend needs them to Geneve-encap to the backend.
	// Carrying the ports is what lets a bus-only edge program the whole load balancer: it has no API
	// server, so a backend announcement is its ONLY source for the LB address's service tuples.
	ulByKey, localSet, err := r.underlayByKey(ctx)
	if err != nil {
		return nil, err
	}
	lbs, err := r.desiredLB(ctx, ulByKey, localSet)
	if err != nil {
		return nil, err
	}
	for _, lb := range lbs {
		prefix, err := hostPrefix(lb.IP)
		if err != nil {
			return nil, fmt.Errorf("lb lbIP %q: %w", lb.IP, err)
		}
		recs = append(recs, PublicPrefix{
			Kind:          rbv1.PublicKind_PUBLIC_KIND_LB_IP,
			Prefix:        prefix,
			OwnerUnderlay: lb.NicUnderlay,
			Vni:           lb.Vni,
			OverlayIP:     lb.OverlayIP,
			Ports:         lb.Ports,
		})
	}
	return recs, nil
}

// applyPublic handles a learned PublicPrefix update off the routebus. For
// EDGE_UNDERLAY it records the anycast-underlay -> owner-loopback mapping in
// learnedEdge, which exists to pin the WAN return path to the specific edge that owns a flow
// rather than ECMP'ing the anycast /128. Other kinds are not yet handled.
func (b *Bus) applyPublic(ctx context.Context, pp *rbv1.PublicPrefix, op rbv1.RouteOp) {
	if pp == nil {
		return
	}
	switch pp.GetKind() {
	case rbv1.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY:
		anycast := stripMask(pp.GetPrefix())
		owner := pp.GetOwnerUnderlay()
		b.mu.Lock()
		if b.learnedEdge == nil {
			b.learnedEdge = map[string]string{}
		}
		switch op {
		case rbv1.RouteOp_ROUTE_OP_ADD:
			b.learnedEdge[anycast] = owner
		case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
			delete(b.learnedEdge, anycast)
		}
		b.mu.Unlock()
		log.Printf("learned EDGE_UNDERLAY anycast=%s owner=%s op=%s", anycast, owner, op)
	case rbv1.PublicKind_PUBLIC_KIND_LB_IP:
		if !b.isEdge {
			return // only the edge runs maglev/backends; E/W uses the plain anycast route
		}
		switch op {
		case rbv1.RouteOp_ROUTE_OP_ADD:
			b.addLbBackend(ctx, pp)
		case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
			b.delLbBackend(ctx, pp)
		}
	default:
		log.Printf("applyPublic: kind=%s not yet handled", pp.GetKind())
	}
}

// backendKey identifies one LB backend the way the dataplane does: by its node VTEP AND its overlay
// IP. The VTEP alone is not enough — two guests of one Service can be scheduled on the same node.
type backendKey struct{ owner, overlay string }

// edgeLb is the edge's view of one registered load balancer: the ports it was registered with and
// the backends currently attached to it (value = the backend's VPC VNI, needed to re-attach it if
// the LB address has to be re-registered).
type edgeLb struct {
	ports    []LbPort
	backends map[backendKey]uint32
}

// addLbBackend applies one LB_IP ADD at the edge. A backend announcement carries BOTH halves of
// the load balancer, so this call may have to create it: add_lb_target rejects an unknown LB, so
// AddLoadBalancer must come first. It is diffed against b.edgeLbs because the dataplane is not idempotent
// here — create_lb rejects a duplicate id and add_lb_target a duplicate backend — and the edge sees
// each record repeatedly (every backend announces the same ports, and the reflector replays the
// whole snapshot on every reconnect).
//
// Called only from the Bus Run goroutine (handleServerMsg), like the installed/origin bookkeeping,
// so b.edgeLbs needs no lock.
func (b *Bus) addLbBackend(ctx context.Context, pp *rbv1.PublicPrefix) {
	lbIP := stripMask(pp.GetPrefix())
	bk := backendKey{owner: pp.GetOwnerUnderlay(), overlay: pp.GetOverlayIp()}
	ports := portsFromPB(pp.GetPorts())

	lb, ok := b.edgeLbs[lbIP]
	switch {
	case !ok:
		if !b.registerLoadBalancer(ctx, lbIP, ports) {
			return
		}
		lb = b.edgeLbs[lbIP]
	case !routebus.LbPortsEqual(lb.ports, ports):
		// The LoadBalancer's port set changed. create_lb cannot update in place, so tear the LB down
		// and rebuild it — then re-attach every backend, because DelLoadBalancer took them with it. The
		// backends we re-attach are the ones we already know; the announcer's own is added below.
		prev := lb.backends
		if err := b.dp.DelLoadBalancer(ctx, lbIP); err != nil {
			log.Printf("DelLoadBalancer %s (port change): %v", lbIP, err)
			return
		}
		delete(b.edgeLbs, lbIP)
		if !b.registerLoadBalancer(ctx, lbIP, ports) {
			return
		}
		lb = b.edgeLbs[lbIP]
		for pk, pvni := range prev {
			if err := b.dp.AddLbBackend(ctx, lbIP, pk.owner, pk.overlay, pvni); err != nil {
				log.Printf("AddLbBackend lbIP=%s backend=%s overlay=%s (port-change re-add): %v", lbIP, pk.owner, pk.overlay, err)
				continue
			}
			lb.backends[pk] = pvni
		}
	}

	if _, have := lb.backends[bk]; have {
		return // already attached; re-announce or snapshot replay
	}
	if err := b.dp.AddLbBackend(ctx, lbIP, bk.owner, bk.overlay, pp.GetVni()); err != nil {
		log.Printf("AddLbBackend lbIP=%s backend=%s: %v", lbIP, bk.owner, err)
		return
	}
	lb.backends[bk] = pp.GetVni()
}

// registerLoadBalancer creates the load balancer on the dataplane and records it. vni=0 is the WAN/public
// VNI and lbUnderlay is THIS edge's own anycast underlay: create_lb skips the UNDERLAY write for
// vni==0, so it cannot clobber the LOCAL_DELIVER entry attach_edge wrote there. Reports success.
//
// The retry is for an agent restart. The agent and the dataplane have independent lifetimes —
// flowplane pins its maps and adopts them across a restart, and the agent can restart on its own
// while flowplane keeps running — so a fresh agent routinely meets a dataplane that already has
// this LB, and create_lb rejects a duplicate id. Giving up there would be terminal: with no record
// of the LB address the agent can never attach a backend that scales up later, nor honour a withdraw, and
// the edge would serve a frozen backend set until flowplane itself restarted.
//
// Re-creating from scratch is safe precisely because this only happens on a session's first sight
// of the LB address, and a session opens with the reflector replaying the FULL public snapshot: every
// backend's record is already in flight, so the set rebuilds within the same burst. DelLoadBalancer on an
// id the dataplane does not know is a no-op (delete_lb returns false, not an error), so the fallback
// is also harmless when AddLoadBalancer failed for some other reason.
func (b *Bus) registerLoadBalancer(ctx context.Context, lbIP string, ports []LbPort) bool {
	err := b.dp.AddLoadBalancer(ctx, lbIP, PublicVNI, lbIP, b.underlay, ports)
	if err != nil {
		log.Printf("AddLoadBalancer %s: %v; re-creating (stale registration from a previous agent?)", lbIP, err)
		if derr := b.dp.DelLoadBalancer(ctx, lbIP); derr != nil {
			log.Printf("DelLoadBalancer %s during re-create: %v", lbIP, derr)
			return false
		}
		if err = b.dp.AddLoadBalancer(ctx, lbIP, PublicVNI, lbIP, b.underlay, ports); err != nil {
			log.Printf("AddLoadBalancer %s after re-create: %v", lbIP, err)
			return false
		}
	}
	if b.edgeLbs == nil {
		b.edgeLbs = map[string]*edgeLb{}
	}
	b.edgeLbs[lbIP] = &edgeLb{ports: append([]LbPort(nil), ports...), backends: map[backendKey]uint32{}}
	return true
}

// delLbBackend applies one LB_IP WITHDRAW at the edge: detach the backend and, when it was the
// last one, delete the load balancer itself. Dropping the empty LB matters twice over — an edge
// that Maglev-hashes to an empty backend set can only blackhole, and a registration left behind
// would make create_lb reject the LB address's next add.
func (b *Bus) delLbBackend(ctx context.Context, pp *rbv1.PublicPrefix) {
	lbIP := stripMask(pp.GetPrefix())
	bk := backendKey{owner: pp.GetOwnerUnderlay(), overlay: pp.GetOverlayIp()}

	lb, ok := b.edgeLbs[lbIP]
	if !ok {
		return
	}
	if _, have := lb.backends[bk]; have {
		// overlay disambiguates two backends sharing the same owner node (see DelLbBackend's doc).
		if err := b.dp.DelLbBackend(ctx, lbIP, bk.owner, bk.overlay); err != nil {
			log.Printf("DelLbBackend lbIP=%s backend=%s overlay=%s: %v", lbIP, bk.owner, bk.overlay, err)
			return
		}
		delete(lb.backends, bk)
	}
	if len(lb.backends) > 0 {
		return
	}
	if err := b.dp.DelLoadBalancer(ctx, lbIP); err != nil {
		log.Printf("DelLoadBalancer %s (last backend withdrawn): %v", lbIP, err)
		return
	}
	delete(b.edgeLbs, lbIP)
}

// LearnedEdge returns a copy of the learned anycast-underlay -> owner-loopback
// map, used to resolve the WAN edge return path for a flow.
func (b *Bus) LearnedEdge() map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]string, len(b.learnedEdge))
	for k, v := range b.learnedEdge {
		out[k] = v
	}
	return out
}

// stripMask returns the address portion of a CIDR ("fd00::e/128" -> "fd00::e").
func stripMask(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return cidr[:i]
	}
	return cidr
}
