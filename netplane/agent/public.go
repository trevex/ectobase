package agent

import (
	"context"
	"fmt"
	"log"
	"strings"

	rbv1 "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
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
}

// DesiredPublic returns the public-address records THIS node should announce on
// the PublicPrefix channel. A WAN edge (edgeLoopback != "") announces one
// EDGE_UNDERLAY record mapping its anycast datapath /128 (the underlay) to its
// unique control-plane loopback (the owner). Non-edge nodes announce nothing.
// NAT_IP records ride this channel in a later task.
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
	// LB backends on this node: one LB_VIP record per backed VIP so the edge can AddLbBackend.
	// vni=0: the edge supplies its WAN LB-VNI at AddLbVip; AddLbBackend needs no VNI.
	lbs, err := r.desiredLB(ctx)
	if err != nil {
		return nil, err
	}
	for _, lb := range lbs {
		prefix, err := hostPrefix(lb.VIP)
		if err != nil {
			return nil, fmt.Errorf("lb vip %q: %w", lb.VIP, err)
		}
		recs = append(recs, PublicPrefix{
			Kind:          rbv1.PublicKind_PUBLIC_KIND_LB_VIP,
			Prefix:        prefix,
			OwnerUnderlay: lb.NicUnderlay,
			Vni:           0,
		})
	}
	return recs, nil
}

// applyPublic handles a learned PublicPrefix update off the routebus. For
// EDGE_UNDERLAY it records the anycast-underlay -> owner-loopback mapping in
// learnedEdge (so a later task can pin the WAN return path to the specific edge
// rather than ECMP'ing the anycast /128). Other kinds are not yet handled.
func (b *Bus) applyPublic(pp *rbv1.PublicPrefix, op rbv1.RouteOp) {
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
	case rbv1.PublicKind_PUBLIC_KIND_LB_VIP:
		if !b.isEdge {
			return // only the edge runs maglev/backends; E/W uses the plain anycast route
		}
		vip := stripMask(pp.GetPrefix())
		owner := pp.GetOwnerUnderlay()
		switch op {
		case rbv1.RouteOp_ROUTE_OP_ADD:
			if err := b.dp.AddLbBackend(context.Background(), vip, owner); err != nil {
				log.Printf("AddLbBackend vip=%s backend=%s: %v", vip, owner, err)
			}
		case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
			if err := b.dp.DelLbBackend(context.Background(), vip, owner); err != nil {
				log.Printf("DelLbBackend vip=%s backend=%s: %v", vip, owner, err)
			}
		}
	default:
		log.Printf("applyPublic: kind=%s not yet handled", pp.GetKind())
	}
}

// LearnedEdge returns a copy of the learned anycast-underlay -> owner-loopback
// map so a later task can resolve the WAN edge return path.
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
