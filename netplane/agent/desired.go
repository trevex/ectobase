package agent

// desired.go — the incremental-reconcile core for the route-bus session.
//
// The agent used to announce its routes/NAT/public records ONCE at session open and never withdraw
// them: a NIC descheduled from a still-connected node stayed advertised fabric-wide, and CRD changes
// were not applied until the session happened to drop. DesiredState + diffDesired make the agent
// converge continuously: every reconcile tick recomputes the full desired set, diffs it against what
// is currently applied on the live stream, and emits only the deltas (announce new/changed, withdraw
// removed). On reconnect the "applied" set is reset to empty so the whole desired set is re-sent.

import "fmt"

// DesiredState is the complete set of things this node wants live on the route bus at a point in
// time. It is recomputed from the K8s objects every reconcile tick.
type DesiredState struct {
	Subs   []uint32
	Routes []Route
	Nats   []NatBlock
	Pubs   []PublicPrefix
	// EgressVNIs is not announced; it configures how learned public-VNI routes are imported into
	// local VNIs (see Bus.apply). Carried here so one reconcile pass produces it alongside the rest.
	EgressVNIs []uint32
}

// routeRef / natRef identify a withdrawn record by its reflector key (see reflector.natKey /
// publicKey / the per-VNI RIB key). PublicPrefix is withdrawn by its full (kind, prefix, owner) key,
// so we reuse the struct directly.
type routeRef struct {
	Vni    uint32
	Prefix string
}
type natRef struct {
	NatIP   string
	PortMin uint32
	PortMax uint32
}

// busDelta is the set of stream messages needed to move the applied state to the desired state.
type busDelta struct {
	subscribe   []uint32
	unsubscribe []uint32
	announceR   []Route
	withdrawR   []routeRef
	announceN   []NatBlock
	withdrawN   []natRef
	announceP   []PublicPrefix
	withdrawP   []PublicPrefix
}

func (d busDelta) empty() bool {
	return len(d.subscribe) == 0 && len(d.unsubscribe) == 0 &&
		len(d.announceR) == 0 && len(d.withdrawR) == 0 &&
		len(d.announceN) == 0 && len(d.withdrawN) == 0 &&
		len(d.announceP) == 0 && len(d.withdrawP) == 0
}

func routeKey(r Route) routeRef  { return routeRef{Vni: r.Vni, Prefix: r.Prefix} }
func natKey(n NatBlock) natRef   { return natRef{NatIP: n.NatIP, PortMin: n.PortMin, PortMax: n.PortMax} }
func pubKey(p PublicPrefix) string {
	return fmt.Sprintf("%d|%s|%s", p.Kind, p.Prefix, p.OwnerUnderlay)
}

// diffDesired computes the minimal set of stream messages to converge `applied` to `next`.
//
// Semantics per record type:
//   - A record present in `next` but not in `applied` (by key) is ANNOUNCED.
//   - A record whose key is in both but whose VALUE changed is re-ANNOUNCED (the reflector upserts by
//     key, so a re-announce updates in place — no withdraw needed).
//   - A record whose key is in `applied` but not in `next` is WITHDRAWN.
//
// Subscriptions are diffed as a set (subscribe added VNIs, unsubscribe removed ones).
func diffDesired(applied, next DesiredState) busDelta {
	var d busDelta

	// Subscriptions (set diff).
	prevSubs := map[uint32]bool{}
	for _, v := range applied.Subs {
		prevSubs[v] = true
	}
	nextSubs := map[uint32]bool{}
	for _, v := range next.Subs {
		nextSubs[v] = true
	}
	for v := range nextSubs {
		if !prevSubs[v] {
			d.subscribe = append(d.subscribe, v)
		}
	}
	for v := range prevSubs {
		if !nextSubs[v] {
			d.unsubscribe = append(d.unsubscribe, v)
		}
	}

	// Routes (keyed by vni+prefix; value = nexthop+external).
	prevR := map[routeRef]Route{}
	for _, r := range applied.Routes {
		prevR[routeKey(r)] = r
	}
	nextR := map[routeRef]Route{}
	for _, r := range next.Routes {
		k := routeKey(r)
		nextR[k] = r
		if old, ok := prevR[k]; !ok || old != r {
			d.announceR = append(d.announceR, r)
		}
	}
	for k := range prevR {
		if _, ok := nextR[k]; !ok {
			d.withdrawR = append(d.withdrawR, k)
		}
	}

	// NAT blocks (keyed by natIp+portMin+portMax; value = whole block).
	prevN := map[natRef]NatBlock{}
	for _, n := range applied.Nats {
		prevN[natKey(n)] = n
	}
	nextN := map[natRef]NatBlock{}
	for _, n := range next.Nats {
		k := natKey(n)
		nextN[k] = n
		if old, ok := prevN[k]; !ok || old != n {
			d.announceN = append(d.announceN, n)
		}
	}
	for k := range prevN {
		if _, ok := nextN[k]; !ok {
			d.withdrawN = append(d.withdrawN, k)
		}
	}

	// Public records (keyed by kind+prefix+owner; value = whole record).
	prevP := map[string]PublicPrefix{}
	for _, p := range applied.Pubs {
		prevP[pubKey(p)] = p
	}
	nextP := map[string]PublicPrefix{}
	for _, p := range next.Pubs {
		k := pubKey(p)
		nextP[k] = p
		if old, ok := prevP[k]; !ok || old != p {
			d.announceP = append(d.announceP, p)
		}
	}
	for k, p := range prevP {
		if _, ok := nextP[k]; !ok {
			d.withdrawP = append(d.withdrawP, p)
		}
	}

	return d
}
