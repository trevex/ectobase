package agent

import (
	"context"
	"fmt"
	"sync"
)

// recordingDP is the single recording fake for the Dataplane interface used by
// the agent tests. It records every call the agent makes so tests can assert on
// the programmed state. All access is guarded by mu; the interface methods are
// safe to call from the bus's reconcile goroutines.
type recordingDP struct {
	mu       sync.Mutex
	added    map[string]string // "vni prefix" -> nexthop
	external map[string]bool   // "vni prefix" -> external flag as programmed
	withdrew map[string]bool
	nbrNat   map[string]string // "natIp min max" -> ownerUnderlay
	nbrNatWd map[string]bool
	fwAdds   []fwCall
	fwDels   []struct{ iface, ruleID string }
	// fwReplace records the LAST ReplaceInterfaceFirewall call per interface (the full desired set),
	// modelling the real dataplane where a replace overwrites the interface's entire rule set.
	fwReplace map[string][]FwRuleWithID
	// fwInstalled models the real dataplane: a rule id is unique per interface, and AddFwRule on an
	// existing id fails (ALREADY_EXISTS) — so a correct reconcile must NOT re-add unchanged rules.
	fwInstalled map[string]bool
	lbVips      []string            // ids added
	lbDels      []string            // ids deleted
	lbBackends  map[string][]string // id -> backends
	routeAdds   []routeCall         // every AddRoute call, in order
	// natSrc/natSrcN record AddNatSource calls (local egress SNAT programming).
	natSrc  map[string]natSrcCall // sourceIP -> last call
	natSrcN map[string]int        // sourceIP -> call count
	// qos/qosN record ConfigureQoS calls (per-interface QoS lane configuration).
	qos  map[string]qosCall // interfaceID -> last call
	qosN map[string]int     // interfaceID -> call count
	// ifaces is what ListInterfaces returns: the node-local attached interfaces + their underlays.
	ifaces []LocalInterface
}

type qosCall struct {
	iface                               string
	egressMbps, publicMbps, ingressMbps uint32
}

type fwCall struct {
	iface  string
	ruleID string
	rule   FwRule
}

type routeCall struct {
	vni      uint32
	prefix   string
	nexthop  string
	external bool
}

type natSrcCall struct {
	vni              uint32
	src, nat         string
	portMin, portMax uint32
}

func newRecordingDP() *recordingDP {
	return &recordingDP{
		added: map[string]string{}, external: map[string]bool{}, withdrew: map[string]bool{},
		nbrNat: map[string]string{}, nbrNatWd: map[string]bool{},
		fwInstalled: map[string]bool{},
		fwReplace:   map[string][]FwRuleWithID{},
		lbBackends:  map[string][]string{},
		natSrc:      map[string]natSrcCall{}, natSrcN: map[string]int{},
		qos: map[string]qosCall{}, qosN: map[string]int{},
	}
}

func natKeyStr(natIp string, min, max uint32) string {
	return fmt.Sprintf("%s %d %d", natIp, min, max)
}

func (f *recordingDP) AddNeighborNat(_ context.Context, natIp string, min, max uint32, ownerUnderlay string, _ uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nbrNat[natKeyStr(natIp, min, max)] = ownerUnderlay
	return nil
}
func (f *recordingDP) WithdrawNeighborNat(_ context.Context, natIp string, min, max uint32, _ uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nbrNatWd[natKeyStr(natIp, min, max)] = true
	return nil
}
func (f *recordingDP) getNbrNat(natIp string, min, max uint32) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.nbrNat[natKeyStr(natIp, min, max)]
	return v, ok
}

func (f *recordingDP) AddRoute(_ context.Context, vni uint32, prefix, nexthop string, external bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added[key(vni, prefix)] = nexthop
	f.external[key(vni, prefix)] = external
	f.routeAdds = append(f.routeAdds, routeCall{vni, prefix, nexthop, external})
	return nil
}
func (f *recordingDP) AddNatSource(_ context.Context, vni uint32, src, nat string, portMin, portMax uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.natSrc[src] = natSrcCall{vni: vni, src: src, nat: nat, portMin: portMin, portMax: portMax}
	f.natSrcN[src]++
	return nil
}
func (f *recordingDP) AddFwRule(_ context.Context, iface, ruleID string, r FwRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := iface + "|" + ruleID
	if f.fwInstalled[k] {
		return fmt.Errorf("fwrule %s already exists", k) // model dataplane ALREADY_EXISTS
	}
	f.fwInstalled[k] = true
	f.fwAdds = append(f.fwAdds, fwCall{iface, ruleID, r})
	return nil
}
func (f *recordingDP) DelFwRule(_ context.Context, iface, ruleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.fwInstalled, iface+"|"+ruleID)
	f.fwDels = append(f.fwDels, struct{ iface, ruleID string }{iface, ruleID})
	return nil
}
func (f *recordingDP) ReplaceInterfaceFirewall(_ context.Context, iface string, rules []FwRuleWithID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Overwrite: the whole set for this interface becomes exactly `rules` (clears prior on empty).
	f.fwReplace[iface] = append([]FwRuleWithID(nil), rules...)
	// Keep fwInstalled consistent with a wholesale replace so any cross-checks stay accurate.
	for k := range f.fwInstalled {
		if len(k) > len(iface) && k[:len(iface)+1] == iface+"|" {
			delete(f.fwInstalled, k)
		}
	}
	for _, rr := range rules {
		f.fwInstalled[iface+"|"+rr.ID] = true
	}
	return nil
}
func (f *recordingDP) WithdrawRoute(_ context.Context, vni uint32, prefix string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdrew[key(vni, prefix)] = true
	return nil
}
func (f *recordingDP) get(vni uint32, prefix string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.added[key(vni, prefix)]
	return v, ok
}
func key(vni uint32, prefix string) string { return fmt.Sprintf("%d %s", vni, prefix) } // VNI-aware: dual-role tests need per-table keys

func (f *recordingDP) AddLbVip(ctx context.Context, id string, vni uint32, vip, lbUnderlay string, ports []LbPort) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lbVips = append(f.lbVips, id)
	return nil
}
func (f *recordingDP) DelLbVip(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lbDels = append(f.lbDels, id)
	return nil
}
func (f *recordingDP) AddLbBackend(ctx context.Context, id, backendUnderlay string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lbBackends[id] = append(f.lbBackends[id], backendUnderlay)
	return nil
}
func (f *recordingDP) DelLbBackend(ctx context.Context, id, backendUnderlay string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur := f.lbBackends[id][:0]
	for _, b := range f.lbBackends[id] {
		if b != backendUnderlay {
			cur = append(cur, b)
		}
	}
	f.lbBackends[id] = cur
	return nil
}
func (f *recordingDP) ConfigureQoS(_ context.Context, iface string, egressMbps, publicMbps, ingressMbps uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.qos[iface] = qosCall{iface: iface, egressMbps: egressMbps, publicMbps: publicMbps, ingressMbps: ingressMbps}
	f.qosN[iface]++
	return nil
}
func (f *recordingDP) getQoS(iface string) (qosCall, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.qos[iface]
	return v, ok
}
func (f *recordingDP) ListInterfaces(_ context.Context) ([]LocalInterface, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]LocalInterface(nil), f.ifaces...), nil
}
