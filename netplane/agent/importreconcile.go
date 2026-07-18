package agent

import (
	"context"
	"fmt"
	"sort"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

// desiredEgressVNIs returns the VNIs this node hosts that need internet egress: a VNI whose VPC has a
// NATGateway (and this node hosts a NIC in it), or a VNI of a local LB-backend NIC. These VNIs import
// the public VNI's default route (0.0.0.0/0, etc.) so their egress reaches the WAN edge.
func (r *Reconciler) desiredEgressVNIs(ctx context.Context) ([]uint32, error) {
	set := map[uint32]struct{}{}

	// (a) NATGateway VNIs, intersected with VNIs this node actually hosts.
	var gws netv1.NATGatewayList
	if err := r.client.List(ctx, &gws); err != nil {
		return nil, fmt.Errorf("list natgateways: %w", err)
	}
	natVNIs := map[uint32]struct{}{}
	for i := range gws.Items {
		vni, err := vpcVNIFor(ctx, r.client, gws.Items[i].Namespace, gws.Items[i].Spec.VPCRef.Name)
		if err != nil {
			continue // VPC not resolvable yet; skip
		}
		if vni != 0 {
			natVNIs[vni] = struct{}{}
		}
	}
	if len(natVNIs) > 0 {
		var nics netv1.NetworkInterfaceList
		if err := r.client.List(ctx, &nics); err != nil {
			return nil, fmt.Errorf("list networkinterfaces: %w", err)
		}
		for i := range nics.Items {
			n := &nics.Items[i]
			if n.Spec.NodeName == nil || *n.Spec.NodeName != r.nodeID {
				continue
			}
			vni := uint32(n.Status.VNI)
			if _, ok := natVNIs[vni]; ok && vni != 0 {
				set[vni] = struct{}{}
			}
		}
	}

	// (b) LB-backend VNIs on this node (CompiledNIC.LB non-empty).
	var cnics netv1.CompiledNICList
	if err := r.client.List(ctx, &cnics); err != nil {
		return nil, fmt.Errorf("list compilednics: %w", err)
	}
	for i := range cnics.Items {
		c := &cnics.Items[i]
		if c.Spec.NodeName == r.nodeID && len(c.Spec.LB) > 0 && c.Spec.VNI != 0 {
			set[uint32(c.Spec.VNI)] = struct{}{}
		}
	}

	out := make([]uint32, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	return out, nil
}

// desiredPeeringImports scans CompiledNICs scheduled to this node and returns, per local VNI,
// the peer imports (deduped by peerVNI, prefixes unioned). Mirrors desiredEgressVNIs' scan.
func (r *Reconciler) desiredPeeringImports(ctx context.Context) (map[uint32][]PeerImport, error) {
	var cnics netv1.CompiledNICList
	if err := r.client.List(ctx, &cnics); err != nil {
		return nil, err
	}
	// localVNI -> peerVNI -> set of prefixes
	acc := map[uint32]map[uint32]map[string]struct{}{}
	for i := range cnics.Items {
		c := &cnics.Items[i]
		if c.Spec.NodeName != r.nodeID || c.Spec.VNI == 0 {
			continue
		}
		local := uint32(c.Spec.VNI)
		for _, pi := range c.Spec.PeerImports {
			if pi.PeerVNI == 0 {
				continue
			}
			pv := uint32(pi.PeerVNI)
			if acc[local] == nil {
				acc[local] = map[uint32]map[string]struct{}{}
			}
			if acc[local][pv] == nil {
				acc[local][pv] = map[string]struct{}{}
			}
			for _, p := range pi.ImportPrefixes {
				acc[local][pv][p] = struct{}{}
			}
		}
	}
	result := map[uint32][]PeerImport{}
	for local, peers := range acc {
		for pv, prefs := range peers {
			ps := make([]string, 0, len(prefs))
			for p := range prefs {
				ps = append(ps, p)
			}
			sort.Strings(ps) // deterministic
			result[local] = append(result[local], PeerImport{PeerVNI: pv, ImportPrefixes: ps})
		}
	}
	return result, nil
}
