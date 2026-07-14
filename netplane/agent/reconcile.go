package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Reconciler reads NetworkInterfaces scheduled to this node and derives the
// VNIs to subscribe to plus the local routes to announce.
type Reconciler struct {
	client   client.Client
	nodeID   string
	underlay string
	dp       Dataplane // local xdp-dp; used to program egress SNAT sources
}

// NewReconciler builds a Reconciler from a kubeconfig path (empty = in-cluster).
func NewReconciler(kubeconfig, nodeID string) (*Reconciler, error) {
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
	// underlay is threaded in by main via SetUnderlay to avoid a wider signature.
	return &Reconciler{client: c, nodeID: nodeID}, nil
}

// SetUnderlay records this node's underlay IPv6 (used as the announced nexthop).
func (r *Reconciler) SetUnderlay(underlay string) { r.underlay = underlay }

// SetDataplane wires the local xdp-dp so the reconciler can program egress SNAT.
func (r *Reconciler) SetDataplane(dp Dataplane) { r.dp = dp }

// Desired returns the VNIs to subscribe to, the local routes to announce, and
// the local egress-NAT blocks to announce for this node, snapshotting the current
// NetworkInterface set. As a side effect it programs local egress SNAT sources on
// the dataplane (idempotent: AddNatSource delete-then-adds).
func (r *Reconciler) Desired(ctx context.Context) (subs []uint32, announce []Route, announceNat []NatBlock, err error) {
	var nics netv1.NetworkInterfaceList
	if err := r.client.List(ctx, &nics); err != nil {
		return nil, nil, nil, fmt.Errorf("list networkinterfaces: %w", err)
	}
	vniSet := map[uint32]struct{}{}
	for i := range nics.Items {
		nic := &nics.Items[i]
		vni, err := r.vniFor(ctx, nic)
		if err != nil {
			return nil, nil, nil, err
		}
		if vni == 0 {
			continue // VPC not yet allocated a VNI; skip until it is
		}
		vniSet[vni] = struct{}{} // subscribe to every VNI we host, local or not
		if nic.Spec.NodeName == nil || *nic.Spec.NodeName != r.nodeID {
			continue // only announce interfaces scheduled to THIS node
		}
		// The route's nexthop is the ENDPOINT's own underlay /128 (the identity the
		// attach path allocated and recorded in status.underlayRoute), NOT the node
		// address: remote nodes encap to that /128 and the local node's UNDERLAY map
		// resolves it to the endpoint's tap. Fall back to the node underlay only when
		// the endpoint hasn't been attached yet (status.underlayRoute empty).
		nexthop := nic.Status.UnderlayRoute
		if nexthop == "" {
			nexthop = r.underlay
		}
		for _, ip := range nic.Spec.IPs {
			prefix, err := hostPrefix(ip)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("nic %s/%s ip %q: %w", nic.Namespace, nic.Name, ip, err)
			}
			// Endpoint host routes are internal; egress-NAT default routes (external=true)
			// are distributed separately by a controller.
			announce = append(announce, Route{Vni: vni, Prefix: prefix, Nexthop: nexthop, External: false})
		}
	}
	for v := range vniSet {
		subs = append(subs, v)
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i] < subs[j] })

	// Egress NAT: program the LOCAL SNAT sources for allocations whose source is a
	// NIC on this node, and return the matching blocks for the caller to announce on
	// the routebus (so peers learn the neighbor-nat return route to us).
	srcs, blocks, err := DesiredNat(ctx, r.client, r.nodeID, r.underlay)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, s := range srcs {
		if r.dp == nil {
			continue // no dataplane wired; skip programming (e.g. unit tests that only inspect returned blocks)
		}
		if err := r.dp.AddNatSource(ctx, s.Vni, s.SourceIP, s.NatIP, s.PortMin, s.PortMax); err != nil {
			log.Printf("AddNatSource %s->%s vni=%d: %v", s.SourceIP, s.NatIP, s.Vni, err)
			continue
		}
	}
	return subs, announce, blocks, nil
}

// vniFor resolves an interface's VNI: prefer status.vni, else the referenced VPC's status.vni.
func (r *Reconciler) vniFor(ctx context.Context, nic *netv1.NetworkInterface) (uint32, error) {
	if nic.Status.VNI != 0 {
		return uint32(nic.Status.VNI), nil
	}
	var vpc netv1.VPC
	key := types.NamespacedName{Namespace: nic.Namespace, Name: nic.Spec.VPCRef.Name}
	if err := r.client.Get(ctx, key, &vpc); err != nil {
		return 0, fmt.Errorf("get vpc %s: %w", key, err)
	}
	return uint32(vpc.Status.VNI), nil
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
