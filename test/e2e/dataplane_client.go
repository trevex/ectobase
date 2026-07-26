package e2e

// dataplane_client.go — thin helper that dials the node-local DataplaneNode
// gRPC service and exposes the RPCs the smoke tests (Tasks 2.2/2.3) need.
//
// Endpoint: TCP at 127.0.0.1:1337 (plaintext, no TLS). flowplane serve
// registers DataplaneNode on the same TCP address as the legacy DPDKironcore
// service. The default address matches the grpcAddr constant used in the
// existing routebus_test.go helpers.
//
// The caller is responsible for closing the connection (the returned closer)
// when done — typically via t.Cleanup(closer).

import (
	"context"
	"fmt"

	dataplanev1 "github.com/trevex/ectobase/cni/gen/dataplanev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// DefaultDataplaneAddr is the address flowplane serve listens on. All existing
// e2e tests use this value when starting flowplane inside a clab/kind node.
// The port is the mirrored DataplanePort (see env.go — matches hack/clab/env.sh).
var DefaultDataplaneAddr = DataplaneAddrFromEnv()

// dataplaneClient wraps the generated DataplaneNodeClient with the RPCs the
// smoke tests exercise. Add pass-throughs here as Tasks 2.2/2.3 need them.
type dataplaneClient struct {
	cl dataplanev1.DataplaneNodeClient
}

// dialDataplaneNode dials the node-local DataplaneNode gRPC over plaintext TCP
// and returns a thin wrapper plus a closer. The caller must call closer() when
// done (e.g. defer closer()).
//
//	cl, closer, err := dialDataplaneNode("127.0.0.1:1337")
//	if err != nil { t.Fatal(err) }
//	defer closer()
func dialDataplaneNode(addr string) (*dataplaneClient, func() error, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("dial DataplaneNode %q: %w", addr, err)
	}
	cl := dataplanev1.NewDataplaneNodeClient(conn)
	return &dataplaneClient{cl: cl}, conn.Close, nil
}

// AttachInterface wires a VM interface into the eBPF dataplane.
func (c *dataplaneClient) AttachInterface(ctx context.Context, req *dataplanev1.AttachInterfaceRequest) (*dataplanev1.AttachInterfaceResponse, error) {
	resp, err := c.cl.AttachInterface(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AttachInterface: %w", err)
	}
	return resp, nil
}

// DetachInterface removes a previously attached interface.
func (c *dataplaneClient) DetachInterface(ctx context.Context, req *dataplanev1.DetachInterfaceRequest) (*dataplanev1.DetachInterfaceResponse, error) {
	resp, err := c.cl.DetachInterface(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("DetachInterface: %w", err)
	}
	return resp, nil
}

// ConfigureNetwork programs the node-wide network configuration (underlay,
// gateway) without requiring a live eBPF object (used after graceful restart).
func (c *dataplaneClient) ConfigureNetwork(ctx context.Context, req *dataplanev1.ConfigureNetworkRequest) (*dataplanev1.ConfigureNetworkResponse, error) {
	resp, err := c.cl.ConfigureNetwork(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("ConfigureNetwork: %w", err)
	}
	return resp, nil
}

// AddRoute programs a single overlay route (vni, prefix -> nexthop underlay).
func (c *dataplaneClient) AddRoute(ctx context.Context, req *dataplanev1.AddRouteRequest) (*dataplanev1.AddRouteResponse, error) {
	resp, err := c.cl.AddRoute(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AddRoute: %w", err)
	}
	return resp, nil
}

// WithdrawRoute removes an overlay route.
func (c *dataplaneClient) WithdrawRoute(ctx context.Context, req *dataplanev1.WithdrawRouteRequest) (*dataplanev1.WithdrawRouteResponse, error) {
	resp, err := c.cl.WithdrawRoute(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("WithdrawRoute: %w", err)
	}
	return resp, nil
}

// AddNatSource programs egress SNAT for a (vni, source_ip) onto a NAT block.
func (c *dataplaneClient) AddNatSource(ctx context.Context, req *dataplanev1.AddNatSourceRequest) (*dataplanev1.AddNatSourceResponse, error) {
	resp, err := c.cl.AddNatSource(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AddNatSource: %w", err)
	}
	return resp, nil
}

// WithdrawNatSource removes a SNAT source entry.
func (c *dataplaneClient) WithdrawNatSource(ctx context.Context, req *dataplanev1.WithdrawNatSourceRequest) (*dataplanev1.WithdrawNatSourceResponse, error) {
	resp, err := c.cl.WithdrawNatSource(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("WithdrawNatSource: %w", err)
	}
	return resp, nil
}

// AddNeighborNat programs a return-to-owner entry for distributed NAT.
func (c *dataplaneClient) AddNeighborNat(ctx context.Context, req *dataplanev1.AddNeighborNatRequest) (*dataplanev1.AddNeighborNatResponse, error) {
	resp, err := c.cl.AddNeighborNat(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AddNeighborNat: %w", err)
	}
	return resp, nil
}

// WithdrawNeighborNat removes a return-to-owner entry.
func (c *dataplaneClient) WithdrawNeighborNat(ctx context.Context, req *dataplanev1.WithdrawNeighborNatRequest) (*dataplanev1.WithdrawNeighborNatResponse, error) {
	resp, err := c.cl.WithdrawNeighborNat(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("WithdrawNeighborNat: %w", err)
	}
	return resp, nil
}

// AddLbVip registers an external load balancer VIP.
func (c *dataplaneClient) AddLbVip(ctx context.Context, req *dataplanev1.AddLbVipRequest) (*dataplanev1.AddLbVipResponse, error) {
	resp, err := c.cl.AddLbVip(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AddLbVip: %w", err)
	}
	return resp, nil
}

// AddLbBackend appends a backend to a registered LB VIP.
func (c *dataplaneClient) AddLbBackend(ctx context.Context, req *dataplanev1.AddLbBackendRequest) (*dataplanev1.AddLbBackendResponse, error) {
	resp, err := c.cl.AddLbBackend(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AddLbBackend: %w", err)
	}
	return resp, nil
}

// DelLbVip removes a registered LB VIP and all its state.
func (c *dataplaneClient) DelLbVip(ctx context.Context, req *dataplanev1.DelLbVipRequest) (*dataplanev1.DelLbVipResponse, error) {
	resp, err := c.cl.DelLbVip(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("DelLbVip: %w", err)
	}
	return resp, nil
}

// DelLbBackend removes a single backend from a registered LB VIP.
func (c *dataplaneClient) DelLbBackend(ctx context.Context, req *dataplanev1.DelLbBackendRequest) (*dataplanev1.DelLbBackendResponse, error) {
	resp, err := c.cl.DelLbBackend(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("DelLbBackend: %w", err)
	}
	return resp, nil
}

// AddFwRule programs a per-interface firewall rule (ingress or egress).
func (c *dataplaneClient) AddFwRule(ctx context.Context, req *dataplanev1.AddFwRuleRequest) (*dataplanev1.AddFwRuleResponse, error) {
	resp, err := c.cl.AddFwRule(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AddFwRule: %w", err)
	}
	return resp, nil
}

// DelFwRule removes a per-interface firewall rule by id.
func (c *dataplaneClient) DelFwRule(ctx context.Context, req *dataplanev1.DelFwRuleRequest) (*dataplanev1.DelFwRuleResponse, error) {
	resp, err := c.cl.DelFwRule(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("DelFwRule: %w", err)
	}
	return resp, nil
}
