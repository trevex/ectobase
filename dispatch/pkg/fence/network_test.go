// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package fence

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"github.com/trevex/ectobase/mesh/reflector"
)

func TestNetworkFencer_FenceCallsAdmin(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	rib := reflector.NewRIB()
	rib.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	pb.RegisterRouteBusAdminServer(srv, reflector.NewAdminServer(rib))
	go srv.Serve(lis)
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	f := NewNetworkFencer(pb.NewRouteBusAdminClient(conn))
	if err := f.Fence(context.Background(), "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Fence: %v", err)
	}
	if rib.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("Fence should have withdrawn the route via admin RPC")
	}
	if err := f.Release(context.Background(), "2001:db8:0:1::/64"); err != nil {
		t.Fatalf("Release: %v", err)
	}
}
