// Command reflector runs the central route reflector: it accepts routebus.v1
// Session streams from per-node agents and reflects per-VNI routes between them.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os/signal"
	"syscall"
	"time"

	"github.com/trevex/ectobase/netplane/gen/routebusv1"
	"github.com/trevex/ectobase/netplane/reflector"
	"github.com/trevex/ectobase/netplane/routebus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

func main() {
	addr := flag.String("listen", ":1338", "agent-facing RouteBus session gRPC listen address")
	adminAddr := flag.String("admin-listen", "127.0.0.1:1339", "RouteBusAdmin (fence) gRPC listen address; kept OFF the agent-facing port so a session-cert holder cannot drive fencing")
	adminCN := flag.String("admin-client-cn", "", "if set, only this client-cert CommonName may call admin RPCs (defense-in-depth over the split listener)")
	tlsCA := flag.String("tls-ca", "", "CA bundle to verify client certs (enables mTLS on both listeners)")
	tlsCert := flag.String("tls-cert", "", "reflector server cert")
	tlsKey := flag.String("tls-key", "", "reflector server key")
	flag.Parse()

	// Shared server credentials: when any TLS flag is set both listeners require and
	// verify a client cert (mTLS). The agent-facing session port and the admin port
	// share the server identity but are separate sockets exposing different services.
	var creds credentials.TransportCredentials
	if *tlsCA != "" || *tlsCert != "" || *tlsKey != "" {
		c, err := routebus.ServerTLS(*tlsCA, *tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		creds = c
		log.Printf("mTLS enabled")
	}

	rib := reflector.NewRIB()

	// Session server: the ONLY service on the agent-facing port is RouteBus. The admin
	// (fence) API is deliberately not registered here.
	sessionOpts := []grpc.ServerOption{
		// Aggressive keepalive so a dead agent's session is torn down (and its routes
		// fast-withdrawn) within a bounded budget — the v1 stand-in for BFD.
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 2 * time.Second, Timeout: 3 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: time.Second, PermitWithoutStream: true}),
	}
	if creds != nil {
		sessionOpts = append(sessionOpts, grpc.Creds(creds))
	}
	sessionSrv := grpc.NewServer(sessionOpts...)
	routebusv1.RegisterRouteBusServer(sessionSrv, reflector.NewServer(rib))

	// Admin server: separate socket, CN-gated to the dispatch-controller identity so even a
	// compromised agent holding a valid session cert cannot fence nodes.
	adminOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(reflector.RequireClientCN(*adminCN)),
	}
	if creds != nil {
		adminOpts = append(adminOpts, grpc.Creds(creds))
	}
	adminSrv := grpc.NewServer(adminOpts...)
	routebusv1.RegisterRouteBusAdminServer(adminSrv, reflector.NewAdminServer(rib))

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	adminLis, err := net.Listen("tcp", *adminAddr)
	if err != nil {
		log.Fatalf("admin listen %s: %v", *adminAddr, err)
	}

	// On SIGTERM/SIGINT, GracefulStop drains in-flight sessions (agents see clean stream closes and
	// fast-withdraw) instead of a hard kill.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Print("shutdown signal received; draining reflector")
		sessionSrv.GracefulStop()
		adminSrv.GracefulStop()
	}()

	go func() {
		log.Printf("reflector admin listening on %s", *adminAddr)
		if err := adminSrv.Serve(adminLis); err != nil {
			log.Fatalf("admin serve: %v", err)
		}
	}()

	log.Printf("reflector listening on %s", *addr)
	if err := sessionSrv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
