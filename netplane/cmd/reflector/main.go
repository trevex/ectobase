// Command reflector runs the central route reflector: it accepts routebus.v1
// Session streams from per-node agents and reflects per-VNI routes between them.
package main

import (
	"flag"
	"log"
	"net"

	"github.com/trevex/xdp-dp/netplane/gen/routebusv1"
	"github.com/trevex/xdp-dp/netplane/reflector"
	"github.com/trevex/xdp-dp/netplane/routebus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"time"
)

func main() {
	addr := flag.String("listen", ":1338", "gRPC listen address")
	tlsCA := flag.String("tls-ca", "", "CA bundle to verify agent client certs (enables mTLS)")
	tlsCert := flag.String("tls-cert", "", "reflector server cert")
	tlsKey := flag.String("tls-key", "", "reflector server key")
	flag.Parse()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	// Aggressive keepalive so a dead agent's session is torn down (and its routes
	// fast-withdrawn) within a bounded budget — the v1 stand-in for BFD.
	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 2 * time.Second, Timeout: 3 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: time.Second, PermitWithoutStream: true}),
	}
	if *tlsCA != "" || *tlsCert != "" || *tlsKey != "" {
		creds, err := routebus.ServerTLS(*tlsCA, *tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		opts = append(opts, grpc.Creds(creds))
		log.Printf("mTLS enabled")
	}
	srv := grpc.NewServer(opts...)
	routebusv1.RegisterRouteBusServer(srv, reflector.NewServer(reflector.NewRIB()))
	log.Printf("reflector listening on %s", *addr)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
