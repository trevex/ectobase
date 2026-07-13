// Command agent runs the per-node control plane: it dials the local xdp-dp
// DataplaneNode and the central reflector, then reconciles NetworkInterfaces on
// this node into route announcements while programming learned remote routes.
package main

import (
	"context"
	"flag"
	"log"
	"time"

	dpv1 "github.com/trevex/xdp-dp/cni/gen/dataplanev1"
	"github.com/trevex/xdp-dp/netplane/agent"
	rbv1 "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func main() {
	nodeID := flag.String("node-id", "", "stable node identity (required)")
	underlay := flag.String("underlay", "", "this node's underlay IPv6 (required)")
	reflectorAddr := flag.String("reflector", "127.0.0.1:1338", "reflector gRPC address")
	dataplaneAddr := flag.String("dataplane", "127.0.0.1:1337", "local xdp-dp DataplaneNode address")
	kubeconfig := flag.String("kubeconfig", "", "kubeconfig for the central API (empty = in-cluster)")
	flag.Parse()
	if *nodeID == "" || *underlay == "" {
		log.Fatal("--node-id and --underlay are required")
	}

	dpConn, err := grpc.NewClient(*dataplaneAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial dataplane: %v", err)
	}
	defer dpConn.Close()
	dp := agent.NewDataplaneAdapter(dpv1.NewDataplaneNodeClient(dpConn))

	rbConn, err := grpc.NewClient(*reflectorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 2 * time.Second, Timeout: 3 * time.Second, PermitWithoutStream: true}))
	if err != nil {
		log.Fatalf("dial reflector: %v", err)
	}
	defer rbConn.Close()
	rb := rbv1.NewRouteBusClient(rbConn)

	ctx := context.Background()
	r, err := agent.NewReconciler(*kubeconfig, *nodeID)
	if err != nil {
		log.Fatalf("reconciler: %v", err)
	}
	r.SetUnderlay(*underlay)
	// Reconcile the desired announcements/subscriptions for this node, then run the
	// bus session. On disconnect, retry with backoff (the reflector fast-withdrew us).
	for {
		subs, ann, err := r.Desired(ctx)
		if err != nil {
			log.Printf("reconcile: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		bus := agent.NewBus(*nodeID, *underlay, dp)
		if err := bus.Run(ctx, rb, subs, ann); err != nil {
			log.Printf("bus session ended: %v; reconnecting", err)
		}
		time.Sleep(time.Second)
	}
}
