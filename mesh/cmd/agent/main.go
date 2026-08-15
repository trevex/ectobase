// Command agent runs the per-node control plane: it dials the local flowplane
// DataplaneNode and the central reflector, then reconciles NetworkInterfaces on
// this node into route announcements while programming learned remote routes.
package main

import (
	"context"
	"flag"
	"log"
	"math/rand/v2"
	"os/signal"
	"syscall"
	"time"

	dpv1 "github.com/trevex/ectobase/cni/gen/dataplanev1"
	"github.com/trevex/ectobase/mesh/agent"
	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"github.com/trevex/ectobase/mesh/routebus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func main() {
	nodeID := flag.String("node-id", "", "stable node identity (required)")
	underlay := flag.String("underlay", "", "this node's underlay IPv6 (required)")
	reflectorAddr := flag.String("reflector", "127.0.0.1:1338", "reflector gRPC address")
	dataplaneAddr := flag.String("dataplane", "unix:///run/flowplane/dataplane.sock", "local flowplane DataplaneNode address (unix:// socket or host:port)")
	kubeconfig := flag.String("kubeconfig", "", "kubeconfig for this node's own cluster apiserver — where the broker syncs the compiled CRDs (empty = in-cluster). The agent never talks to the dispatch.")
	edgeLoopback := flag.String("edge-loopback", "", "if set, this node is a WAN edge; value = its UNIQUE control-plane loopback IPv6 (e.g. fd00:db8:0:9::1)")
	tlsCA := flag.String("tls-ca", "", "CA bundle to verify the reflector (enables mTLS)")
	tlsCert := flag.String("tls-cert", "", "agent client cert (identity == node)")
	tlsKey := flag.String("tls-key", "", "agent client key")
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

	var rbCreds = insecure.NewCredentials()
	if *tlsCA != "" || *tlsCert != "" || *tlsKey != "" {
		tc, err := routebus.ClientTLS(*tlsCA, *tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		rbCreds = tc
	}
	rbConn, err := grpc.NewClient(*reflectorAddr,
		grpc.WithTransportCredentials(rbCreds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 2 * time.Second, Timeout: 3 * time.Second, PermitWithoutStream: true}))
	if err != nil {
		log.Fatalf("dial reflector: %v", err)
	}
	defer rbConn.Close()
	rb := rbv1.NewRouteBusClient(rbConn)

	// SIGTERM/SIGINT cancel ctx so the bus session drains and Run returns; the loop below then exits.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	r, err := agent.NewReconciler(*kubeconfig, *nodeID, agent.Deps{
		Underlay:     *underlay,
		Dataplane:    dp,
		EdgeLoopback: *edgeLoopback,
	})
	if err != nil {
		log.Fatalf("reconciler: %v", err)
	}

	// reconcile recomputes this node's full desired bus state AND programs the local dataplane
	// (SNAT via Desired's side effect, firewall + LB diffs). The Bus calls it every reconcile tick
	// and on session (re)open, pushing only the deltas onto the live stream — so CRD changes after
	// startup converge without waiting for a disconnect, and removed NICs are withdrawn fabric-wide.
	reconcile := func(ctx context.Context) (agent.DesiredState, error) {
		// Snapshot the node-wide reads (ListInterfaces + CompiledNIC list) once for the whole tick:
		// Desired + the firewall/LB/QoS/public reconcilers below otherwise re-fetch them ~7x and could
		// see disagreeing mid-tick snapshots.
		r.BeginTick()
		defer r.EndTick()
		subs, routes, nats, egressVNIs, peeringImports, err := r.Desired(ctx)
		if err != nil {
			return agent.DesiredState{}, err
		}
		if err := r.ReconcileFirewall(ctx); err != nil {
			log.Printf("reconcile firewall: %v", err)
		}
		if err := r.ReconcileLB(ctx); err != nil {
			log.Printf("reconcile lb: %v", err)
		}
		if err := r.ReconcileQoS(ctx); err != nil {
			log.Printf("reconcile qos: %v", err)
		}
		pubs, err := r.DesiredPublic(ctx)
		if err != nil {
			return agent.DesiredState{}, err
		}
		if err := r.StampNodePrefix(ctx); err != nil {
			log.Printf("stamp node prefix: %v", err)
		}
		return agent.DesiredState{Subs: subs, Routes: routes, Nats: nats, Pubs: pubs, EgressVNIs: egressVNIs, PeeringImports: peeringImports}, nil
	}

	// One Bus for the process lifetime: its installed-route bookkeeping must survive reconnects so
	// prune-on-EndOfRIB can remove routes that left the RIB while we were disconnected. On disconnect,
	// retry (the reflector fast-withdrew our announcements; the next Run re-announces from scratch).
	bus := agent.NewBus(*nodeID, *underlay, dp, *edgeLoopback != "")
	const maxBackoff = 30 * time.Second
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		if err := bus.Run(ctx, rb, reconcile); err != nil {
			log.Printf("bus session ended: %v; reconnecting", err)
		}
		if time.Since(start) > maxBackoff {
			backoff = time.Second // long-lived session; reset the backoff
		}
		// Back off before reconnecting (capped exponential + jitter so agents don't
		// stampede the reflector in lockstep on recovery), but wake immediately on shutdown.
		wait := backoff + time.Duration(rand.Int64N(int64(backoff)))
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
		backoff = min(2*backoff, maxBackoff)
	}
	log.Print("shutdown signal received; agent exiting")
}
