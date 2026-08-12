// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Command controller runs the central control-plane reconcilers against the
// aggregated apiserver (platform.ectobase.dev). Today it runs the ClusterPool
// reconciler, which seeds a new pool's lifecycle phase to "Pending"; Phase 2's
// scheduler/failover reconcilers register on the same manager.
package main

import (
	"flag"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	// registers the --kubeconfig flag on flag.CommandLine via init().
	_ "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"github.com/trevex/ectobase/api/platform/install"
	"github.com/trevex/ectobase/hub/pkg/clusterpool"
	"github.com/trevex/ectobase/hub/pkg/failover"
	"github.com/trevex/ectobase/hub/pkg/fence"
	"github.com/trevex/ectobase/hub/pkg/scheduler"
	routebusv1 "github.com/trevex/ectobase/netplane/gen/routebusv1"
	"github.com/trevex/ectobase/netplane/routebus"
)

func main() {
	// CRITICAL: disable client-go streaming list-watch before any client/manager
	// construction. The aggregated apiserver does not support WatchList; without
	// this the scheduler/clusterpool informers stall silently and no events are
	// delivered. The Deployment manifest carries this in its env stanza too.
	os.Setenv("KUBE_FEATURE_WatchListClient", "false") //nolint:errcheck

	reflectorAdmin := flag.String("reflector-admin", "", "reflector RouteBusAdmin gRPC address (network fence); empty => DenyFencer")
	reflectorTLSCA := flag.String("reflector-tls-ca", "", "CA bundle to verify the reflector (enables mTLS on the admin dial)")
	reflectorTLSCert := flag.String("reflector-tls-cert", "", "hub-controller client cert presented to the reflector admin API")
	reflectorTLSKey := flag.String("reflector-tls-key", "", "hub-controller client key")
	csiDriver := flag.String("csi-driver", "rbd.csi.ceph.com", "CSI driver for NetworkFence")
	csiClusterID := flag.String("csi-cluster-id", "", "Ceph clusterID (fsid) written to NetworkFence spec.parameters.clusterID; required against a real ceph-csi driver")
	csiSecretName := flag.String("csi-secret-name", "rook-csi-rbd-provisioner", "NetworkFence provisioner secret name")
	csiSecretNS := flag.String("csi-secret-namespace", "rook-ceph", "NetworkFence provisioner secret namespace")

	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	install.Install(scheme)
	// The scheduler/failover read VirtualMachine (compute.ectobase.dev) + ClusterPool
	// (platform), and a NATGateway path touches net, so all three groups must be present
	// on the manager scheme.
	if err := netv1.AddToScheme(scheme); err != nil {
		log.Fatalf("register net.ectobase.dev scheme: %v", err)
	}
	if err := computev1.AddToScheme(scheme); err != nil {
		log.Fatalf("register compute.ectobase.dev scheme: %v", err)
	}
	// The aggregated group has no core-v1; register the meta options group so the
	// client can encode List/Watch/Status requests.
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	cfg := ctrl.GetConfigOrDie()

	// Disable the metrics server: a default :8080 listener collides on rolling
	// restart (new pod can't bind while the old holds it) → crashloop. Nothing
	// scrapes it in this deployment; "0" turns it off. Same lesson as the
	// netplane controller.
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		log.Fatalf("new manager: %v", err)
	}

	if err := (&clusterpool.Reconciler{Client: mgr.GetClient(), HealthStale: 30 * time.Second}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup clusterpool controller: %v", err)
	}

	if err := (&scheduler.Reconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup scheduler controller: %v", err)
	}

	// The Container pool-scheduler mirrors the VM scheduler: it binds unbound
	// Containers to a ClusterPool (VMs and Containers share pool capacity).
	if err := (&scheduler.ContainerReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup container scheduler controller: %v", err)
	}

	// Tier-2 failover: threshold (2m) is deliberately > pool-health's 30s
	// HealthStale — a pool must be Unknown for a while before a destructive
	// rebind. Both scheduler + failover watch ClusterPool; independent
	// controllers on the same manager is fine.
	//
	// The storage fencer is ALWAYS the real csi-addons NetworkFence actuator
	// (a cluster without csi-addons just errors on Fence → the barrier blocks →
	// fail-safe). The network fencer defaults to DenyFencer (fail-safe) and is
	// wired to the real reflector RouteBusAdmin only when -reflector-admin is set.
	var storageF failover.PrefixFencer = fence.NewStorageFencer(mgr.GetClient(), *csiDriver, *csiClusterID, client.ObjectKey{Name: *csiSecretName, Namespace: *csiSecretNS})
	var networkF failover.PrefixFencer = failover.DenyFencer{}
	if *reflectorAdmin != "" {
		creds := insecure.NewCredentials()
		if *reflectorTLSCA != "" || *reflectorTLSCert != "" || *reflectorTLSKey != "" {
			tc, terr := routebus.ClientTLS(*reflectorTLSCA, *reflectorTLSCert, *reflectorTLSKey)
			if terr != nil {
				log.Fatalf("reflector admin tls: %v", terr)
			}
			creds = tc
		}
		conn, derr := grpc.NewClient(*reflectorAdmin, grpc.WithTransportCredentials(creds))
		if derr != nil {
			log.Fatalf("dial reflector admin: %v", derr)
		}
		networkF = fence.NewNetworkFencer(routebusv1.NewRouteBusAdminClient(conn))
	}

	if err := (&failover.Reconciler{Client: mgr.GetClient(), StorageFencer: storageF, NetworkFencer: networkF, FailoverThreshold: 2 * time.Minute}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup failover controller: %v", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatalf("manager: %v", err)
	}
}
