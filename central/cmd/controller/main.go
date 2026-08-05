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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	// registers the --kubeconfig flag on flag.CommandLine via init().
	_ "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	"github.com/trevex/ectobase/central/apis/platform/install"
	"github.com/trevex/ectobase/central/internal/clusterpool"
	"github.com/trevex/ectobase/central/internal/failover"
	"github.com/trevex/ectobase/central/internal/scheduler"
)

func main() {
	// CRITICAL: disable client-go streaming list-watch before any client/manager
	// construction. The aggregated apiserver does not support WatchList; without
	// this the scheduler/clusterpool informers stall silently and no events are
	// delivered. The Deployment manifest carries this in its env stanza too.
	os.Setenv("KUBE_FEATURE_WatchListClient", "false") //nolint:errcheck

	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	install.Install(scheme)
	// The scheduler reads VirtualMachine (net) + ClusterPool (platform), so both
	// groups must be present on the manager scheme.
	if err := netv1.AddToScheme(scheme); err != nil {
		log.Fatalf("register net.ectobase.dev scheme: %v", err)
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

	// Tier-2 failover: threshold (2m) is deliberately > pool-health's 30s
	// HealthStale — a pool must be Unknown for a while before a destructive
	// rebind. DenyFencer is the default so Tier-2 fails safe until Phase-4
	// storage/network fence actuators exist. Both scheduler + failover watch
	// ClusterPool; independent controllers on the same manager is fine.
	if err := (&failover.Reconciler{Client: mgr.GetClient(), StorageFencer: failover.DenyFencer{}, NetworkFencer: failover.DenyFencer{}, FailoverThreshold: 2 * time.Minute}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup failover controller: %v", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatalf("manager: %v", err)
	}
}
