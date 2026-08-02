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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	// registers the --kubeconfig flag on flag.CommandLine via init().
	_ "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/trevex/ectobase/central/apis/platform/install"
	"github.com/trevex/ectobase/central/internal/clusterpool"
)

func main() {
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	install.Install(scheme)
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

	if err := (&clusterpool.Reconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup clusterpool controller: %v", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatalf("manager: %v", err)
	}
}
