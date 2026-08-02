// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Command broker runs the per-cluster broker: it watches CompiledWorkload objects
// in the CENTRAL aggregated apiserver (filtered by spec.clusterName) and
// set-reconciles them onto a DOWNSTREAM cluster's apiserver.
//
// Required env: KUBE_FEATURE_WatchListClient=false (set unconditionally below).
// The aggregated apiserver does not support the client-go streaming list-watch;
// without this flag the informer stalls silently. The eventual Deployment manifest
// (Task 6) must carry this in its env stanza as well.
package main

import (
	"context"
	"flag"
	"log"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
	"github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/internal/broker"
)

func main() {
	// CRITICAL: disable client-go streaming list-watch before any client/manager
	// construction. The aggregated apiserver does not support WatchList; without
	// this the informer stalls silently and no events are delivered.
	os.Setenv("KUBE_FEATURE_WatchListClient", "false") //nolint:errcheck

	var (
		centralKubeconfig    string
		downstreamKubeconfig string
		clusterName          string
	)
	flag.StringVar(&centralKubeconfig, "central-kubeconfig", "", "Path to the central aggregated-apiserver kubeconfig.")
	flag.StringVar(&downstreamKubeconfig, "downstream-kubeconfig", "", "Path to the downstream cluster kubeconfig.")
	flag.StringVar(&clusterName, "cluster-name", "", "Cluster name this broker instance serves (required).")
	flag.Parse()

	if clusterName == "" {
		log.Fatal("--cluster-name is required")
	}

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	// Build scheme: platform types + meta group (aggregated apiserver has no core-v1).
	scheme := runtime.NewScheme()
	platforminstall.Install(scheme)
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	// Central rest.Config — from --central-kubeconfig if given, else in-cluster/KUBECONFIG.
	centralCfg, err := clientcmd.BuildConfigFromFlags("", centralKubeconfig)
	if err != nil {
		log.Fatalf("build central rest.Config: %v", err)
	}

	// Downstream client — plain client.Client (no cache; broker writes here directly).
	downstreamCfg, err := clientcmd.BuildConfigFromFlags("", downstreamKubeconfig)
	if err != nil {
		log.Fatalf("build downstream rest.Config: %v", err)
	}
	downstreamClient, err := client.New(downstreamCfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("build downstream client: %v", err)
	}

	// Manager on the CENTRAL config. Cache is scoped to this cluster's slice via a
	// field selector on spec.clusterName so the informer only streams the objects
	// this broker owns — bounding both memory and apiserver watch traffic.
	mgr, err := ctrl.NewManager(centralCfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&v1alpha1.CompiledWorkload{}: {
					Field: fields.OneTermEqualSelector("spec.clusterName", clusterName),
				},
			},
		},
	})
	if err != nil {
		log.Fatalf("new manager: %v", err)
	}

	// Reconciler: on any CompiledWorkload event, trigger a full set-reconcile.
	// A full resync per event is correct here: SyncOnce is declarative + idempotent
	// (derives both desired and current sets live; no in-memory diff state).
	// The central client comes from the manager so it reads through the cache.
	r := &brokerReconciler{
		central:     mgr.GetClient(),
		downstream:  downstreamClient,
		clusterName: clusterName,
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.CompiledWorkload{}).
		Complete(r); err != nil {
		log.Fatalf("setup broker controller: %v", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatalf("manager: %v", err)
	}
}

// brokerReconciler wraps the broker engine so it satisfies reconcile.Reconciler.
// It holds no per-object state: every CompiledWorkload event triggers a full
// SyncOnce (declarative set-reconcile; idempotent and restart-safe).
type brokerReconciler struct {
	central     client.Client
	downstream  client.Client
	clusterName string
}

func (r *brokerReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	b := &broker.Broker{
		Central:     r.central,
		Downstream:  r.downstream,
		ClusterName: r.clusterName,
	}
	if err := b.SyncOnce(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}
