// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Command broker runs the per-cluster broker: it watches the compiled objects
// (CompiledNIC, CompiledVM, CompiledVolumeAttachment) in the CENTRAL aggregated
// apiserver (filtered by spec.clusterName) and set-reconciles them onto a
// DOWNSTREAM cluster's apiserver.
//
// Required env: KUBE_FEATURE_WatchListClient=false (set unconditionally below).
// The aggregated apiserver does not support the client-go streaming list-watch;
// without this flag the informer stalls silently. The eventual Deployment manifest
// (Task 6) must carry this in its env stanza as well.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
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

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platforminstall "github.com/trevex/ectobase/central/apis/platform/install"
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

	// Build scheme covering all three groups the broker touches:
	//   - net.ectobase.dev  (CompiledNIC + CompiledVM sync, on central),
	//   - platform.ectobase.dev (ClusterPool lease/capacity heartbeat, on central),
	//   - core/v1 (downstream Node list for capacity reporting).
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		log.Fatalf("register net.ectobase.dev scheme: %v", err)
	}
	platforminstall.Install(scheme)
	if err := corev1.AddToScheme(scheme); err != nil {
		log.Fatalf("register corev1 scheme: %v", err)
	}
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
				&netv1.CompiledNIC{}: {
					Field: fields.OneTermEqualSelector("spec.clusterName", clusterName),
				},
				&netv1.CompiledVM{}: {
					Field: fields.OneTermEqualSelector("spec.clusterName", clusterName),
				},
				&netv1.CompiledVolumeAttachment{}: {
					Field: fields.OneTermEqualSelector("spec.clusterName", clusterName),
				},
			},
		},
	})
	if err != nil {
		log.Fatalf("new manager: %v", err)
	}

	// Reconciler: on any CompiledNIC OR CompiledVM event, trigger a full set-reconcile
	// of BOTH types. A full resync per event is correct here: the syncs are declarative +
	// idempotent (derive both desired and current sets live; no in-memory diff state).
	// The central client comes from the manager so it reads through the cache.
	r := &brokerReconciler{
		central:     mgr.GetClient(),
		downstream:  downstreamClient,
		clusterName: clusterName,
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&netv1.CompiledNIC{}).
		Complete(r); err != nil {
		log.Fatalf("setup broker controller: %v", err)
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("compiledvm").
		For(&netv1.CompiledVM{}).
		Complete(r); err != nil {
		log.Fatalf("setup compiledvm broker controller: %v", err)
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("compiledvolumeattachment").
		For(&netv1.CompiledVolumeAttachment{}).
		Complete(r); err != nil {
		log.Fatalf("setup compiledvolumeattachment broker controller: %v", err)
	}

	// Heartbeater: renew the ClusterPool lease + report node capacity every 10s.
	holderIdentity, err := os.Hostname()
	if err != nil {
		holderIdentity = clusterName
	}
	hb := &broker.Heartbeater{
		Central:        mgr.GetClient(),
		PoolName:       clusterName,
		HolderIdentity: holderIdentity,
		Reporter:       &nodeCapacityReporter{downstream: downstreamClient},
		Interval:       10 * time.Second,
	}
	if err := mgr.Add(hb); err != nil {
		log.Fatalf("add heartbeater runnable: %v", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatalf("manager: %v", err)
	}
}

// nodeCapacityReporter sums Status.Allocatable over all Ready downstream nodes.
type nodeCapacityReporter struct {
	downstream client.Client
}

// Report lists downstream nodes and sums Allocatable resources over Ready nodes only.
func (r *nodeCapacityReporter) Report(ctx context.Context) (corev1.ResourceList, error) {
	nodes := &corev1.NodeList{}
	if err := r.downstream.List(ctx, nodes); err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	total := corev1.ResourceList{}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if !nodeIsReady(node) {
			continue
		}
		for name, qty := range node.Status.Allocatable {
			if existing, ok := total[name]; ok {
				existing.Add(qty)
				total[name] = existing
			} else {
				// Copy the quantity so we don't hold a reference into the node list.
				copied := qty.DeepCopy()
				total[name] = copied
			}
		}
	}
	return total, nil
}

// nodeIsReady returns true when the node has a Ready condition with Status True.
func nodeIsReady(node *corev1.Node) bool {
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// brokerReconciler wraps the broker engine so it satisfies reconcile.Reconciler.
// It holds no per-object state: every CompiledNIC, CompiledVM, or
// CompiledVolumeAttachment event triggers a full SyncOnce + SyncCompiledVMs +
// SyncCompiledVolumeAttachments (declarative set-reconcile; idempotent and restart-safe).
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
	if err := b.SyncCompiledVMs(ctx); err != nil {
		return ctrl.Result{}, err
	}
	if err := b.SyncCompiledVolumeAttachments(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}
