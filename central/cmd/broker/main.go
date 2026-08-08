// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Command broker runs the per-cluster broker: it watches the compiled objects
// (CompiledNIC, CompiledVM, CompiledVolumeAttachment, CompiledContainer) in the CENTRAL aggregated
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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	platforminstall "github.com/trevex/ectobase/api/platform/install"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/central/pkg/broker"
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

	// Build scheme covering all groups the broker touches:
	//   - net.ectobase.dev (networking types, on central),
	//   - compiled.ectobase.dev (CompiledNIC + CompiledVM + CompiledContainer + CompiledVolumeAttachment sync, on central),
	//   - platform.ectobase.dev (ClusterPool lease/capacity heartbeat, on central),
	//   - core/v1 (downstream Node list for capacity reporting).
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		log.Fatalf("register net.ectobase.dev scheme: %v", err)
	}
	if err := compiledv1.AddToScheme(scheme); err != nil {
		log.Fatalf("register compiled.ectobase.dev scheme: %v", err)
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
				&compiledv1.CompiledNIC{}: {
					Field: fields.OneTermEqualSelector("spec.clusterName", clusterName),
				},
				&compiledv1.CompiledVM{}: {
					Field: fields.OneTermEqualSelector("spec.clusterName", clusterName),
				},
				&compiledv1.CompiledVolumeAttachment{}: {
					Field: fields.OneTermEqualSelector("spec.clusterName", clusterName),
				},
				&compiledv1.CompiledContainer{}: {
					Field: fields.OneTermEqualSelector("spec.clusterName", clusterName),
				},
			},
		},
	})
	if err != nil {
		log.Fatalf("new manager: %v", err)
	}

	// The cache's ByObject.Field selector is only a server-side WATCH filter; the broker's
	// Broker.List(MatchingFields{"spec.clusterName"}) against the cached client additionally needs a
	// registered field INDEX, else it fails "Index with name field:spec.clusterName does not exist"
	// and nothing ever syncs downstream. Register the index for each synced type.
	idxCtx := context.Background()
	idx := func(obj client.Object, extract func(client.Object) string) {
		if ierr := mgr.GetFieldIndexer().IndexField(idxCtx, obj, "spec.clusterName", func(o client.Object) []string {
			return []string{extract(o)}
		}); ierr != nil {
			log.Fatalf("index spec.clusterName on %T: %v", obj, ierr)
		}
	}
	idx(&compiledv1.CompiledNIC{}, func(o client.Object) string { return o.(*compiledv1.CompiledNIC).Spec.ClusterName })
	idx(&compiledv1.CompiledVM{}, func(o client.Object) string { return o.(*compiledv1.CompiledVM).Spec.ClusterName })
	idx(&compiledv1.CompiledVolumeAttachment{}, func(o client.Object) string { return o.(*compiledv1.CompiledVolumeAttachment).Spec.ClusterName })
	idx(&compiledv1.CompiledContainer{}, func(o client.Object) string { return o.(*compiledv1.CompiledContainer).Spec.ClusterName })

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
		For(&compiledv1.CompiledNIC{}).
		Complete(r); err != nil {
		log.Fatalf("setup broker controller: %v", err)
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("compiledvm").
		For(&compiledv1.CompiledVM{}).
		Complete(r); err != nil {
		log.Fatalf("setup compiledvm broker controller: %v", err)
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("compiledvolumeattachment").
		For(&compiledv1.CompiledVolumeAttachment{}).
		Complete(r); err != nil {
		log.Fatalf("setup compiledvolumeattachment broker controller: %v", err)
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("compiledcontainer").
		For(&compiledv1.CompiledContainer{}).
		Complete(r); err != nil {
		log.Fatalf("setup compiledcontainer broker controller: %v", err)
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

	// Upward status reporter: every 10s, gather the downstream fence facts (each node's
	// /64 + each VM's running node) and stamp them into central (ClusterPool
	// NodePrefixes/NodeDrain + per-VM Placement). Separate from the lease heartbeater so
	// a slow node/VMI list never delays the lease renewal.
	sr := &statusReporter{
		central:     mgr.GetClient(),
		downstream:  downstreamClient,
		clusterName: clusterName,
		interval:    10 * time.Second,
	}
	if err := mgr.Add(sr); err != nil {
		log.Fatalf("add status reporter runnable: %v", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatalf("manager: %v", err)
	}
}

// statusReporter periodically reports this pool's fence facts upward to central via
// Broker.ReportStatus. It gathers the (fuzzy-sourced) node /64 prefixes + VM->node
// map from the downstream cluster, keeping that gathering out of the clean, unit-
// tested ReportStatus seam.
type statusReporter struct {
	central     client.Client
	downstream  client.Client
	clusterName string
	interval    time.Duration
}

// Start runs reportOnce every interval until ctx is done (manager.Runnable).
func (s *statusReporter) Start(ctx context.Context) error {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	_ = s.reportOnce(ctx) // best-effort immediate report; retried next tick on error
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := s.reportOnce(ctx); err != nil {
				log.Printf("status report: %v", err)
			}
		}
	}
}

// reportOnce gathers downstream fence facts and calls Broker.ReportStatus.
func (s *statusReporter) reportOnce(ctx context.Context) error {
	nodes, err := s.gatherNodes(ctx)
	if err != nil {
		return fmt.Errorf("gather nodes: %w", err)
	}
	vmNode := s.gatherVMNodes(ctx)
	b := &broker.Broker{Central: s.central, Downstream: s.downstream, ClusterName: s.clusterName}
	return b.ReportStatus(ctx, nodes, vmNode)
}

// nodePrefixFromNode returns the node's underlay /64 fence prefix from the annotation the
// netplane agent stamps on its own Node, or "" if absent (the node is not fence-eligible).
func nodePrefixFromNode(n *corev1.Node) string {
	return n.Annotations[netv1.NodeUnderlayPrefixAnnotation]
}

// gatherNodes lists downstream nodes and reads each node's /64 fence prefix from the
// agent-stamped NodeUnderlayPrefixAnnotation. A node without it is not fence-eligible
// (dropped from NodePrefixes by NodePrefixesFromNodes) — safer than a wrong prefix.
func (s *statusReporter) gatherNodes(ctx context.Context) ([]broker.NodeFact, error) {
	nodeList := &corev1.NodeList{}
	if err := s.downstream.List(ctx, nodeList); err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]broker.NodeFact, 0, len(nodeList.Items))
	for i := range nodeList.Items {
		n := &nodeList.Items[i]
		out = append(out, broker.NodeFact{Name: n.Name, Prefix: nodePrefixFromNode(n)})
	}
	return out, nil
}

// gatherVMNodes maps each downstream KubeVirt VirtualMachineInstance's
// "namespace/name" -> the node it runs on (VMI.status.nodeName). Read via unstructured
// so central need not import the heavy kubevirt.io/api module. Best-effort: if the VMI
// CRD is absent (no KubeVirt on the downstream) it returns an empty map, and
// ReportStatus still stamps the node prefixes + an all-drained NodeDrain.
func (s *statusReporter) gatherVMNodes(ctx context.Context) map[string]string {
	vmis := &unstructured.UnstructuredList{}
	vmis.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "kubevirt.io",
		Version: "v1",
		Kind:    "VirtualMachineInstanceList",
	})
	if err := s.downstream.List(ctx, vmis); err != nil {
		// No KubeVirt / no VMIs — not fatal; report prefixes with nothing busy.
		return map[string]string{}
	}
	out := make(map[string]string, len(vmis.Items))
	for i := range vmis.Items {
		vmi := &vmis.Items[i]
		nodeName, found, err := unstructured.NestedString(vmi.Object, "status", "nodeName")
		if err != nil || !found || nodeName == "" {
			continue // not scheduled to a node yet
		}
		out[vmi.GetNamespace()+"/"+vmi.GetName()] = nodeName
	}
	return out
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
// It holds no per-object state: every CompiledNIC, CompiledVM,
// CompiledVolumeAttachment, or CompiledContainer event triggers a full SyncOnce +
// SyncCompiledVMs + SyncCompiledVolumeAttachments + SyncCompiledContainers
// (declarative set-reconcile; idempotent and restart-safe).
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
	if err := b.SyncCompiledContainers(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}
