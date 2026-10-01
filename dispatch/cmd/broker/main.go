// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Command broker runs the per-cluster broker: it watches the compiled objects
// (CompiledNIC, CompiledVM, CompiledVolumeAttachment, CompiledContainer) in the DISPATCH aggregated
// apiserver (filtered by spec.clusterName) and set-reconciles them onto a
// DOWNSTREAM cluster's apiserver.
//
// Required env: KUBE_FEATURE_WatchListClient=false (set unconditionally below).
// The aggregated apiserver does not support the client-go streaming list-watch;
// without this flag the informer stalls silently. The Deployment manifest
// must carry this in its env stanza as well.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	platforminstall "github.com/trevex/ectobase/api/platform/install"
	"github.com/trevex/ectobase/api/validate"
	"github.com/trevex/ectobase/dispatch/pkg/broker"
)

func main() {
	// CRITICAL: disable client-go streaming list-watch before any client/manager
	// construction. The aggregated apiserver does not support WatchList; without
	// this the informer stalls silently and no events are delivered.
	os.Setenv("KUBE_FEATURE_WatchListClient", "false") //nolint:errcheck

	var (
		downstreamKubeconfig string
		clusterName          string
		routebusSecret       string
		routebusSecretNS     string
	)
	flag.StringVar(&downstreamKubeconfig, "downstream-kubeconfig", "", "Path to the downstream cluster kubeconfig.")
	flag.StringVar(&clusterName, "cluster-name", "", "Cluster name this broker instance serves (required).")
	flag.StringVar(&routebusSecret, "routebus-intermediate-secret", "", "if set, bootstrap this pool's route-bus intermediate CA into this Secret (enables the mTLS PKI); empty => disabled")
	flag.StringVar(&routebusSecretNS, "routebus-intermediate-namespace", os.Getenv("POD_NAMESPACE"), "namespace for the intermediate CA Secret (defaults to POD_NAMESPACE)")
	var routebusCIDRs string
	flag.StringVar(&routebusCIDRs, "routebus-underlay-cidrs", "", "comma-separated pool underlay CIDRs (e.g. the pool /48); the intermediate is IP-name-constrained to these so it can only mint node leaves inside the pool's underlay")
	var dispatchServer, dispatchCA, dispatchCert, dispatchKey string
	flag.StringVar(&dispatchServer, "dispatch-server", "", "dispatch apiserver URL (mTLS mode); with --dispatch-{ca,client-cert,client-key}")
	flag.StringVar(&dispatchCA, "dispatch-ca", "", "CA file verifying the dispatch serving cert")
	flag.StringVar(&dispatchCert, "dispatch-client-cert", "", "broker client cert file (cert-manager-rotated)")
	flag.StringVar(&dispatchKey, "dispatch-client-key", "", "broker client key file")
	var dispatchBootstrapKubeconfig string
	flag.StringVar(&dispatchBootstrapKubeconfig, "dispatch-bootstrap-kubeconfig", "", "first-boot bootstrap-token kubeconfig; used to bootstrap the pool intermediate before the steady-state mTLS leaf exists")
	flag.Parse()

	if clusterName == "" {
		log.Fatal("--cluster-name is required")
	}
	if dispatchServer == "" {
		log.Fatal("--dispatch-server is required")
	}

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	// SetupSignalHandler must be called exactly once; ctx is reused below for the first-boot
	// bootstrap phase and for the final mgr.Start.
	ctx := ctrl.SetupSignalHandler()

	// Build scheme covering all groups the broker touches:
	//   - net.ectobase.dev (networking types, on dispatch),
	//   - compiled.ectobase.dev (CompiledNIC + CompiledVM + CompiledContainer + CompiledVolumeAttachment sync, on dispatch),
	//   - platform.ectobase.dev (ClusterPool lease/capacity heartbeat, on dispatch),
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

	// Downstream client — plain client.Client (no cache; broker writes here directly).
	downstreamCfg, err := clientcmd.BuildConfigFromFlags("", downstreamKubeconfig)
	if err != nil {
		log.Fatalf("build downstream rest.Config: %v", err)
	}
	downstreamClient, err := client.New(downstreamCfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("build downstream client: %v", err)
	}

	// Pool underlay CIDRs — parsed once; used by both the first-boot bootstrap phase below
	// and the steady-state renewal bootstrapper added as a manager runnable further down.
	var cidrs []string
	for _, c := range strings.Split(routebusCIDRs, ",") {
		if c = strings.TrimSpace(c); c != "" {
			cidrs = append(cidrs, c)
		}
	}

	// FIRST-BOOT BOOTSTRAP (mTLS mode only): a fresh pool has no steady-state client cert yet —
	// cert-manager only issues the broker's leaf (broker-dispatch-tls) AFTER the pool
	// intermediate exists, and the intermediate is bootstrapped BY the broker over dispatch.
	// Break that chicken-and-egg with a short-lived bootstrap-token connection: bootstrap the
	// intermediate once, then wait for cert-manager to mint the leaf before building the
	// steady-state dispatch client below.
	mtls := dispatchServer != ""
	if mtls && routebusSecret != "" && needsBootstrap(dispatchCert, dispatchKey) {
		if dispatchBootstrapKubeconfig == "" {
			log.Fatal("mTLS mode with no client cert present requires --dispatch-bootstrap-kubeconfig for first-boot bootstrap")
		}
		bootCfg, berr := clientcmd.BuildConfigFromFlags("", dispatchBootstrapKubeconfig)
		if berr != nil {
			log.Fatalf("build bootstrap dispatch config: %v", berr)
		}
		bootClient, berr := client.New(bootCfg, client.Options{Scheme: scheme})
		if berr != nil {
			log.Fatalf("build bootstrap dispatch client: %v", berr)
		}
		boot := &broker.PoolCertBootstrapper{
			Dispatch: bootClient, Downstream: downstreamClient,
			PoolName: clusterName, SecretName: routebusSecret, SecretNS: routebusSecretNS,
			PermittedCIDRs: cidrs,
		}
		log.Printf("first boot: bootstrapping pool intermediate via bootstrap token")
		if berr := boot.EnsureOnce(ctx); berr != nil {
			log.Fatalf("bootstrap pool intermediate: %v", berr)
		}
		log.Printf("intermediate bootstrapped; waiting for cert-manager to mint the client cert")
		if berr := waitForLeaf(ctx, dispatchCert, dispatchKey, 5*time.Minute, 3*time.Second); berr != nil {
			log.Fatalf("waiting for broker client cert: %v", berr)
		}
	}

	// Dispatch rest.Config — mTLS from cert files (client-go re-reads the cert/key/CA files
	// from disk, so cert-manager rotation needs no broker restart).
	dispatchCfg, err := dispatchConfig(dispatchAuth{
		server: dispatchServer, caFile: dispatchCA, certFile: dispatchCert, keyFile: dispatchKey,
	})
	if err != nil {
		log.Fatalf("build dispatch rest.Config: %v", err)
	}

	// Manager on the DISPATCH config. The cache is scoped to this pool's NAMESPACE rather than
	// filtered by a spec.clusterName field selector. Both bound what the informer streams, but only
	// the namespace scope is expressible in RBAC: a cluster-wide LIST/WATCH authorizes against an
	// empty namespace in its SubjectAccessReview, which a namespaced RoleBinding can never match,
	// so a field-selector cache would 403 the moment per-pool read RBAC is switched on.
	poolNamespace := validate.PoolNamespace(clusterName)
	mgr, err := ctrl.NewManager(dispatchCfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{poolNamespace: {}},
		},
	})
	if err != nil {
		log.Fatalf("new manager: %v", err)
	}

	// The dispatch client comes from the manager so it reads through the cache.
	if err := setupSync(mgr, &brokerReconciler{
		dispatch:    mgr.GetClient(),
		downstream:  downstreamClient,
		clusterName: clusterName,
	}); err != nil {
		log.Fatalf("setup broker sync: %v", err)
	}

	// One UNCACHED dispatch client for the cluster-scoped resources (ClusterPool,
	// RouteBusIdentity). A cached read of either would start a cluster-wide LIST/WATCH, and RBAC
	// cannot narrow a list/watch to one object — resourceNames only matches a named request. Going
	// by name keeps both inside this pool's own grant.
	dispatchDirect, err := client.New(dispatchCfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("build direct dispatch client: %v", err)
	}

	// Heartbeater: renew the ClusterPool lease + report node capacity every 10s.
	holderIdentity, err := os.Hostname()
	if err != nil {
		holderIdentity = clusterName
	}
	hb := &broker.Heartbeater{
		Dispatch:       dispatchDirect,
		PoolName:       clusterName,
		HolderIdentity: holderIdentity,
		Reporter:       &nodeCapacityReporter{downstream: downstreamClient},
		Interval:       10 * time.Second,
	}
	if err := mgr.Add(hb); err != nil {
		log.Fatalf("add heartbeater runnable: %v", err)
	}

	// Upward status reporter: every 10s, gather the downstream fence facts (each node's
	// /64 + each VM's running node) and stamp them into the dispatch (ClusterPool
	// NodePrefixes/NodeDrain + per-VM Placement). Separate from the lease heartbeater so
	// a slow node/VMI list never delays the lease renewal.
	sr := &statusReporter{
		dispatch:    mgr.GetClient(),
		pools:       dispatchDirect,
		downstream:  downstreamClient,
		clusterName: clusterName,
		interval:    10 * time.Second,
	}
	if err := mgr.Add(sr); err != nil {
		log.Fatalf("add status reporter runnable: %v", err)
	}

	// Route-bus PKI bootstrap: when enabled, generate this pool's intermediate CA keypair
	// locally, submit a CSR as a RouteBusIdentity on dispatch, and write the signed intermediate
	// + root bundle into the pool Secret that backs the pool cert-manager CA Issuer. A direct
	// (uncached) dispatch client avoids adding a cluster-wide RouteBusIdentity watch to the cache.
	if routebusSecret != "" {
		boot := &broker.PoolCertBootstrapper{
			Dispatch:       dispatchDirect,
			Downstream:     downstreamClient,
			PoolName:       clusterName,
			SecretName:     routebusSecret,
			SecretNS:       routebusSecretNS,
			PermittedCIDRs: cidrs,
		}
		if err := mgr.Add(boot); err != nil {
			log.Fatalf("add routebus cert bootstrapper: %v", err)
		}
	}

	if err := mgr.Start(ctx); err != nil {
		log.Fatalf("manager: %v", err)
	}
}

// statusReporter periodically reports this pool's fence facts upward to the dispatch via
// Broker.ReportStatus. It gathers the (fuzzy-sourced) node /64 prefixes + VM->node
// map from the downstream cluster, keeping that gathering out of the clean, unit-
// tested ReportStatus seam.
type statusReporter struct {
	dispatch    client.Client
	pools       client.Client // uncached: ClusterPool is cluster-scoped (see the hoisted client)
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
	vmNode, vmErr := s.gatherVMNodes(ctx)
	if vmErr != nil {
		// Fail closed: without knowing where VMIs run, the drain report stays as stored this tick.
		log.Printf("status report: %v; leaving the drain report unchanged", vmErr)
	}
	b := &broker.Broker{Dispatch: s.dispatch, Pools: s.pools, Downstream: s.downstream, ClusterName: s.clusterName}
	if err := b.ReportStatus(ctx, nodes, vmNode, vmErr == nil); err != nil {
		return err
	}
	// Reported on the same tick, but its failures are not folded into the fence signal above:
	// a disk identity that never reaches the dispatch means a later rebind of that workload
	// provisions a blank disk, so it has to be retried rather than logged and forgotten.
	return b.ReportDiskIdentities(ctx)
}

// nodePrefixFromNode returns the node's underlay /64 fence prefix from the annotation the
// mesh agent stamps on its own Node, or "" if absent (the node is not fence-eligible).
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
// so the dispatch need not import the heavy kubevirt.io/api module.
//
// KubeVirt not installed on the downstream is an empty set: no VMI can run there, so every
// fenced /64 is drained. Any other failure to list is returned, and the caller leaves the
// drain report as stored: reading "could not list" as "nothing runs" would report drained
// /64s that still run VMs, and central releases fences on that.
func (s *statusReporter) gatherVMNodes(ctx context.Context) (map[string]string, error) {
	vmis := &unstructured.UnstructuredList{}
	vmis.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "kubevirt.io",
		Version: "v1",
		Kind:    "VirtualMachineInstanceList",
	})
	if err := s.downstream.List(ctx, vmis); err != nil {
		if kubevirtAbsent(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("list VMIs: %w", err)
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
	return out, nil
}

// kubevirtAbsent reports whether a VMI list failed only because the downstream does not serve
// kubevirt.io at all. controller-runtime's RESTMapper says so in two shapes: a NoKindMatchError
// when the group is unknown, and an ErrResourceDiscoveryFailed whose group versions all failed
// discovery as NotFound (it unwraps those as NoResourceMatchError). The latter must be checked
// entry by entry: errors.Is would also match a map where one version is missing and another
// failed for a reason that says nothing about whether KubeVirt is there.
func kubevirtAbsent(err error) bool {
	var df *apiutil.ErrResourceDiscoveryFailed
	if errors.As(err, &df) {
		for _, e := range *df {
			if !apierrors.IsNotFound(e) && !meta.IsNoMatchError(e) {
				return false
			}
		}
		return len(*df) > 0
	}
	return meta.IsNoMatchError(err)
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
