// Command controller runs the dispatch control-plane reconcilers: it watches
// NATGateway and NetworkInterface objects and writes deterministic
// (public-IP, port-block) allocations to NATGateway.Status.Allocations; and
// watches NetworkInterfaces + NetworkPolicies to write CompiledNIC objects.
package main

import (
	"flag"
	"log"
	"os"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	"github.com/trevex/ectobase/mesh/controllers"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	// registers --kubeconfig flag to flag.CommandLine via init().
	_ "sigs.k8s.io/controller-runtime/pkg/client/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	// CRITICAL: disable client-go streaming list-watch before any client/manager construction.
	// This controller now targets the dispatch aggregated apiserver, which does not support the
	// client-go WatchList; without this flag the informer stalls silently and no events are delivered.
	os.Setenv("KUBE_FEATURE_WatchListClient", "false") //nolint:errcheck

	var (
		dispatchKubeconfig string
		clusterName   string
		networkName   string
	)
	flag.StringVar(&dispatchKubeconfig, "dispatch-kubeconfig", "", "Path to the dispatch aggregated-apiserver kubeconfig (falls back to in-cluster/KUBECONFIG when empty).")
	flag.StringVar(&clusterName, "cluster-name", "", "Default cluster binding stamped onto CompiledNICs whose NIC has no owning VirtualMachine.")
	flag.StringVar(&networkName, "network-name", "flowplane-overlay", "Multus NetworkAttachmentDefinition name for the flowplane overlay binding stamped onto CompiledVMs.")
	flag.Parse()

	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		log.Fatalf("add scheme: %v", err)
	}
	if err := compiledv1.AddToScheme(scheme); err != nil {
		log.Fatalf("add compiled scheme: %v", err)
	}
	if err := computev1.AddToScheme(scheme); err != nil {
		log.Fatalf("add compute scheme: %v", err)
	}
	if err := storagev1.AddToScheme(scheme); err != nil {
		log.Fatalf("add storage scheme: %v", err)
	}

	// Build the rest.Config from --dispatch-kubeconfig if given, else fall back to the
	// controller-runtime default (in-cluster, then --kubeconfig / KUBECONFIG).
	var cfg *rest.Config
	var err error
	if dispatchKubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", dispatchKubeconfig)
	} else {
		cfg, err = ctrl.GetConfig()
	}
	if err != nil {
		log.Fatalf("get config: %v", err)
	}

	// Disable the metrics server: the controller runs hostNetwork (see the compiler Deployment in
	// charts/ectobase-dispatch/templates/compiler.yaml),
	// so a default :8080 listener collides on rolling restart (new pod can't bind while the old holds
	// it) → crashloop. Nothing scrapes it in this deployment; "0" turns it off.
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		log.Fatalf("new manager: %v", err)
	}

	if err := (&controllers.NATGatewayReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup natgateway controller: %v", err)
	}

	if err := (&controllers.CompiledNICReconciler{Client: mgr.GetClient(), DefaultClusterName: clusterName}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup compilednic controller: %v", err)
	}

	if err := (&controllers.CompiledVMReconciler{Client: mgr.GetClient(), NetworkName: networkName}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup compiledvm controller: %v", err)
	}

	if err := (&controllers.CompiledContainerReconciler{Client: mgr.GetClient(), NetworkName: networkName}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup compiledcontainer controller: %v", err)
	}

	if err := (&controllers.CompiledVolumeAttachmentReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup compiledvolumeattachment controller: %v", err)
	}

	if err := (&controllers.VPCPeeringReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup vpcpeering controller: %v", err)
	}

	if err := (&controllers.VPCReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup vpc controller: %v", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatalf("manager: %v", err)
	}
}
