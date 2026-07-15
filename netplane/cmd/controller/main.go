// Command controller runs the central control-plane reconcilers: it watches
// NATGateway and NetworkInterface objects and writes deterministic
// (public-IP, port-block) allocations to NATGateway.Status.Allocations; and
// watches NetworkInterfaces + NetworkPolicies to write CompiledNIC objects.
package main

import (
	"flag"
	"log"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	"github.com/trevex/xdp-dp/netplane/controllers"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	// registers --kubeconfig flag to flag.CommandLine via init().
	_ "sigs.k8s.io/controller-runtime/pkg/client/config"
)

func main() {
	flag.Parse()

	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		log.Fatalf("add scheme: %v", err)
	}

	cfg, err := ctrl.GetConfig()
	if err != nil {
		log.Fatalf("get config: %v", err)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("new manager: %v", err)
	}

	if err := (&controllers.Reconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup natgateway controller: %v", err)
	}

	if err := (&controllers.CompiledNICReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup compilednic controller: %v", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatalf("manager: %v", err)
	}
}
