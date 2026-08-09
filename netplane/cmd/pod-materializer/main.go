// Command pod-materializer runs the DOWNSTREAM controller that materializes local
// CompiledContainer objects into v1.Pod objects (attached to the flowplane overlay via
// Multus + the flowplane-cni annotation, pinned to a node). It targets a plain downstream
// k8s cluster with Multus + flowplane-cni installed (in-cluster config by default, or
// --kubeconfig), NOT the hub aggregated apiserver.
package main

import (
	"flag"
	"log"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/netplane/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	// blank import registers the --kubeconfig flag on flag.CommandLine via init().
	_ "sigs.k8s.io/controller-runtime/pkg/client/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	flag.Parse()

	scheme := runtime.NewScheme()
	if err := compiledv1.AddToScheme(scheme); err != nil {
		log.Fatalf("add compiled scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		log.Fatalf("add corev1 scheme: %v", err)
	}
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	cfg, err := ctrl.GetConfig()
	if err != nil {
		log.Fatalf("get config: %v", err)
	}

	// Disable the metrics server: the materializer may run hostNetwork; a default :8080
	// listener collides on rolling restart. Nothing scrapes it in this deployment.
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		log.Fatalf("new manager: %v", err)
	}

	if err := (&controllers.PodMaterializerReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup pod-materializer controller: %v", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatalf("manager: %v", err)
	}
}
