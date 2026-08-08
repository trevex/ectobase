// Command vm-materializer runs the DOWNSTREAM controller that materializes local
// CompiledVM objects into kubevirt.io/v1.VirtualMachine objects (containerDisk boot,
// pinned-MAC overlay interfaces on the flowplane multus network, runStrategy). It
// targets a plain downstream k8s cluster with KubeVirt installed (in-cluster config by
// default, or --kubeconfig), NOT the central aggregated apiserver.
package main

import (
	"flag"
	"log"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"github.com/trevex/ectobase/netplane/controllers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubevirtv1 "kubevirt.io/api/core/v1"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	// blank import registers the --kubeconfig flag on flag.CommandLine via init().
	_ "sigs.k8s.io/controller-runtime/pkg/client/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	flag.Parse()

	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		log.Fatalf("add netv1 scheme: %v", err)
	}
	if err := kubevirtv1.AddToScheme(scheme); err != nil {
		log.Fatalf("add kubevirt scheme: %v", err)
	}
	if err := cdiv1.AddToScheme(scheme); err != nil {
		log.Fatalf("add cdi scheme: %v", err)
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

	if err := (&controllers.VMMaterializerReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup vm-materializer controller: %v", err)
	}

	if err := (&controllers.VolumeMaterializerReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup volume-materializer controller: %v", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatalf("manager: %v", err)
	}
}
