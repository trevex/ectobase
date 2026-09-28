// Command vm-materializer runs the DOWNSTREAM controller that materializes local
// CompiledVM objects into kubevirt.io/v1.VirtualMachine objects (containerDisk boot,
// pinned-MAC overlay interfaces on the flowplane multus network, runStrategy). It
// targets a plain downstream k8s cluster with KubeVirt installed (in-cluster config by
// default, or --kubeconfig), NOT the dispatch aggregated apiserver.
package main

import (
	"flag"
	"log"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/mesh/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubevirtv1 "kubevirt.io/api/core/v1"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// blank import registers the --kubeconfig flag on flag.CommandLine via init().
	_ "sigs.k8s.io/controller-runtime/pkg/client/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	flag.Parse()

	// Without this, controller-runtime discards every log line -- including reconcile errors --
	// and the binary fails silently. A disk-identity bug was invisible here until this was added:
	// the only symptom was a disk that never got its reclaimPolicy flipped, with no error anywhere.
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	if err := compiledv1.AddToScheme(scheme); err != nil {
		log.Fatalf("add compiled scheme: %v", err)
	}
	if err := kubevirtv1.AddToScheme(scheme); err != nil {
		log.Fatalf("add kubevirt scheme: %v", err)
	}
	if err := cdiv1.AddToScheme(scheme); err != nil {
		log.Fatalf("add cdi scheme: %v", err)
	}
	// Core types: the disk-identity controller reads PersistentVolumeClaims and patches
	// PersistentVolumes, which without this fail at runtime with "no kind is registered".
	if err := corev1.AddToScheme(scheme); err != nil {
		log.Fatalf("add core scheme: %v", err)
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

	// Runs beside the volume-materializer because a PersistentVolume only exists downstream: it
	// retains each provisioned disk so a clusterName change detaches it instead of destroying it,
	// and records its CSI identity for the pool to report upward.
	if err := (&controllers.DiskIdentityReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup disk-identity controller: %v", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatalf("manager: %v", err)
	}
}
