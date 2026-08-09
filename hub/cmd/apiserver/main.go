// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"go.opendefense.cloud/kit/apiserver"

	compiledapi "github.com/trevex/ectobase/api/compiled"
	compiledinstall "github.com/trevex/ectobase/api/compiled/install"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computeapi "github.com/trevex/ectobase/api/compute"
	computeinstall "github.com/trevex/ectobase/api/compute/install"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	netapi "github.com/trevex/ectobase/api/net"
	netinstall "github.com/trevex/ectobase/api/net/install"
	storageapi "github.com/trevex/ectobase/api/storage"
	storageinstall "github.com/trevex/ectobase/api/storage/install"
	storagev1 "github.com/trevex/ectobase/api/storage/v1alpha1"
	"github.com/trevex/ectobase/api/platform"
	"github.com/trevex/ectobase/api/platform/install"
	"github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/hub/client-go/openapi"
	"github.com/trevex/ectobase/hub/pkg/clusterrestriction"
)

const (
	componentName = "central-apiserver"
)

var scheme = runtime.NewScheme()

func init() {
	install.Install(scheme)
	netinstall.Install(scheme)
	compiledinstall.Install(scheme)
	computeinstall.Install(scheme)
	storageinstall.Install(scheme)

	// we need to add the options to empty v1
	// TODO: fix the server code to avoid this
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	// TODO: keep the generic API server from wanting this
	unversioned := schema.GroupVersion{Group: "", Version: "v1"}
	scheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
	)
}

func main() {
	code := apiserver.NewBuilder(scheme).
		WithComponentName(componentName).
		WithOpenAPIDefinitions(componentName, "v0.1.0", openapi.GetOpenAPIDefinitions).
		// Thin ClusterRestriction: a broker (ectobase:cluster:<name>) may write only
		// its own ClusterPool status and may never set spec.clusterName. Enabled by
		// default; Phase-1 disables MutatingAdmissionPolicy/ValidatingAdmissionPolicy.
		WithAdmissionPlugin(clusterrestriction.PluginName, clusterrestriction.Register).
		With(apiserver.Resource(&platform.ClusterPool{}, v1alpha1.SchemeGroupVersion)).
		With(apiserver.Resource(&netapi.VPC{}, netv1.SchemeGroupVersion)).
		With(apiserver.Resource(&netapi.NetworkInterface{}, netv1.SchemeGroupVersion)).
		With(apiserver.Resource(&netapi.FirewallPolicy{}, netv1.SchemeGroupVersion)).
		With(apiserver.Resource(&netapi.FloatingIP{}, netv1.SchemeGroupVersion)).
		With(apiserver.Resource(&netapi.LoadBalancer{}, netv1.SchemeGroupVersion)).
		With(apiserver.Resource(&netapi.NATGateway{}, netv1.SchemeGroupVersion)).
		With(apiserver.Resource(&netapi.VPCPeering{}, netv1.SchemeGroupVersion)).
		With(apiserver.Resource(&storageapi.Volume{}, storagev1.SchemeGroupVersion)).
		With(apiserver.Resource(&computeapi.VirtualMachine{}, computev1.SchemeGroupVersion)).
		With(apiserver.Resource(&computeapi.Container{}, computev1.SchemeGroupVersion)).
		With(apiserver.Resource(&compiledapi.CompiledNIC{}, compiledv1.SchemeGroupVersion)).
		With(apiserver.Resource(&compiledapi.CompiledVM{}, compiledv1.SchemeGroupVersion)).
		With(apiserver.Resource(&compiledapi.CompiledVolumeAttachment{}, compiledv1.SchemeGroupVersion)).
		With(apiserver.Resource(&compiledapi.CompiledContainer{}, compiledv1.SchemeGroupVersion)).
		Execute()
	os.Exit(code)
}
