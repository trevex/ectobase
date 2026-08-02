// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/trevex/ectobase/central/apis/platform"
	"github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// Install registers the API group and adds types to a scheme
func Install(scheme *runtime.Scheme) {
	utilruntime.Must(platform.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(scheme.SetVersionPriority(v1alpha1.SchemeGroupVersion))
}

// AddToScheme is a convenience wrapper around Install for callers that expect
// the standard func(scheme *runtime.Scheme) error signature.
func AddToScheme(scheme *runtime.Scheme) error {
	Install(scheme)
	return nil
}
