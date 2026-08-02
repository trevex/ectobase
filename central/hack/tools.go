//go:build tools

// Package tools pins build- and code-generation dependencies for the central
// aggregated apiserver so they are recorded in go.mod before the API types and
// server code that import them exist. This file is never compiled into any
// binary (guarded by the "tools" build tag).
package tools

import (
	_ "go.opendefense.cloud/kit/apiserver"
	_ "go.opendefense.cloud/kit/envtest"
	_ "k8s.io/apimachinery/pkg/runtime"
	_ "k8s.io/apiserver/pkg/server"
	_ "k8s.io/client-go/rest"
	_ "k8s.io/code-generator/cmd/deepcopy-gen"
)
