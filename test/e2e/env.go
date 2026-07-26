package e2e

// env.go — the SINGLE logical source of truth for the clab-fabric constants the Go
// e2e tests share with the shell scenarios.
//
// MUST match hack/clab/env.sh — the shell scenarios (hack/clab-up.sh,
// hack/multicluster-e2e.sh, hack/clab/cilium-up.sh) `source` env.sh; these Go
// consts MIRROR the same defaults so there is ONE logical source of truth. A Go
// test binary cannot `source` a bash file at compile time, so this mirrored block
// with a cross-link comment is the pragmatic single-source approach: whenever a
// value in hack/clab/env.sh changes, change it here too (and vice-versa).
//
// The env* helpers below additionally honour the SAME environment variable names
// env.sh exports (CLAB_*), so a run that overrides env.sh via the environment
// (e.g. `CLAB_DATAPLANE_PORT=1339 go test ...`) stays in agreement with the shell
// scenarios without any code change. Callers that need the raw default use the
// exported consts; callers that want the env-overridable value use the helpers.

import (
	"fmt"
	"os"
)

// Defaults mirrored from hack/clab/env.sh (keep in sync — see file doc above).
const (
	// CLAB_FABRIC_REFLECTOR6 — k01 control-plane fabric loopback (reflector + apiserver).
	FabricReflector6 = "fd00:db8:0:1::1"
	// CLAB_REFLECTOR_PORT — routebus reflector listen port.
	ReflectorPort = 1338
	// CLAB_DATAPLANE_PORT — DataplaneNode gRPC listen port.
	DataplanePort = 1337
	// CLAB_VNI — the blue VPC's VNI used by the multicluster scenario.
	FabricVNI = 100
	// CLAB_OVERLAY_IP_A / _C — the two cross-cluster endpoint overlay IPs.
	OverlayIPA = "10.0.0.1"
	OverlayIPC = "10.0.0.3"
	// CLAB_IMAGE_FLOWPLANE / _NETPLANE / _KINDNODE — the container images.
	ImageFlowplane = "ghcr.io/trevex/ectobase/flowplane:dev"
	ImageNetplane  = "ghcr.io/trevex/ectobase/netplane:dev"
	ImageKindNode  = "ghcr.io/trevex/ectobase/kind-node-fabric:dev"
	// CLAB_KIND_CENTRAL / _COMPUTE — the two kind cluster names.
	KindCentral = "k01"
	KindCompute = "k02"
	// CLAB_NODE_A / _C — the two endpoint-hosting node containers (one per cluster).
	NodeA = "k01-control-plane"
	NodeC = "k02-control-plane"

	// WorkerNode is the second k01 node used by the single-cluster smoke tests as the
	// "hypervisor" that runs flowplane and hosts the guest. It has no env.sh knob (the
	// scenarios that need it derive it from the topology), so it is defined here only.
	WorkerNode = "k01-worker"
)

// getenv returns os.Getenv(key) if non-empty, else def. Lets a run that overrides
// hack/clab/env.sh via the environment stay in agreement (see file doc).
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// DataplaneAddrFromEnv returns "127.0.0.1:<port>" honouring CLAB_DATAPLANE_PORT,
// defaulting to the mirrored DataplanePort. This is the address flowplane serve
// listens on inside a clab/kind node.
func DataplaneAddrFromEnv() string {
	return "127.0.0.1:" + getenv("CLAB_DATAPLANE_PORT", fmt.Sprint(DataplanePort))
}

// FlowplaneImageFromEnv returns the flowplane image, honouring CLAB_IMAGE_FLOWPLANE.
func FlowplaneImageFromEnv() string { return getenv("CLAB_IMAGE_FLOWPLANE", ImageFlowplane) }

// Reflector6FromEnv returns the fabric reflector/apiserver loopback, honouring
// CLAB_FABRIC_REFLECTOR6.
func Reflector6FromEnv() string { return getenv("CLAB_FABRIC_REFLECTOR6", FabricReflector6) }
