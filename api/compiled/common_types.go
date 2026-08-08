// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compiled

// LocalObjectReference references an object by name within the same namespace.
type LocalObjectReference struct {
	// Name is the name of the referenced object.
	Name string
}

// PortStatus describes the dataplane port allocated for a NetworkInterface.
type PortStatus struct {
	// Type is the port type (e.g. tap or vf).
	Type string
	// Name is the host-side interface name (e.g. dtapvf_0) for tap ports.
	Name string
	// PCIAddress is the PCI address for vf ports.
	PCIAddress string
}
