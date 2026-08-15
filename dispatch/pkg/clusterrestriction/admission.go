// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package clusterrestriction implements the thin ClusterRestriction admission
// policy: a per-cluster broker (username ectobase:cluster:<name>) may write ONLY
// its own ClusterPool's status and may never set/change spec.clusterName (so it
// cannot bind or re-bind workloads). Non-broker identities are unrestricted.
package clusterrestriction

import (
	"fmt"
	"strings"

	authuser "k8s.io/apiserver/pkg/authentication/user"
)

// brokerPrefix is the username convention identifying a per-cluster broker.
const brokerPrefix = "ectobase:cluster:"

// Attr is the minimal admission context Review needs (decoupled from the k8s
// admission.Attributes type so the decision is pure + unit-testable).
type Attr struct {
	Resource        string // plural, e.g. "clusterpools", "virtualmachines"
	Name            string
	Subresource     string // "status" for status writes
	SetsClusterName bool   // the write creates/changes spec.clusterName
	Delete          bool   // the operation is a DELETE
}

// clusterOf returns the cluster a broker identity is scoped to, and whether the user is a broker.
func clusterOf(u authuser.Info) (string, bool) {
	if u == nil {
		return "", false
	}
	if strings.HasPrefix(u.GetName(), brokerPrefix) {
		return strings.TrimPrefix(u.GetName(), brokerPrefix), true
	}
	return "", false
}

// Review is the thin ClusterRestriction: a broker identity ectobase:cluster:<name>
// may write ONLY its own ClusterPool's status, and may never set spec.clusterName.
// Non-broker identities are unrestricted.
func Review(u authuser.Info, a Attr) (bool, string) {
	cluster, isBroker := clusterOf(u)
	if !isBroker {
		return true, ""
	}
	if a.Delete {
		// A broker's only legitimate dispatch writes are its own ClusterPool status and
		// per-VM placement status — it never deletes dispatch objects. Deny all deletes so
		// a future RBAC widening (e.g. granting delete for GC) cannot silently become a
		// cross-tenant delete primitive.
		return false, "broker may not delete dispatch objects"
	}
	if a.SetsClusterName {
		return false, "broker may not set spec.clusterName (cannot bind/re-bind workloads)"
	}
	if a.Resource == "clusterpools" {
		if a.Name != cluster {
			return false, fmt.Sprintf("broker %q may only write its own ClusterPool %q, not %q", u.GetName(), cluster, a.Name)
		}
		if a.Subresource != "status" {
			return false, "broker may only write the status of its own ClusterPool"
		}
	}
	return true, ""
}
