// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RouteBusIdentitySpec is a request for a route-bus intermediate CA. The requester generates the
// intermediate keypair LOCALLY and submits only the CSR — the private key is never transmitted.
// The dispatch signer returns a name-constrained intermediate that can mint agent leaves scoped
// to it.
//
// Usually the requester is a ClusterPool (its broker), one identity per pool. The WAN edge FLEET
// is the other kind: an edge is a router rather than a Kubernetes node, so it has no broker and no
// cert-manager — it is modelled as an ordinary identity named `edge`, permitted the edge loopback
// aggregate, and each edge agent mints its own leaf from that intermediate in process.
type RouteBusIdentitySpec struct {
	// PoolName is the identity this intermediate belongs to — a ClusterPool name, or `edge` for
	// the WAN edge fleet. The signed intermediate is name-constrained to it so it can only mint
	// leaves within it: the cross-pool security boundary.
	PoolName string
	// Request is the PEM-encoded PKCS#10 certificate-signing request for the intermediate CA
	// (the requester keeps the matching private key).
	Request []byte
	// PermittedUnderlayCIDRs are this identity's underlay IPv6 ranges — a pool's covering /48, or
	// the edge loopback aggregate for the edge fleet. The signer name-constrains the intermediate
	// to these so it can only mint leaves whose IP SAN (a node's /128 underlay) falls inside them,
	// closing the IP-SAN bypass of the DNS constraint; the reflector then binds route nexthops to
	// that SAN. This constraint, not the minting code, is what bounds a holder of the intermediate
	// — which matters most for the edge, where an agent signs its own leaf locally.
	PermittedUnderlayCIDRs []string
}

// RouteBusIdentityStatus carries the signer's response: the signed intermediate and the
// root CA bundle the reflector trusts.
type RouteBusIdentityStatus struct {
	// Certificate is the PEM-encoded signed intermediate CA certificate (the CSR response).
	Certificate []byte
	// CABundle is the PEM-encoded root CA the reflector trusts, so the pool can present the
	// full chain (leaf -> intermediate -> root).
	CABundle []byte
	// Conditions represent the latest observations (e.g. Signed / Denied).
	Conditions []metav1.Condition
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RouteBusIdentity is a route-bus intermediate-CA request + signed response, served by the
// dispatch aggregated apiserver. A pool's broker creates its own; the WAN edge fleet's is created
// by whatever provisions the edges. The dispatch signer fills the status either way.
type RouteBusIdentity struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   RouteBusIdentitySpec
	Status RouteBusIdentityStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RouteBusIdentityList is a list of RouteBusIdentity objects.
type RouteBusIdentityList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []RouteBusIdentity
}
