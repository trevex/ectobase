// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RouteBusIdentitySpec is a request for a route-bus intermediate CA. The requester generates the
// intermediate keypair LOCALLY and submits only the CSR — the private key is never transmitted.
// The dispatch signer returns a name-constrained intermediate that can mint agent leaves scoped to
// it.
//
// Usually the requester is a ClusterPool (its broker), one identity per pool. The WAN edge FLEET is
// the other kind: an edge is a router rather than a Kubernetes node, so it has no broker and no
// cert-manager — it is modelled as an ordinary identity named `edge`, permitted the edge loopback
// aggregate, and each edge agent mints its own leaf from that intermediate in process.
type RouteBusIdentitySpec struct {
	// PoolName is the identity this intermediate belongs to — a ClusterPool name, or `edge` for
	// the WAN edge fleet. It must equal the object's name. The signed intermediate is
	// name-constrained to it so it can only mint leaves within it.
	PoolName string `json:"poolName,omitempty" protobuf:"bytes,1,opt,name=poolName"`
	// Request is the PEM-encoded PKCS#10 certificate-signing request for the pool's
	// intermediate CA (the pool keeps the matching private key).
	Request []byte `json:"request,omitempty" protobuf:"bytes,2,opt,name=request"`
	// PermittedUnderlayCIDRs are the underlay ranges of a FLEET identity: one the dispatch-controller
	// is told is not a pool (--routebus-fleet-identities, the dispatch chart's pki.fleetIdentities),
	// such as the edge fleet (its loopback aggregate). The signer name-constrains that identity's
	// intermediate to these, so it can only mint leaves whose IP SAN falls inside them; the
	// reflector then binds route nexthops to that SAN. This constraint, not the minting code, is
	// what bounds a holder of the intermediate, which matters most for the edge, where an agent
	// signs its own leaf locally. Empty there means the signer denies the request.
	//
	// For a pool it is IGNORED: a pool's broker writes this object, so the signer constrains the
	// pool's intermediate to its ClusterPool's spec.underlayPrefix instead, and only names any
	// requested range outside that prefix in the Signed condition.
	// +optional
	PermittedUnderlayCIDRs []string `json:"permittedUnderlayCIDRs,omitempty" protobuf:"bytes,3,rep,name=permittedUnderlayCIDRs"`
}

// RouteBusIdentityStatus carries the signer's response: the signed intermediate and the
// root CA bundle the reflector trusts.
type RouteBusIdentityStatus struct {
	// Certificate is the PEM-encoded signed intermediate CA certificate (the CSR response).
	// +optional
	Certificate []byte `json:"certificate,omitempty" protobuf:"bytes,1,opt,name=certificate"`
	// CABundle is the PEM-encoded root CA the reflector trusts, so the pool can present the
	// full chain (leaf -> intermediate -> root).
	// +optional
	CABundle []byte `json:"caBundle,omitempty" protobuf:"bytes,2,opt,name=caBundle"`
	// Conditions represent the latest observations (e.g. Signed / Denied).
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,3,rep,name=conditions"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RouteBusIdentity is a pool's route-bus intermediate-CA request + signed response, served
// by the dispatch aggregated apiserver. The operator pre-creates it when enrolling the pool, the
// broker files its CSR into it, and the dispatch signer fills status.
type RouteBusIdentity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   RouteBusIdentitySpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status RouteBusIdentityStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RouteBusIdentityList is a list of RouteBusIdentity objects.
type RouteBusIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []RouteBusIdentity `json:"items" protobuf:"bytes,2,rep,name=items"`
}
