// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RouteBusIdentitySpec is a pool's request for a route-bus intermediate CA. The pool (its
// broker) generates the intermediate keypair LOCALLY and submits only the CSR — the private
// key is never transmitted. The dispatch signer returns a name-constrained intermediate that
// can mint per-node agent leaves scoped to this pool.
type RouteBusIdentitySpec struct {
	// PoolName is the ClusterPool this identity belongs to. The signed intermediate is
	// name-constrained to this pool so it can only mint node identities within it.
	PoolName string `json:"poolName,omitempty" protobuf:"bytes,1,opt,name=poolName"`
	// Request is the PEM-encoded PKCS#10 certificate-signing request for the pool's
	// intermediate CA (the pool keeps the matching private key).
	Request []byte `json:"request,omitempty" protobuf:"bytes,2,opt,name=request"`
	// PermittedUnderlayCIDRs are the pool's underlay IPv6 ranges. The signer name-constrains
	// the intermediate to these so it can only mint node leaves whose IP SAN falls inside the
	// pool — the reflector binds route nexthops to that SAN.
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
// by the dispatch aggregated apiserver. The broker creates it; the dispatch signer fills status.
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
