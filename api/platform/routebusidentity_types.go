// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RouteBusIdentitySpec is a pool's request for a route-bus intermediate CA. The pool
// (its broker) generates the intermediate keypair LOCALLY and submits only the CSR — the
// private key is never transmitted. The dispatch signer returns a name-constrained
// intermediate that can mint per-node agent leaves scoped to this pool.
type RouteBusIdentitySpec struct {
	// PoolName is the ClusterPool this identity belongs to. The signed intermediate is
	// name-constrained to this pool so it can only mint node identities within it — the
	// cross-pool security boundary.
	PoolName string
	// Request is the PEM-encoded PKCS#10 certificate-signing request for the pool's
	// intermediate CA (the pool keeps the matching private key).
	Request []byte
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

// RouteBusIdentity is a pool's route-bus intermediate-CA request + signed response,
// served by the dispatch aggregated apiserver. The broker creates it, the dispatch signer
// fills its status.
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
