// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FloatingIPSpec is the desired state of a FloatingIP.
//
// SCAFFOLD ONLY: intentionally empty. Floating/movable virtual IP (§3.7).
type FloatingIPSpec struct {
}

// FloatingIPStatus is the observed state of a FloatingIP.
//
// SCAFFOLD ONLY: intentionally empty.
type FloatingIPStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FloatingIP is a scaffold-only resource. Floating/movable virtual IP (§3.7).
type FloatingIP struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   FloatingIPSpec
	Status FloatingIPStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FloatingIPList is a list of FloatingIP objects.
type FloatingIPList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []FloatingIP
}
