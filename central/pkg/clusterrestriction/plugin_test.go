// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package clusterrestriction

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

// vm builds a typed VirtualMachine with the given spec.clusterName so setsClusterName
// exercises the real ToUnstructured extraction path (not a hand-built map).
func vm(clusterName string) runtime.Object {
	return &netv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm1"},
		Spec:       netv1.VirtualMachineSpec{ClusterName: clusterName},
	}
}

func TestSetsClusterName(t *testing.T) {
	gvk := schema.GroupVersionKind{Group: "net.ectobase.dev", Version: "v1alpha1", Kind: "VirtualMachine"}
	gvr := schema.GroupVersionResource{Group: "net.ectobase.dev", Version: "v1alpha1", Resource: "virtualmachines"}
	mk := func(newObj, oldObj runtime.Object, op admission.Operation) admission.Attributes {
		return admission.NewAttributesRecord(newObj, oldObj, gvk, "default", "vm1", gvr, "", op, nil, false, nil)
	}

	cases := []struct {
		name string
		attr admission.Attributes
		want bool
	}{
		{"create with clusterName", mk(vm("c1"), nil, admission.Create), true},
		{"create without clusterName", mk(vm(""), nil, admission.Create), false},
		{"update changes clusterName", mk(vm("c2"), vm("c1"), admission.Update), true},
		{"update unchanged clusterName", mk(vm("c1"), vm("c1"), admission.Update), false},
		{"update clears clusterName", mk(vm(""), vm("c1"), admission.Update), true},
		{"delete is never a set", mk(vm("c1"), vm("c1"), admission.Delete), false},
	}
	for _, tc := range cases {
		if got := setsClusterName(tc.attr); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}
