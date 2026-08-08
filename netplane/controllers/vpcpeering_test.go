// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// peering builds a one-directional VPCPeering (localVPC → peerVPC) with the given exposed prefixes.
func peering(name, localVPC, peerVPC string, exposed ...string) *netv1.VPCPeering {
	return &netv1.VPCPeering{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: netv1.VPCPeeringSpec{
			VPCRef:          netv1.LocalObjectReference{Name: localVPC},
			PeerVPCRef:      netv1.VPCReference{Namespace: "default", Name: peerVPC},
			ExposedPrefixes: exposed,
		},
	}
}

func reconcilePeering(t *testing.T, name string, objs ...*netv1.VPCPeering) netv1.VPCPeering {
	t.Helper()
	s := lbScheme(t)
	builder := fake.NewClientBuilder().WithScheme(s)
	for _, o := range objs {
		builder = builder.WithObjects(o).WithStatusSubresource(o)
	}
	cl := builder.Build()
	r := &VPCPeeringReconciler{Client: cl}
	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: name}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var got netv1.VPCPeering
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestVPCPeering_PendingUntilReciprocal(t *testing.T) {
	got := reconcilePeering(t, "a-to-b", peering("a-to-b", "a", "b", "10.0.0.0/24"))
	if got.Status.State != netv1.VPCPeeringPending {
		t.Fatalf("State = %q, want %q", got.Status.State, netv1.VPCPeeringPending)
	}
}

func TestVPCPeering_ReadyWhenReciprocalExists(t *testing.T) {
	got := reconcilePeering(t, "a-to-b",
		peering("a-to-b", "a", "b", "10.0.0.0/24"),
		peering("b-to-a", "b", "a", "10.1.0.0/24"),
	)
	if got.Status.State != netv1.VPCPeeringReady {
		t.Fatalf("State = %q, want %q", got.Status.State, netv1.VPCPeeringReady)
	}
}

func TestVPCPeering_InvalidPrefix(t *testing.T) {
	got := reconcilePeering(t, "a-to-b", peering("a-to-b", "a", "b", "not-a-cidr"))
	if got.Status.State != netv1.VPCPeeringInvalid {
		t.Fatalf("State = %q, want %q", got.Status.State, netv1.VPCPeeringInvalid)
	}
}
