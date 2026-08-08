// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
)

func TestUnderlayPrefix(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"2001:db8:0:1::a", "2001:db8:0:1::/64"},
		{"2001:db8:0:1::", "2001:db8:0:1::/64"},
		{"fd00:db8:0:9::1", "fd00:db8:0:9::/64"},
		{"10.0.0.1", ""},           // IPv4 -> not fence-eligible
		{"::ffff:10.0.0.1", ""},    // v4-mapped -> not a real v6 underlay
		{"not-an-ip", ""},          // garbage
		{"", ""},                   // empty
	}
	for _, c := range cases {
		if got := underlayPrefix(c.in); got != c.want {
			t.Errorf("underlayPrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestStampNodePrefix(t *testing.T) {
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(node).Build()
	r := &Reconciler{client: c, nodeID: "node-1", underlay: "2001:db8:0:1::a"}

	// First stamp writes the annotation.
	if err := r.StampNodePrefix(context.Background()); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	got := &corev1.Node{}
	_ = c.Get(context.Background(), client.ObjectKey{Name: "node-1"}, got)
	if got.Annotations[netv1.NodeUnderlayPrefixAnnotation] != "2001:db8:0:1::/64" {
		t.Fatalf("annotation not set: %v", got.Annotations)
	}
	// Idempotent: a second stamp is a no-op (no error).
	if err := r.StampNodePrefix(context.Background()); err != nil {
		t.Fatalf("second stamp: %v", err)
	}

	// A v4 underlay skips silently (no error, no annotation).
	node2 := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-2"}}
	c2 := fake.NewClientBuilder().WithScheme(s).WithObjects(node2).Build()
	r2 := &Reconciler{client: c2, nodeID: "node-2", underlay: "10.0.0.2"}
	if err := r2.StampNodePrefix(context.Background()); err != nil {
		t.Fatalf("v4 stamp should skip, got: %v", err)
	}
	got2 := &corev1.Node{}
	_ = c2.Get(context.Background(), client.ObjectKey{Name: "node-2"}, got2)
	if _, ok := got2.Annotations[netv1.NodeUnderlayPrefixAnnotation]; ok {
		t.Fatalf("v4 underlay must not stamp an annotation")
	}
}
