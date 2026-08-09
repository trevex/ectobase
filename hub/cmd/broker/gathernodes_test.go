// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
)

func TestNodePrefixFromNode(t *testing.T) {
	withAnno := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:        "n1",
		Annotations: map[string]string{netv1.NodeUnderlayPrefixAnnotation: "2001:db8:0:1::/64"},
	}}
	if got := nodePrefixFromNode(withAnno); got != "2001:db8:0:1::/64" {
		t.Fatalf("want prefix from annotation, got %q", got)
	}
	bare := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n2"}}
	if got := nodePrefixFromNode(bare); got != "" {
		t.Fatalf("no annotation must yield empty, got %q", got)
	}
}
