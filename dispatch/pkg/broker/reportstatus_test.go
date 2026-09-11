// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computeinstall "github.com/trevex/ectobase/api/compute/install"
	netinstall "github.com/trevex/ectobase/api/net/install"
	platforminstall "github.com/trevex/ectobase/api/platform/install"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
)

// TestReportStatus_WritesPrefixesPlacementAndDrain proves ReportStatus stamps the
// pool's NodePrefixes + per-/64 NodeDrain and each central VM's Placement, using the
// fenced-prefix + node-busy join to decide drain state.
func TestReportStatus_WritesPrefixesPlacementAndDrain(t *testing.T) {
	s := runtime.NewScheme()
	if err := platforminstall.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := netinstall.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := computeinstall.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}

	const (
		prefix1 = "2001:db8:0:1::/64" // node-1, hosts vm1 -> stays busy (fenced)
		prefix2 = "2001:db8:0:2::/64" // node-2, empty -> drains (fenced)
	)

	// Pool with both /64s fenced; only node-1's is still busy (vm1 runs there).
	pool := &platformv1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{Name: "c1"},
		Status:     platformv1.ClusterPoolStatus{FencedPrefixes: []string{prefix1, prefix2}},
	}
	// Placement is reported onto this pool's own CompiledVM (in its pool namespace), never onto
	// the tenant-namespace VirtualMachine — that write is not scopeable by per-pool RBAC, so a
	// mesh controller performs the cross-namespace hop instead.
	cvm := &compiledv1.CompiledVM{
		ObjectMeta: metav1.ObjectMeta{Namespace: validate.PoolNamespace("c1"), Name: "default-vm1"},
	}
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(pool, cvm).
		WithStatusSubresource(pool, cvm).
		Build()

	b := &Broker{Dispatch: c, ClusterName: "c1"}
	nodes := []NodeFact{
		{Name: "node-1", Prefix: prefix1},
		{Name: "node-2", Prefix: prefix2},
	}
	vmNode := map[string]string{"default/default-vm1": "node-1"}

	if err := b.ReportStatus(context.Background(), nodes, vmNode); err != nil {
		t.Fatalf("ReportStatus: %v", err)
	}

	// Pool: NodePrefixes == both node /64s (order preserved).
	gotPool := &platformv1.ClusterPool{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "c1"}, gotPool); err != nil {
		t.Fatal(err)
	}
	if len(gotPool.Status.NodePrefixes) != 2 ||
		gotPool.Status.NodePrefixes[0] != prefix1 || gotPool.Status.NodePrefixes[1] != prefix2 {
		t.Fatalf("NodePrefixes: %v", gotPool.Status.NodePrefixes)
	}

	// Drain: prefix1 busy (vm1 still there) -> NOT drained; prefix2 empty -> drained.
	drain := map[string]bool{}
	for _, d := range gotPool.Status.NodeDrain {
		drain[d.Prefix] = d.Drained
	}
	if drain[prefix1] {
		t.Fatalf("prefix1 hosts vm1, must NOT be drained: %v", gotPool.Status.NodeDrain)
	}
	if !drain[prefix2] {
		t.Fatalf("prefix2 is empty, must be drained: %v", gotPool.Status.NodeDrain)
	}

	// CompiledVM: Placement stamped with cluster + node + resolved /64, in the POOL namespace.
	gotCVM := &compiledv1.CompiledVM{}
	if err := c.Get(context.Background(),
		client.ObjectKey{Namespace: validate.PoolNamespace("c1"), Name: "default-vm1"}, gotCVM); err != nil {
		t.Fatal(err)
	}
	if gotCVM.Status.Placement == nil {
		t.Fatalf("vm1 placement not stamped onto its CompiledVM")
	}
	if gotCVM.Status.Placement.ClusterName != "c1" ||
		gotCVM.Status.Placement.NodeName != "node-1" ||
		gotCVM.Status.Placement.NodePrefix != prefix1 {
		t.Fatalf("vm1 placement: %+v", gotCVM.Status.Placement)
	}
}
