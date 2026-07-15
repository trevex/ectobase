package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReconcileFirewall_PushesRules(t *testing.T) {
	c := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: "nodeA",
			NICRef:   netv1.LocalObjectReference{Name: "web-0-nic0"},
			Firewall: netv1.CompiledFirewall{
				Ingress: []netv1.CompiledFwRule{{CIDR: "10.0.0.0/24", Proto: "TCP", Port: 443, Action: "Allow"}},
				Egress:  []netv1.CompiledFwRule{{CIDR: "0.0.0.0/0", Action: "Allow"}},
			},
		},
	}
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(c).Build()
	dp := newFakeDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.fwAdds) != 2 {
		t.Fatalf("want 2 AddFwRule, got %d: %+v", len(dp.fwAdds), dp.fwAdds)
	}
	// find the ingress rule (Egress == false)
	var ing *fwCall
	for i := range dp.fwAdds {
		if !dp.fwAdds[i].rule.Egress {
			ing = &dp.fwAdds[i]
		}
	}
	if ing == nil {
		t.Fatal("no ingress rule found")
	}
	if ing.iface != "web-0-nic0" {
		t.Fatalf("ingress rule iface = %q, want web-0-nic0", ing.iface)
	}
	if ing.rule.DstCIDR != "10.0.0.0/24" {
		t.Fatalf("ingress rule DstCIDR = %q, want 10.0.0.0/24", ing.rule.DstCIDR)
	}
	if ing.rule.Proto != 6 {
		t.Fatalf("ingress rule Proto = %d, want 6 (TCP)", ing.rule.Proto)
	}
	if ing.rule.DstPortMin != 443 || ing.rule.DstPortMax != 443 {
		t.Fatalf("ingress rule ports = [%d,%d], want [443,443]", ing.rule.DstPortMin, ing.rule.DstPortMax)
	}
	if !ing.rule.Allow {
		t.Fatal("ingress rule Allow = false, want true")
	}
}

func TestReconcileFirewall_DeletesStaleRules(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	// First reconcile: CompiledNIC with 2 ingress rules.
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-nic0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: "nodeA",
			NICRef:   netv1.LocalObjectReference{Name: "web-0-nic0"},
			Firewall: netv1.CompiledFirewall{
				Ingress: []netv1.CompiledFwRule{
					{CIDR: "10.0.0.0/24", Proto: "TCP", Port: 443, Action: "Allow"},
					{CIDR: "10.1.0.0/24", Proto: "TCP", Port: 80, Action: "Allow"},
				},
			},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cnic).Build()
	dp := newFakeDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.fwAdds) != 2 {
		t.Fatalf("first reconcile: want 2 AddFwRule, got %d", len(dp.fwAdds))
	}

	// Update the object to have only 1 ingress rule (remove the second).
	cnic.Spec.Firewall.Ingress = []netv1.CompiledFwRule{
		{CIDR: "10.0.0.0/24", Proto: "TCP", Port: 443, Action: "Allow"},
	}
	if err := cl.Update(context.Background(), cnic); err != nil {
		t.Fatal(err)
	}

	// Reset fwAdds to check only second reconcile additions.
	dp.fwAdds = nil

	// Second reconcile: should delete fw-in-1 and re-add fw-in-0.
	if err := r.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.fwDels) != 1 {
		t.Fatalf("want 1 DelFwRule, got %d: %+v", len(dp.fwDels), dp.fwDels)
	}
	if dp.fwDels[0].ruleID != "fw-in-1" {
		t.Fatalf("deleted ruleID = %q, want fw-in-1", dp.fwDels[0].ruleID)
	}
}
