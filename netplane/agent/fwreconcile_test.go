package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func fwScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// The agent pushes the COMPLETE desired rule set per interface, in CompiledNIC order (ingress rules
// fw-in-0..N first, then egress fw-eg-0..N), via a single ReplaceInterfaceFirewall call.
func TestReconcileFirewall_PushesFullOrderedSet(t *testing.T) {
	cnic := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "green-0-nic0", Namespace: "default"},
		Spec: compiledv1.CompiledNICSpec{
			NodeName:   "nodeA",
			OverlayIPs: []string{"10.0.20.11"},
			Firewall: compiledv1.CompiledFirewall{
				Ingress: []compiledv1.CompiledFwRule{
					{CIDR: "0.0.0.0/0", Action: "Deny"},
					{CIDR: "10.0.10.0/24", Proto: "ICMP", Action: "Allow"},
				},
				Egress: []compiledv1.CompiledFwRule{{CIDR: "0.0.0.0/0", Action: "Allow"}},
			},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(fwScheme(t)).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "podUID/eth0", Vni: 120, OverlayIPs: []string{"10.0.20.11"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := dp.fwReplace["podUID/eth0"]
	if len(got) != 3 {
		t.Fatalf("want 3 rules in one replace, got %d: %+v", len(got), got)
	}
	if got[0].ID != "fw-in-0" || got[1].ID != "fw-in-1" || got[2].ID != "fw-eg-0" {
		t.Fatalf("wrong order/ids: %+v", got)
	}
	if got[0].Rule.Allow /* deny */ || !got[1].Rule.Allow /* allow */ || got[1].Rule.SrcCIDR != "10.0.10.0/24" {
		t.Fatalf("wrong rule contents: %+v", got)
	}
}

// The decisive regression: a fresh Reconciler (empty in-memory state = post-restart) sharing the
// same client+dp must converge a deny→allow swap to EXACTLY [allow] — the old in-memory-diff path
// left the stale deny in place after a restart (scenario-vpc-peering Assertion 2).
func TestReconcileFirewall_RestartSafeConverges(t *testing.T) {
	cnic := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "green-0-nic0", Namespace: "default"},
		Spec: compiledv1.CompiledNICSpec{
			NodeName:   "nodeA",
			OverlayIPs: []string{"10.0.20.11"},
			Firewall:   compiledv1.CompiledFirewall{Ingress: []compiledv1.CompiledFwRule{{CIDR: "0.0.0.0/0", Action: "Deny"}}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(fwScheme(t)).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "podUID/eth0", Vni: 120, OverlayIPs: []string{"10.0.20.11"}, Underlay: "fd00::a"}}

	// Incarnation 1: program the deny-all.
	r1 := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}
	if err := r1.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Swap deny → allow on the same object.
	cnic.Spec.Firewall.Ingress = []compiledv1.CompiledFwRule{{CIDR: "10.0.10.0/24", Proto: "ICMP", Action: "Allow"}}
	if err := cl.Update(context.Background(), cnic); err != nil {
		t.Fatal(err)
	}

	// Incarnation 2: a NEW Reconciler (no shared in-memory state) must converge to exactly [allow].
	r2 := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}
	if err := r2.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := dp.fwReplace["podUID/eth0"]
	if len(got) != 1 || !got[0].Rule.Allow || got[0].Rule.SrcCIDR != "10.0.10.0/24" {
		t.Fatalf("post-restart did not converge to [allow]: %+v", got)
	}
}

// Replace is idempotent: repeated reconciles never error (no ALREADY_EXISTS) and leave the final set.
func TestReconcileFirewall_ConvergesOnRepeat(t *testing.T) {
	cnic := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "green-0-nic0", Namespace: "default"},
		Spec: compiledv1.CompiledNICSpec{
			NodeName:   "nodeA",
			OverlayIPs: []string{"10.0.20.11"},
			Firewall: compiledv1.CompiledFirewall{
				Ingress: []compiledv1.CompiledFwRule{{CIDR: "0.0.0.0/0", Proto: "TCP", Port: 443, Action: "Allow"}},
				Egress:  []compiledv1.CompiledFwRule{{CIDR: "0.0.0.0/0", Action: "Allow"}},
			},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(fwScheme(t)).WithObjects(cnic).Build()
	dp := newRecordingDP()
	dp.ifaces = []LocalInterface{{InterfaceID: "podUID/eth0", Vni: 120, OverlayIPs: []string{"10.0.20.11"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	for i := 0; i < 3; i++ {
		if err := r.ReconcileFirewall(context.Background()); err != nil {
			t.Fatalf("reconcile #%d errored: %v", i+1, err)
		}
	}
	if got := dp.fwReplace["podUID/eth0"]; len(got) != 2 {
		t.Fatalf("want final set of 2 rules, got %d: %+v", len(got), got)
	}
}
