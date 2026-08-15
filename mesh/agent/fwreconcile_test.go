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
			VNI:        120,
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
			VNI:        120,
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
			VNI:        120,
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

// TestReconcileFirewall_SkipsNotLocallyAttached proves that a CompiledNIC whose (VNI, overlayIP)
// is NOT in the dataplane's ListInterfaces produces no firewall programming — regardless of any
// node name field that may have been set historically.
func TestReconcileFirewall_SkipsNotLocallyAttached(t *testing.T) {
	cnic := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "remote-nic", Namespace: "default"},
		Spec: compiledv1.CompiledNICSpec{
			VNI:        120,
			OverlayIPs: []string{"10.0.20.99"},
			Firewall:   compiledv1.CompiledFirewall{Ingress: []compiledv1.CompiledFwRule{{CIDR: "0.0.0.0/0", Action: "Allow"}}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(fwScheme(t)).WithObjects(cnic).Build()
	dp := newRecordingDP()
	// dp.ifaces is empty: no locally-attached interfaces → NIC must be skipped.
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.fwReplace) != 0 {
		t.Fatalf("no interface attached locally: expected no firewall programming, got %+v", dp.fwReplace)
	}
}

// TestReconcileFirewall_OverlappingVPCIPs proves that (VNI, overlayIP) keying — not IP alone —
// determines locality. Two CompiledNICs share the same overlay IP (10.0.0.1) but live in different
// VPCs (VNI 100 vs VNI 200). Only VNI 100 is attached locally; only its policy must be programmed.
func TestReconcileFirewall_OverlappingVPCIPs(t *testing.T) {
	vni100 := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "vpc-a-nic", Namespace: "default"},
		Spec: compiledv1.CompiledNICSpec{
			VNI:        100,
			OverlayIPs: []string{"10.0.0.1"},
			Firewall:   compiledv1.CompiledFirewall{Ingress: []compiledv1.CompiledFwRule{{CIDR: "10.0.0.0/8", Action: "Allow"}}},
		},
	}
	vni200 := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "vpc-b-nic", Namespace: "default"},
		Spec: compiledv1.CompiledNICSpec{
			VNI:        200,
			OverlayIPs: []string{"10.0.0.1"}, // same IP, different VPC
			Firewall:   compiledv1.CompiledFirewall{Ingress: []compiledv1.CompiledFwRule{{CIDR: "192.168.0.0/16", Action: "Deny"}}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(fwScheme(t)).WithObjects(vni100, vni200).Build()
	dp := newRecordingDP()
	// Only VNI 100 / 10.0.0.1 is locally attached; VNI 200 is on a different node.
	dp.ifaces = []LocalInterface{{InterfaceID: "ifA", Vni: 100, OverlayIPs: []string{"10.0.0.1"}, Underlay: "fd00::a"}}
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp}

	if err := r.ReconcileFirewall(context.Background()); err != nil {
		t.Fatal(err)
	}
	// VNI 100 NIC's rules must be programmed.
	if got, ok := dp.fwReplace["ifA"]; !ok || len(got) != 1 {
		t.Fatalf("VNI-100 NIC firewall not programmed correctly; fwReplace=%+v", dp.fwReplace)
	}
	if dp.fwReplace["ifA"][0].Rule.SrcCIDR != "10.0.0.0/8" {
		t.Fatalf("wrong rule programmed for VNI-100: %+v", dp.fwReplace["ifA"])
	}
	// VNI 200 NIC must NOT be programmed (it's not locally attached).
	if len(dp.fwReplace) != 1 {
		t.Fatalf("VNI-200 NIC (same IP, different VPC) was incorrectly programmed; fwReplace=%+v", dp.fwReplace)
	}
}
