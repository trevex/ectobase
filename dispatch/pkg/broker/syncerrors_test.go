// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
)

// twinKind is one of the compiled types the broker mirrors, as the error tests need it.
type twinKind struct {
	name string
	new  func() client.Object
	sync func(*Broker) func(context.Context) error
}

var twinKinds = []twinKind{
	{"CompiledNIC", func() client.Object { return &compiledv1.CompiledNIC{} },
		func(b *Broker) func(context.Context) error { return b.SyncOnce }},
	{"CompiledVM", func() client.Object { return &compiledv1.CompiledVM{} },
		func(b *Broker) func(context.Context) error { return b.SyncCompiledVMs }},
	{"CompiledVolumeAttachment", func() client.Object { return &compiledv1.CompiledVolumeAttachment{} },
		func(b *Broker) func(context.Context) error { return b.SyncCompiledVolumeAttachments }},
	{"CompiledContainer", func() client.Object { return &compiledv1.CompiledContainer{} },
		func(b *Broker) func(context.Context) error { return b.SyncCompiledContainers }},
}

// upstream is the dispatch-side twin of default/<vm> on pool c1, labelled v=<v>.
func (k twinKind) upstream(vm, v string) client.Object {
	o := k.new()
	o.SetNamespace(validate.PoolNamespace("c1"))
	o.SetName("default-" + vm)
	o.SetAnnotations(map[string]string{
		compiledv1.SourceNamespaceAnnotation: "default",
		compiledv1.SourceNameAnnotation:      vm,
	})
	o.SetLabels(map[string]string{"v": v})
	return o
}

// downstream is the pool-side mirror of default/<vm>, labelled v=<v>.
func (k twinKind) downstream(vm, v string) client.Object {
	o := k.new()
	o.SetNamespace("default")
	o.SetName("default-" + vm)
	o.SetLabels(map[string]string{"v": v})
	return o
}

func syncErrorsScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := compiledv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// failingFor makes the downstream refuse to update the twin named update and to create the one
// named create. Everything else goes through.
func failingFor(update, create string) interceptor.Funcs {
	return interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if obj.GetName() == update {
				return errors.New("downstream refuses this update")
			}
			return c.Update(ctx, obj, opts...)
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetName() == create {
				return errors.New("downstream refuses this create")
			}
			return c.Create(ctx, obj, opts...)
		},
	}
}

// One twin the downstream will not take must not stop the sync of the others. Every create,
// update and delete is still attempted, and the failures come back together.
func TestSync_OneFailingTwinDoesNotStopTheOthers(t *testing.T) {
	for _, k := range twinKinds {
		t.Run(k.name, func(t *testing.T) {
			s := syncErrorsScheme(t)
			dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(
				k.upstream("a", "2"), // drifted; its update fails
				k.upstream("b", "2"), // drifted
				k.upstream("c", "2"), // new
				k.upstream("d", "2"), // new; its create fails
				k.upstream("e", "2"), // new
			).Build()
			downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(
				k.downstream("a", "1"),
				k.downstream("b", "1"),
				k.downstream("x", "1"), // no longer wanted
				k.downstream("y", "1"), // no longer wanted
			).WithInterceptorFuncs(failingFor("default-a", "default-d")).Build()
			b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}

			err := k.sync(b)(context.Background())
			if err == nil || !strings.Contains(err.Error(), "default-a") || !strings.Contains(err.Error(), "default-d") {
				t.Fatalf("want both failures returned, got %v", err)
			}
			ctx := context.Background()
			for _, vm := range []string{"b", "c", "e"} {
				got := k.new()
				if err := downstream.Get(ctx, client.ObjectKeyFromObject(k.downstream(vm, "")), got); err != nil {
					t.Fatalf("default-%s not synced: %v", vm, err)
				}
				if got.GetLabels()["v"] != "2" {
					t.Fatalf("default-%s not synced: labels %v", vm, got.GetLabels())
				}
			}
			for _, vm := range []string{"x", "y"} {
				err := downstream.Get(ctx, client.ObjectKeyFromObject(k.downstream(vm, "")), k.new())
				if !apierrors.IsNotFound(err) {
					t.Fatalf("unwanted default-%s survived the sync (get err=%v)", vm, err)
				}
			}
		})
	}
}

// A move's release waits on the source pool stopping the VM. A failure to sync an unrelated VM must
// not keep a retired twin's VM running, or the move waits on an error that is not its own.
func TestSyncCompiledVMs_FailingTwinDoesNotKeepARetiredVMRunning(t *testing.T) {
	vms := twinKinds[1]
	for _, tc := range []struct {
		name         string
		failUpdate   string
		failCreate   string
		upstream     []client.Object
		downstreamOf []string
	}{
		{name: "update fails", failUpdate: "default-a",
			upstream: []client.Object{vms.upstream("a", "2")}, downstreamOf: []string{"a"}},
		{name: "create fails", failCreate: "default-a",
			upstream: []client.Object{vms.upstream("a", "2")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := syncErrorsScheme(t)
			retired := vms.upstream("z", "2").(*compiledv1.CompiledVM)
			now := metav1.Now()
			retired.DeletionTimestamp = &now
			retired.Finalizers = []string{"compiled.ectobase.dev/source-released"}
			dispatch := fake.NewClientBuilder().WithScheme(s).WithObjects(append(tc.upstream, retired)...).Build()
			have := []client.Object{vms.downstream("z", "2")}
			for _, vm := range tc.downstreamOf {
				have = append(have, vms.downstream(vm, "1"))
			}
			downstream := fake.NewClientBuilder().WithScheme(s).WithObjects(have...).
				WithInterceptorFuncs(failingFor(tc.failUpdate, tc.failCreate)).Build()
			b := &Broker{Dispatch: dispatch, Downstream: downstream, ClusterName: "c1"}

			if err := b.SyncCompiledVMs(context.Background()); err == nil {
				t.Fatal("a failed sync of default-a reported success")
			}
			err := downstream.Get(context.Background(), client.ObjectKeyFromObject(vms.downstream("z", "")), &compiledv1.CompiledVM{})
			if !apierrors.IsNotFound(err) {
				t.Fatalf("the retired twin's VM is still mirrored downstream (get err=%v)", err)
			}
		})
	}
}
