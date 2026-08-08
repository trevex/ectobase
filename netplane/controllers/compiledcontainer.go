// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"reflect"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// CompileContainer lowers a Container into a CompiledContainer: the pod template (image, command,
// args, env, resources, restart policy), the cluster/node binding, and one resolved overlay interface
// (MAC + networkName + networkInterfaceRef) per owned NetworkInterface. networkName is the multus NAD
// name for the flowplane overlay binding (the same source CompileVM uses).
func CompileContainer(ctr *netv1.Container, nics []netv1.NetworkInterface, networkName string) netv1.CompiledContainer {
	macByNIC := map[string]string{}
	for i := range nics {
		macByNIC[nics[i].Name] = nics[i].Spec.MAC
	}
	var ifaces []netv1.CompiledContainerInterface
	for _, ref := range ctr.Spec.InterfaceRefs {
		ifaces = append(ifaces, netv1.CompiledContainerInterface{
			NetworkName:         networkName,
			MAC:                 macByNIC[ref.Name],
			NetworkInterfaceRef: ctr.Namespace + "/" + ref.Name,
		})
	}
	compiled := netv1.CompiledContainer{
		TypeMeta:   metav1.TypeMeta{APIVersion: "net.ectobase.dev/v1alpha1", Kind: "CompiledContainer"},
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%s", ctr.Namespace, ctr.Name), Namespace: ctr.Namespace},
		Spec: netv1.CompiledContainerSpec{
			ClusterName:   ctr.Spec.ClusterName,
			NodeName:      ctr.Spec.NodeName,
			Image:         ctr.Spec.Image,
			Command:       append([]string(nil), ctr.Spec.Command...),
			Args:          append([]string(nil), ctr.Spec.Args...),
			Env:           ctr.Spec.Env,
			Resources:     *ctr.Spec.Resources.DeepCopy(),
			RestartPolicy: ctr.Spec.RestartPolicy,
			Interfaces:    ifaces,
		},
	}
	// A Container is always the placement authority for its NICs, so stamp the workload label
	// unconditionally (mirrors the CompiledNIC/CompiledVM workload=<name> convention).
	compiled.Labels = map[string]string{"workload": ctr.Name}
	return compiled
}

// CompiledContainerReconciler watches Containers and upserts their CompiledContainer.
type CompiledContainerReconciler struct {
	Client      client.Client
	NetworkName string // the multus NAD name for the flowplane overlay binding
}

func (r *CompiledContainerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ctr netv1.Container
	if err := r.Client.Get(ctx, req.NamespacedName, &ctr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	var nicList netv1.NetworkInterfaceList
	if err := r.Client.List(ctx, &nicList, client.InNamespace(ctr.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list nics: %w", err)
	}
	compiled := CompileContainer(&ctr, nicList.Items, r.NetworkName)
	key := types.NamespacedName{Namespace: compiled.Namespace, Name: compiled.Name}
	var existing netv1.CompiledContainer
	err := r.Client.Get(ctx, key, &existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := controllerutil.SetControllerReference(&ctr, &compiled, r.Client.Scheme()); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Client.Create(ctx, &compiled); err != nil {
			return ctrl.Result{}, fmt.Errorf("create compiledcontainer: %w", err)
		}
	case err != nil:
		return ctrl.Result{}, err
	default:
		if reflect.DeepEqual(existing.Spec, compiled.Spec) && existing.Labels["workload"] == compiled.Labels["workload"] {
			return ctrl.Result{}, nil
		}
		existing.Spec = compiled.Spec
		if existing.Labels == nil {
			existing.Labels = map[string]string{}
		}
		existing.Labels["workload"] = compiled.Labels["workload"]
		if err := r.Client.Update(ctx, &existing); err != nil {
			return ctrl.Result{}, fmt.Errorf("update compiledcontainer: %w", err)
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager watches Containers (Owns their CompiledContainers) and re-enqueues a Container when
// one of its NetworkInterfaces changes (MAC — the source of each interface's L2 address).
func (r *CompiledContainerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("compiledcontainer").
		For(&netv1.Container{}).
		Owns(&netv1.CompiledContainer{}).
		// MAC lives in NetworkInterface.spec, so a MAC change bumps generation;
		// GenerationChangedPredicate avoids recompiling every Container on unrelated NIC status writes
		// (e.g. port allocation).
		Watches(&netv1.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(r.containersForNIC),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// containersForNIC maps a NetworkInterface event to reconcile requests for every Container in the same
// namespace that references it.
func (r *CompiledContainerReconciler) containersForNIC(ctx context.Context, obj client.Object) []reconcile.Request {
	nic, ok := obj.(*netv1.NetworkInterface)
	if !ok {
		return nil
	}
	var ctrs netv1.ContainerList
	if err := r.Client.List(ctx, &ctrs, client.InNamespace(nic.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range ctrs.Items {
		for _, ref := range ctrs.Items[i].Spec.InterfaceRefs {
			if ref.Name == nic.Name {
				reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ctrs.Items[i].Namespace, Name: ctrs.Items[i].Name}})
				break
			}
		}
	}
	return reqs
}
