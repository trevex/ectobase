// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"strings"

	dataplanev1 "github.com/trevex/ectobase/cni/gen/dataplanev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	v1alpha1 "github.com/trevex/ectobase/api/net/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// podArgs are the k8s pod coordinates the runtime forwards via CNI_ARGS.
type podArgs struct {
	Namespace string
	Name      string
	UID       string
}

// parseCNIArgs parses the ";"-separated "K=V" CNI_ARGS string and extracts the
// K8S_POD_* pod coordinates that Multus forwards to the default delegate.
func parseCNIArgs(cniArgs string) podArgs {
	var a podArgs
	for _, kv := range strings.Split(cniArgs, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "K8S_POD_NAMESPACE":
			a.Namespace = v
		case "K8S_POD_NAME":
			a.Name = v
		case "K8S_POD_UID":
			a.UID = v
		}
	}
	return a
}

// newK8sClient builds a controller-runtime client from an on-node kubeconfig
// (the SA-token kubeconfig dropped by the CNI-installer DaemonSet). The scheme
// carries our net.ectobase.dev/v1alpha1 CRDs so resolveCompiledNIC() can GET the
// CompiledNIC.
func newK8sClient(kubeconfigPath string) (client.Client, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig %q: %w", kubeconfigPath, err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register core scheme: %w", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register scheme: %w", err)
	}

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	return c, nil
}

// resolvePodInterfaceRef reads the pod <ns>/<name> via the on-node SA-token
// kubeconfig and returns the NetworkInterface CR "<ns>/<name>" named by the
// pod's net.ectobase.dev/network-interface annotation.
func resolvePodInterfaceRef(ctx context.Context, kubeconfigPath, podNS, podName string) (string, string, error) {
	c, err := newK8sClient(kubeconfigPath)
	if err != nil {
		return "", "", err
	}

	var pod corev1.Pod
	if err := c.Get(ctx, types.NamespacedName{Namespace: podNS, Name: podName}, &pod); err != nil {
		return "", "", fmt.Errorf("get pod %s/%s: %w", podNS, podName, err)
	}

	ref := pod.Annotations[networkInterfaceAnnotation]
	if ref == "" {
		return "", "", fmt.Errorf("pod %s/%s missing annotation %q", podNS, podName, networkInterfaceAnnotation)
	}

	ns, name, ok := strings.Cut(ref, "/")
	if !ok || ns == "" || name == "" {
		return "", "", fmt.Errorf("annotation %q value %q is not <ns>/<name>", networkInterfaceAnnotation, ref)
	}
	return ns, name, nil
}

// dialDataplane dials the node-local flowplane DataplaneNode gRPC. The DaemonSet
// runs with hostNetwork, so from the host netns the CNI reaches it over TCP at
// dataplaneAddr (default 127.0.0.1:1337).
func dialDataplane(addr string) (dataplanev1.DataplaneNodeClient, func() error, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("dial dataplane %q: %w", addr, err)
	}
	return dataplanev1.NewDataplaneNodeClient(conn), conn.Close, nil
}

// attach calls DataplaneNode.AttachInterface and returns the response.
func attach(ctx context.Context, cl dataplanev1.DataplaneNodeClient, req *dataplanev1.AttachInterfaceRequest) (*dataplanev1.AttachInterfaceResponse, error) {
	resp, err := cl.AttachInterface(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AttachInterface: %w", err)
	}
	return resp, nil
}

// detach calls DataplaneNode.DetachInterface best-effort.
func detach(ctx context.Context, cl dataplanev1.DataplaneNodeClient, interfaceID string) error {
	if _, err := cl.DetachInterface(ctx, &dataplanev1.DetachInterfaceRequest{InterfaceId: interfaceID}); err != nil {
		return fmt.Errorf("DetachInterface: %w", err)
	}
	return nil
}
