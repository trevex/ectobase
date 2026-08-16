// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var certGVK = schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"}

// ProvisionNodeCert ensures a per-node cert-manager Certificate exists (CN = node, IP SAN =
// underlay /128, issued by the pool Issuer) and returns the signed chain (leaf + intermediate)
// and key once cert-manager mints the Secret. The node's private key stays in the pool; the
// reflector trusts the root and its nexthop==IP-SAN check binds this node to its own underlay.
func ProvisionNodeCert(ctx context.Context, kubeconfig, ns, node, underlay, issuer string) (chainPEM, keyPEM []byte, err error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("build rest config: %w", err)
	}
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		return nil, nil, fmt.Errorf("build client: %w", err)
	}

	name := "agent-" + node
	secretName := name + "-routebus-tls"

	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(certGVK)
	cert.SetNamespace(ns)
	cert.SetName(name)
	_ = unstructured.SetNestedField(cert.Object, secretName, "spec", "secretName")
	_ = unstructured.SetNestedField(cert.Object, "2160h", "spec", "duration") // 90d
	_ = unstructured.SetNestedField(cert.Object, node, "spec", "commonName")
	_ = unstructured.SetNestedStringSlice(cert.Object, []string{underlay}, "spec", "ipAddresses")
	_ = unstructured.SetNestedMap(cert.Object, map[string]interface{}{"algorithm": "ECDSA", "size": int64(256)}, "spec", "privateKey")
	_ = unstructured.SetNestedStringSlice(cert.Object, []string{"client auth"}, "spec", "usages")
	_ = unstructured.SetNestedMap(cert.Object, map[string]interface{}{"name": issuer, "kind": "Issuer"}, "spec", "issuerRef")

	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(certGVK)
	getErr := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, existing)
	if apierrors.IsNotFound(getErr) {
		if cerr := c.Create(ctx, cert); cerr != nil && !apierrors.IsAlreadyExists(cerr) {
			return nil, nil, fmt.Errorf("create Certificate %s/%s: %w", ns, name, cerr)
		}
	} else if getErr != nil {
		return nil, nil, fmt.Errorf("get Certificate %s/%s: %w", ns, name, getErr)
	}
	// cert-manager owns the object once created (rotation etc.); we only wait for the Secret.

	deadline := time.Now().Add(5 * time.Minute)
	for {
		var sec corev1.Secret
		if e := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: secretName}, &sec); e == nil {
			crt, key, ca := sec.Data["tls.crt"], sec.Data["tls.key"], sec.Data["ca.crt"]
			if len(crt) > 0 && len(key) > 0 {
				// Present leaf + issuing chain so the root-anchored reflector can build the path.
				chain := crt
				if len(ca) > 0 {
					chain = append(append(append([]byte{}, crt...), '\n'), ca...)
				}
				return chain, key, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, nil, fmt.Errorf("timed out waiting for cert-manager to mint Secret %s/%s", ns, secretName)
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
