// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"k8s.io/client-go/rest"
)

// dispatchAuth is the file-based mTLS credential for the dispatch aggregated apiserver.
type dispatchAuth struct {
	server   string // https URL incl. the fabric IP literal, e.g. https://[fd00:...]:6443
	caFile   string // root CA that signs the dispatch serving cert
	certFile string // broker client leaf (cert-manager rotates it on disk)
	keyFile  string // broker client key
}

// dispatchConfig builds a rest.Config that authenticates to the dispatch apiserver with a
// client certificate and verifies the server against caFile. File-based paths (not inline
// data) are deliberate: client-go re-reads them from disk, so cert-manager rotation needs no
// broker restart.
func dispatchConfig(a dispatchAuth) (*rest.Config, error) {
	if a.server == "" {
		return nil, fmt.Errorf("dispatch server URL is required")
	}
	if a.certFile == "" || a.keyFile == "" || a.caFile == "" {
		return nil, fmt.Errorf("dispatch cert/key/ca file paths are required")
	}
	return &rest.Config{
		Host: a.server,
		TLSClientConfig: rest.TLSClientConfig{
			CAFile:   a.caFile,
			CertFile: a.certFile,
			KeyFile:  a.keyFile,
		},
	}, nil
}
