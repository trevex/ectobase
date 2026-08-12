// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	dataplanev1 "github.com/trevex/ectobase/cni/gen/dataplanev1"
)

func TestLoadNetConfDefaults(t *testing.T) {
	conf, err := loadNetConf([]byte(`{"cniVersion":"1.0.0","name":"n","type":"flowplane-cni"}`))
	if err != nil {
		t.Fatalf("loadNetConf: %v", err)
	}
	if conf.Kubeconfig != defaultKubeconfig {
		t.Errorf("Kubeconfig = %q, want default %q", conf.Kubeconfig, defaultKubeconfig)
	}
	if conf.DataplaneAddr != defaultDataplaneAddr {
		t.Errorf("DataplaneAddr = %q, want default %q", conf.DataplaneAddr, defaultDataplaneAddr)
	}
}

func TestLoadNetConfOverrides(t *testing.T) {
	conf, err := loadNetConf([]byte(`{"cniVersion":"1.0.0","name":"n","type":"flowplane-cni","kubeconfig":"/tmp/kc","dataplaneAddr":"127.0.0.1:9999","deviceType":"pod-tap","tapName":"tap0"}`))
	if err != nil {
		t.Fatalf("loadNetConf: %v", err)
	}
	if conf.Kubeconfig != "/tmp/kc" || conf.DataplaneAddr != "127.0.0.1:9999" {
		t.Errorf("overrides not honored: %+v", conf)
	}
	if conf.DeviceType != "pod-tap" || conf.TapName != "tap0" {
		t.Errorf("tap fields not parsed: %+v", conf)
	}
}

func TestLoadNetConfInvalid(t *testing.T) {
	if _, err := loadNetConf([]byte(`not json`)); err == nil {
		t.Fatal("expected error on malformed config")
	}
}

func TestParseCNIArgs(t *testing.T) {
	got := parseCNIArgs("IgnoreUnknown=1;K8S_POD_NAMESPACE=ns1;K8S_POD_NAME=pod1;K8S_POD_UID=uid-123")
	if got.Namespace != "ns1" || got.Name != "pod1" || got.UID != "uid-123" {
		t.Fatalf("parseCNIArgs = %+v", got)
	}
	// Malformed pairs are skipped, not fatal.
	got = parseCNIArgs(";;K8S_POD_NAME=only;garbage")
	if got.Name != "only" || got.Namespace != "" || got.UID != "" {
		t.Fatalf("parseCNIArgs(partial) = %+v", got)
	}
	if empty := parseCNIArgs(""); empty != (podArgs{}) {
		t.Fatalf("parseCNIArgs(empty) = %+v", empty)
	}
}

func TestBuildResult(t *testing.T) {
	cases := []struct {
		name    string
		resp    *dataplanev1.AttachInterfaceResponse
		wantErr bool
		wantGW  string
	}{
		{
			name:    "no IPs is an error",
			resp:    &dataplanev1.AttachInterfaceResponse{Mac: "aa:bb:cc:dd:ee:ff"},
			wantErr: true,
		},
		{
			name:   "v4 CIDR with gateway",
			resp:   &dataplanev1.AttachInterfaceResponse{Ips: []string{"10.0.0.5/24"}, Gateway: "10.0.0.1"},
			wantGW: "10.0.0.1",
		},
		{
			name: "bare v4 falls back to /32",
			resp: &dataplanev1.AttachInterfaceResponse{Ips: []string{"10.0.0.5"}},
		},
		{
			name: "bare v6 falls back to /128",
			resp: &dataplanev1.AttachInterfaceResponse{Ips: []string{"fd00::5"}},
		},
		{
			name:    "garbage IP is an error",
			resp:    &dataplanev1.AttachInterfaceResponse{Ips: []string{"not-an-ip"}},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := buildResult("1.0.0", "eth0", "/var/run/netns/x", tc.resp)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildResult: %v", err)
			}
			if len(res.IPs) != 1 {
				t.Fatalf("want 1 IP config, got %d", len(res.IPs))
			}
			if tc.wantGW != "" && res.IPs[0].Gateway.String() != tc.wantGW {
				t.Errorf("gateway = %v, want %s", res.IPs[0].Gateway, tc.wantGW)
			}
			if ones, _ := res.IPs[0].Address.Mask.Size(); ones == 0 {
				t.Errorf("address mask not set: %v", res.IPs[0].Address)
			}
		})
	}
}
