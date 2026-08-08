// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package clusterrestriction

import (
	"testing"

	authuser "k8s.io/apiserver/pkg/authentication/user"
)

func TestReview(t *testing.T) {
	brokerC1 := &authuser.DefaultInfo{Name: "ectobase:cluster:c1"}
	admin := &authuser.DefaultInfo{Name: "admin"}
	cases := []struct {
		name      string
		user      authuser.Info
		in        Attr
		wantAllow bool
	}{
		{"broker writes own pool status", brokerC1, Attr{Resource: "clusterpools", Name: "c1", Subresource: "status"}, true},
		{"broker writes other pool status", brokerC1, Attr{Resource: "clusterpools", Name: "c2", Subresource: "status"}, false},
		{"broker writes own pool spec", brokerC1, Attr{Resource: "clusterpools", Name: "c1", Subresource: ""}, false},
		{"broker sets clusterName", brokerC1, Attr{Resource: "virtualmachines", Name: "vm1", SetsClusterName: true}, false},
		{"broker writes vm w/o clusterName change", brokerC1, Attr{Resource: "virtualmachines", Name: "vm1"}, true},
		{"admin unrestricted", admin, Attr{Resource: "clusterpools", Name: "c2", Subresource: ""}, true},
		{"admin sets clusterName", admin, Attr{Resource: "virtualmachines", SetsClusterName: true}, true},
	}
	for _, tc := range cases {
		allow, _ := Review(tc.user, tc.in)
		if allow != tc.wantAllow {
			t.Errorf("%s: got allow=%v want %v", tc.name, allow, tc.wantAllow)
		}
	}
}
