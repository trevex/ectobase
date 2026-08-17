// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

// Singular names + kubectl short names for the aggregated platform resources; see
// api/net/names.go for why these are needed (apiserver-kit SingularNameProvider /
// ShortNamesProvider).

func (*ClusterPool) GetSingularName() string { return "clusterpool" }
func (*ClusterPool) ShortNames() []string    { return []string{"cpool"} }

func (*RouteBusIdentity) GetSingularName() string { return "routebusidentity" }
func (*RouteBusIdentity) ShortNames() []string    { return []string{"rbi"} }
