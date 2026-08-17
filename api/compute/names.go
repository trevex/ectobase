// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compute

// Singular names + kubectl short names for the aggregated compute resources; see
// api/net/names.go for why these are needed (apiserver-kit SingularNameProvider /
// ShortNamesProvider).

func (*VirtualMachine) GetSingularName() string { return "virtualmachine" }
func (*VirtualMachine) ShortNames() []string    { return []string{"vm"} }

func (*Container) GetSingularName() string { return "container" }
func (*Container) ShortNames() []string    { return []string{"ctr"} }
