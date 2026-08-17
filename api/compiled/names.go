// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compiled

// Singular names + kubectl short names for the aggregated compiled resources; see
// api/net/names.go for why these are needed (apiserver-kit SingularNameProvider /
// ShortNamesProvider).

func (*CompiledNIC) GetSingularName() string { return "compilednic" }
func (*CompiledNIC) ShortNames() []string    { return []string{"cnic"} }

func (*CompiledVM) GetSingularName() string { return "compiledvm" }
func (*CompiledVM) ShortNames() []string    { return []string{"cvm"} }

func (*CompiledContainer) GetSingularName() string { return "compiledcontainer" }
func (*CompiledContainer) ShortNames() []string    { return []string{"cctr"} }

func (*CompiledVolumeAttachment) GetSingularName() string { return "compiledvolumeattachment" }
func (*CompiledVolumeAttachment) ShortNames() []string    { return []string{"cva"} }
