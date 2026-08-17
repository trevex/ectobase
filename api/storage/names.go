// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package storage

// Singular name + kubectl short names for the aggregated storage resources; see
// api/net/names.go for why these are needed (apiserver-kit SingularNameProvider /
// ShortNamesProvider).

func (*Volume) GetSingularName() string { return "volume" }
func (*Volume) ShortNames() []string    { return []string{"vol"} }
