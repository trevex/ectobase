// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

// Singular names + kubectl short names for the aggregated net resources. The
// apiserver-kit DefaultStrategy reads these off the resource object (via the
// SingularNameProvider / ShortNamesProvider interfaces); without them discovery
// advertises no singular (kubectl then rejects `get vpc`, only `get vpcs` works)
// and no short names.

func (*VPC) GetSingularName() string { return "vpc" }

func (*NetworkInterface) GetSingularName() string { return "networkinterface" }
func (*NetworkInterface) ShortNames() []string    { return []string{"nic"} }

func (*FirewallPolicy) GetSingularName() string { return "firewallpolicy" }
func (*FirewallPolicy) ShortNames() []string    { return []string{"fwp"} }

func (*FloatingIP) GetSingularName() string { return "floatingip" }
func (*FloatingIP) ShortNames() []string    { return []string{"fip"} }

func (*LoadBalancer) GetSingularName() string { return "loadbalancer" }
func (*LoadBalancer) ShortNames() []string    { return []string{"lb"} }

func (*NATGateway) GetSingularName() string { return "natgateway" }
func (*NATGateway) ShortNames() []string    { return []string{"natgw"} }

func (*VPCPeering) GetSingularName() string { return "vpcpeering" }
func (*VPCPeering) ShortNames() []string    { return []string{"vpcp"} }
