// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Command flowplane-cni is the primary-UDN CNI plugin. It is the Multus default
// delegate for a virt-launcher pod: on ADD it resolves the pod's overlay
// {vni, ips} from the net.ectobase.dev CRDs and calls the node-local flowplane
// DataplaneNode gRPC to attach the interface into the eBPF dataplane.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	dataplanev1 "github.com/trevex/ectobase/cni/gen/dataplanev1"
)

const (
	defaultKubeconfig    = "/etc/cni/net.d/dataplane-kubeconfig"
	defaultDataplaneAddr = "unix:///run/flowplane/dataplane.sock"

	// networkInterfaceAnnotation names the NetworkInterface CR bound to this pod.
	networkInterfaceAnnotation = "net.ectobase.dev/network-interface"
)

// netConf is our CNI configuration, parsed from stdin.
type netConf struct {
	types.NetConf

	// Kubeconfig is the on-node SA-token kubeconfig used to read pod + CRDs.
	Kubeconfig string `json:"kubeconfig,omitempty"`
	// DataplaneAddr is the address of the node-local flowplane DataplaneNode gRPC
	// (a unix:// socket by default, or a host:port).
	DataplaneAddr string `json:"dataplaneAddr,omitempty"`
	// DeviceType selects the guest-edge device: "" / "veth" (container; default) or "pod-tap"
	// (a KubeVirt VM — a tap in this pod netns spliced to a root-netns veth). Set in the NAD
	// config of the KubeVirt network-binding plugin.
	DeviceType string `json:"deviceType,omitempty"`
	// TapName is the exact tap device name for device_type=pod-tap. KubeVirt's
	// domainAttachmentType:tap opens the primary tap by the literal name "tap0", so the binding
	// NAD sets tapName:"tap0". Empty = the dataplane derives one.
	TapName string `json:"tapName,omitempty"`
}

func loadNetConf(stdin []byte) (*netConf, error) {
	conf := &netConf{}
	if err := json.Unmarshal(stdin, conf); err != nil {
		return nil, fmt.Errorf("parse network config: %w", err)
	}
	if conf.Kubeconfig == "" {
		conf.Kubeconfig = defaultKubeconfig
	}
	if conf.DataplaneAddr == "" {
		conf.DataplaneAddr = defaultDataplaneAddr
	}
	return conf, nil
}

func main() {
	skel.PluginMainFuncs(
		skel.CNIFuncs{
			Add:   cmdAdd,
			Del:   cmdDel,
			Check: cmdCheck,
		},
		version.All,
		"flowplane primary-UDN CNI plugin",
	)
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	pod := parseCNIArgs(args.Args)
	if pod.Namespace == "" || pod.Name == "" {
		return fmt.Errorf("missing pod identity in CNI_ARGS (K8S_POD_NAMESPACE/K8S_POD_NAME)")
	}

	// Bound the whole ADD flow (two apiserver reads + the AttachInterface gRPC): a hung apiserver or
	// unreachable dataplane must not stall pod sandbox creation indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Read the pod to find which NetworkInterface CR it is bound to.
	niNS, niName, err := resolvePodInterfaceRef(ctx, conf.Kubeconfig, pod.Namespace, pod.Name)
	if err != nil {
		return err
	}

	// Resolve overlay {vni, ips, mac} from the broker-synced CompiledNIC (central policy).
	cl, err := newK8sClient(conf.Kubeconfig)
	if err != nil {
		return err
	}
	res, err := resolveCompiledNIC(ctx, cl, niNS, niName)
	if err != nil {
		return err
	}

	// Attach the interface into the eBPF dataplane via the node-local gRPC.
	dp, closeConn, err := dialDataplane(conf.DataplaneAddr)
	if err != nil {
		return err
	}
	defer closeConn()

	interfaceID := pod.UID + "/" + args.IfName
	resp, err := attach(ctx, dp, &dataplanev1.AttachInterfaceRequest{
		InterfaceId:  interfaceID,
		NetnsPath:    args.Netns,
		Vni:          res.VNI,
		Mac:          res.MAC,
		RequestedIps: res.IPs,
		// For a KubeVirt VM the NAD sets deviceType=pod-tap + tapName=tap0: the dataplane
		// creates the tap in THIS (launcher) pod netns spliced to a root-netns veth, and
		// KubeVirt's domainAttachmentType:tap opens that tap by name for the VM's NIC.
		DeviceType: conf.DeviceType,
		TapName:    conf.TapName,
	})
	if err != nil {
		return err
	}

	result, err := buildResult(conf.CNIVersion, args.IfName, args.Netns, resp)
	if err != nil {
		// The interface is already attached but we cannot return a valid result. Detach
		// it here rather than relying solely on the runtime to call DEL: DEL is keyed off
		// the pod UID from CNI_ARGS, which some runtimes do not forward on the failure
		// path, so without this the dataplane interface state would leak.
		_ = detach(ctx, dp, interfaceID)
		return err
	}
	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	pod := parseCNIArgs(args.Args)
	// DEL is best-effort and keyed off the pod UID; if we cannot identify the
	// interface there is nothing to detach.
	if pod.UID == "" {
		return nil
	}

	dp, closeConn, err := dialDataplane(conf.DataplaneAddr)
	if err != nil {
		// Best-effort: if the dataplane is unreachable, do not block teardown.
		return nil
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	interfaceID := pod.UID + "/" + args.IfName
	// Best-effort: ignore not-found / errors so DEL is idempotent.
	_ = detach(ctx, dp, interfaceID)
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	// CHECK is optional; this plugin holds no per-interface state to validate, so it is a no-op success.
	return nil
}

// buildResult constructs a CNI Result (v1.0.0) from the attach response. A
// Multus default network requires at least one IP.
func buildResult(cniVersion, ifName, netns string, resp *dataplanev1.AttachInterfaceResponse) (*types100.Result, error) {
	result := &types100.Result{
		CNIVersion: cniVersion,
		Interfaces: []*types100.Interface{
			{
				Name:    ifName,
				Mac:     resp.GetMac(),
				Sandbox: netns,
			},
		},
	}

	ips := resp.GetIps()
	if len(ips) == 0 {
		return nil, fmt.Errorf("dataplane returned no IPs; a default network requires at least one")
	}

	for _, ipStr := range ips {
		ip, ipnet, err := net.ParseCIDR(ipStr)
		if err != nil {
			// Fall back to treating a bare address as a host route.
			ip = net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("parse response IP %q: %w", ipStr, err)
			}
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipnet = &net.IPNet{IP: ip, Mask: mask}
		}
		ipConfig := &types100.IPConfig{
			Interface: types100.Int(0),
			Address:   net.IPNet{IP: ip, Mask: ipnet.Mask},
		}
		if gw := resp.GetGateway(); gw != "" {
			ipConfig.Gateway = net.ParseIP(gw)
		}
		result.IPs = append(result.IPs, ipConfig)
	}

	return result, nil
}
