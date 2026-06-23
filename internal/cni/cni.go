// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/cni/route"
	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

const cniTimeout = 10 * time.Second

const labelNode = "bgp.miloapis.com/node"

var cniScheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(cniScheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(cniScheme))
}

// PluginConf is the CNI plugin configuration passed via stdin on each invocation.
type PluginConf struct {
	types.PluginConf
	VPC           string        `json:"vpc"`
	VPCAttachment string        `json:"vpcattachment"`
	MTU           int           `json:"mtu,omitempty"`
	Terminations  []Termination `json:"terminations,omitempty"`
	IPAM          IPAM          `json:"ipam,omitempty"`
	SRv6Locator   string        `json:"srv6_locator"`
}

func RunPlugin() {
	skel.PluginMainFuncs(
		skel.CNIFuncs{
			Add: cmdAdd,
			Del: cmdDel,
		},
		version.All,
		fmt.Sprintf("CNI galactic plugin %s", metadata.Version),
	)
}

func parseConf(data []byte) (*PluginConf, error) {
	conf := &PluginConf{}
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, fmt.Errorf("parse CNI config: %w", err)
	}
	return conf, nil
}

// bgpVRFInstanceName returns the deterministic cluster-scoped name for a
// BGPVRFInstance. Each VPCAttachment is unique per interface across the
// cluster, so the (vpc, vpcAttachment) pair is a reliable 1:1 key.
func bgpVRFInstanceName(vpc, vpcAttachment string) string {
	return fmt.Sprintf("%s-%s", vpc, vpcAttachment)
}

// routeDistinguisher returns the RD in "ASN:NN" (Type 0) format using the
// low 32 bits of the VPC identifier as the NN field. Type 0 has a 4-byte NN
// field, so the full uint32 range is safe on the wire. The RD is VPC-scoped
// rather than node-scoped; EVPN Type 5 next-hop differentiates routes from
// different nodes, so per-node uniqueness is not required.
func routeDistinguisher(asNumber int64, vpcHex string) (string, error) {
	v, err := strconv.ParseUint(vpcHex, 16, 64)
	if err != nil {
		return "", fmt.Errorf("parse VPC hex %q: %w", vpcHex, err)
	}
	return fmt.Sprintf("%d:%d", asNumber, uint32(v)), nil
}

// routeTarget returns the RT in "ASN:NN" format using the low 32 bits of the
// VPC identifier. All nodes in the same VPC produce the same value, enabling
// VPC-scoped route import/export. vpcHex is the 48-bit hex VPC identifier.
func routeTarget(asNumber int64, vpcHex string) (string, error) {
	v, err := strconv.ParseUint(vpcHex, 16, 64)
	if err != nil {
		return "", fmt.Errorf("parse VPC hex %q: %w", vpcHex, err)
	}
	return fmt.Sprintf("%d:%d", asNumber, uint32(v)), nil
}

// bgpConfig holds the BGP values the CNI needs to populate a BGPVRFInstance.
type bgpConfig struct {
	asNumber       int64
	routerSelector map[string]string
}

// lookupBGPConfig finds the BGPRouter on this node and returns its AS number
// and a label selector that the BGPVRFInstance uses to bind to it.
func lookupBGPConfig(ctx context.Context, k8s client.Client, nodeName string) (bgpConfig, error) {
	routerList := &bgpv1alpha1.BGPRouterList{}
	// BGPRouter is Namespaced; list across all namespaces.
	if err := k8s.List(ctx, routerList); err != nil {
		return bgpConfig{}, fmt.Errorf("list BGPRouters: %w", err)
	}

	// Collect BGPRouters whose TargetRef matches this node.
	var matches []*bgpv1alpha1.BGPRouter
	for i := range routerList.Items {
		r := &routerList.Items[i]
		if r.Spec.TargetRef.Kind == "Node" && r.Spec.TargetRef.Name == nodeName {
			matches = append(matches, r)
		}
	}

	switch len(matches) {
	case 0:
		return bgpConfig{}, fmt.Errorf("no BGPRouter found for node %s", nodeName)
	case 1:
		// expected
	default:
		names := make([]string, len(matches))
		for i, m := range matches {
			names[i] = m.Name
		}
		return bgpConfig{}, fmt.Errorf("ambiguous BGP config: %d BGPRouters target node %s: [%s]",
			len(matches), nodeName, strings.Join(names, ", "))
	}
	router := matches[0]

	return bgpConfig{
		asNumber:       int64(router.Spec.LocalASN),
		routerSelector: map[string]string{labelNode: nodeName},
	}, nil
}

func newK8sClient() (client.Client, error) {
	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("get kubeconfig: %w", err)
	}
	c, err := client.New(restCfg, client.Options{Scheme: cniScheme})
	if err != nil {
		return nil, fmt.Errorf("create k8s client: %w", err)
	}
	return c, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return fmt.Errorf("NODE_NAME environment variable is not set")
	}

	if err := vrf.Add(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		return fmt.Errorf("add VRF: %w", err)
	}
	if err := veth.Add(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.MTU); err != nil {
		return fmt.Errorf("add veth: %w", err)
	}
	dev := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)
	for _, termination := range pluginConf.Terminations {
		if err := route.Add(pluginConf.VPC, pluginConf.VPCAttachment, termination.Network, termination.Via, dev); err != nil {
			return fmt.Errorf("add route %s: %w", termination.Network, err)
		}
	}
	if err := hostDevice("ADD", args, pluginConf); err != nil {
		return fmt.Errorf("host-device ADD: %w", err)
	}

	vpcHex, err := intf.Base62ToHex(pluginConf.VPC)
	if err != nil {
		return fmt.Errorf("decode VPC: %w", err)
	}
	vpcAttachmentHex, err := intf.Base62ToHex(pluginConf.VPCAttachment)
	if err != nil {
		return fmt.Errorf("decode VPCAttachment: %w", err)
	}

	k8s, err := newK8sClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cniTimeout)
	defer cancel()

	bgp, err := lookupBGPConfig(ctx, k8s, nodeName)
	if err != nil {
		return err
	}

	rdValue, err := routeDistinguisher(bgp.asNumber, vpcHex)
	if err != nil {
		return fmt.Errorf("compute route distinguisher: %w", err)
	}
	rtValue, err := routeTarget(bgp.asNumber, vpcHex)
	if err != nil {
		return fmt.Errorf("compute route target: %w", err)
	}
	rt := bgpv1alpha1.RouteTarget{Value: rtValue}

	inst := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpVRFInstanceName(pluginConf.VPC, pluginConf.VPCAttachment),
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, k8s, inst, func() error {
		inst.Spec = bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget: bgpv1alpha1.RouterTarget{
				RouterSelector: &bgpv1alpha1.RouterSelector{
					MatchLabels: bgp.routerSelector,
				},
			},
			RouteDistinguisher: rdValue,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{rt},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{rt},
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("apply BGPVRFInstance: %w", err)
	}

	srv6Endpoint, err := intf.EncodeSRv6Endpoint(pluginConf.SRv6Locator, vpcHex, vpcAttachmentHex)
	if err != nil {
		return fmt.Errorf("encode SRv6 endpoint: %w", err)
	}
	if err := srv6.RouteIngressAdd(srv6Endpoint); err != nil {
		return fmt.Errorf("add SRv6 ingress route: %w", err)
	}

	result := &type100.Result{}
	return types.PrintResult(result, pluginConf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	vpcHex, err := intf.Base62ToHex(pluginConf.VPC)
	if err != nil {
		return fmt.Errorf("decode VPC: %w", err)
	}
	vpcAttachmentHex, err := intf.Base62ToHex(pluginConf.VPCAttachment)
	if err != nil {
		return fmt.Errorf("decode VPCAttachment: %w", err)
	}
	srv6Endpoint, err := intf.EncodeSRv6Endpoint(pluginConf.SRv6Locator, vpcHex, vpcAttachmentHex)
	if err != nil {
		return fmt.Errorf("encode SRv6 endpoint: %w", err)
	}
	if err := srv6.RouteIngressDel(srv6Endpoint); err != nil {
		return fmt.Errorf("delete SRv6 ingress route: %w", err)
	}

	// Signal BGP route withdrawal immediately after stopping kernel ingress so
	// remote peers are notified as soon as possible. cosmos reconciles async.
	// IgnoreNotFound handles concurrent DEL races.
	k8s, err := newK8sClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cniTimeout)
	defer cancel()

	inst := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name: bgpVRFInstanceName(pluginConf.VPC, pluginConf.VPCAttachment),
		},
	}
	if err := k8s.Delete(ctx, inst); client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("delete BGPVRFInstance: %w", err)
	}

	dev := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)
	if err := hostDevice("DEL", args, pluginConf); err != nil {
		return fmt.Errorf("host-device DEL: %w", err)
	}
	for _, termination := range pluginConf.Terminations {
		if err := route.Delete(pluginConf.VPC, pluginConf.VPCAttachment, termination.Network, termination.Via, dev); err != nil {
			return fmt.Errorf("delete route %s: %w", termination.Network, err)
		}
	}
	if err := veth.Delete(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		return fmt.Errorf("delete veth: %w", err)
	}
	if err := vrf.Delete(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		return fmt.Errorf("delete VRF: %w", err)
	}

	result := &type100.Result{}
	return types.PrintResult(result, pluginConf.CNIVersion)
}

type HostDevicePluginConf struct {
	types.PluginConf
	Device string `json:"device"`
	IPAM   IPAM   `json:"ipam,omitempty"`
}

func hostDeviceExecutable() string {
	path, _ := os.Executable()
	dir := filepath.Dir(path)
	return filepath.Join(dir, "host-device")
}

func hostDevice(command string, skelArgs *skel.CmdArgs, pluginConf *PluginConf) error {
	conf, err := json.Marshal(HostDevicePluginConf{
		PluginConf: types.PluginConf{
			CNIVersion: pluginConf.CNIVersion,
			Name:       pluginConf.Name,
			Type:       "host-device",
		},
		Device: intf.GenerateInterfaceNameGuest(pluginConf.VPC, pluginConf.VPCAttachment),
		IPAM:   pluginConf.IPAM,
	})
	if err != nil {
		return err
	}

	invokeExec := &invoke.DefaultExec{
		RawExec:       &invoke.RawExec{Stderr: os.Stderr},
		PluginDecoder: version.PluginDecoder{},
	}
	invokeArgs := invoke.Args{
		Command:       command,
		ContainerID:   skelArgs.ContainerID,
		NetNS:         skelArgs.Netns,
		PluginArgsStr: skelArgs.Args,
		IfName:        skelArgs.IfName,
		Path:          skelArgs.Path,
	}
	if _, err := invokeExec.ExecPlugin(context.Background(), hostDeviceExecutable(), conf, invokeArgs.AsEnv()); err != nil {
		return err
	}
	return nil
}
