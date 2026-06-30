// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/cni/ipam"
	"go.datum.net/galactic/internal/cni/route"
	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

const cniTimeout = 10 * time.Second

// ipamTypePool is the ipam type for the built-in local IPAM pool allocator.
const ipamTypePool = "pool"

const (
	// localIPAMDefaultPool is the IPv6 CIDR pool used when local IPAM is
	// enabled but no explicit ipam block is present in the CNI config.
	localIPAMDefaultPool = "fd00:10:ff01::/48"

	// localIPAMDefaultSubnetLen is the default prefix length for local IPAM
	// allocations (default /80, giving 2^48 addresses per pod subnet).
	localIPAMDefaultSubnetLen = 80
)

const (
	// annotationAllocatedSubnet is the BGPAdvertisement annotation key prefix
	// holding the allocated pod subnet CIDR for a container ID. The full key
	// appends a truncated container ID; see subnetAnnotationKey.
	annotationAllocatedSubnet = "galactic.datum.net/allocated-subnet"

	// annotationSRv6SID is the BGPAdvertisement annotation key holding the
	// End.DT46 SRv6 SID for this VPC attachment. Galactic-router reads this
	// annotation to set the EVPN GWIPAddress to the actual SRv6 SID rather
	// than the BGP peering loopback, so remote nodes install correct seg6
	// encap routes.
	annotationSRv6SID = "galactic.datum.net/srv6-sid"

	// annotationContainerIDLen is the number of characters used from a
	// container ID in annotation keys. Kubernetes limits the name part of an
	// annotation key to 63 bytes; "allocated-subnet." is 17 bytes, leaving 46
	// bytes for the container ID prefix.
	annotationContainerIDLen = 46

	// defaultNamespace is used when the CNI config does not specify a namespace.
	defaultNamespace = "default"
)

// subnetAnnotationKey returns the annotation key for storing the allocated
// subnet for the given container ID.
func subnetAnnotationKey(containerID string) string {
	id := containerID
	if len(id) > annotationContainerIDLen {
		id = id[:annotationContainerIDLen]
	}
	return fmt.Sprintf("%s.%s", annotationAllocatedSubnet, id)
}

var cniScheme = runtime.NewScheme()

// enableLocalIPAM controls whether the plugin performs IP allocation when
// no explicit ipam block is present in the CNI config. Defaults to false.
var enableLocalIPAM bool

// SetEnableLocalIPAM sets the local IPAM flag from the CLI.
func SetEnableLocalIPAM(v bool) {
	enableLocalIPAM = v
}

const (
	// interfaceTypeVeth is the default interface type: veth pair for containers.
	interfaceTypeVeth = "veth"
	// interfaceTypeTap is the tap interface type: L2 fd for VMs (Kata, Firecracker).
	interfaceTypeTap = "tap"

	// cniVersion100 is the CNI spec version this plugin reports.
	cniVersion100 = "1.0.0"
)

// resourceTracker tracks resources created during cmdAdd for selective rollback.
type resourceTracker struct {
	vpc, vpcAttachment string
	ifaceType          string
	vrfCreated         bool
	routesCreated      int
	srv6SID            string
	vrfInstanceCreated bool
	advCreated         bool
	k8s                client.Client
	namespace          string
}

// cleanup rolls back all tracked resources in reverse creation order.
// Errors are logged but never returned — the caller already has a failure.
func (rt *resourceTracker) cleanup(ctx context.Context) {
	slog.Info("Selective rollback: cleaning up resources created during failed ADD",
		"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)

	// 1. Delete BGPAdvertisement (withdraws prefixes)
	if rt.advCreated && rt.k8s != nil {
		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bgpAdvertisementName(rt.vpc, rt.vpcAttachment),
				Namespace: rt.namespace,
			},
		}
		if err := rt.k8s.Delete(ctx, adv); client.IgnoreNotFound(err) != nil {
			slog.Error("Rollback: failed to delete BGPAdvertisement", "err", err,
				"name", adv.Name, "namespace", rt.namespace)
		}
	}

	// 2. Delete BGPVRFInstance
	if rt.vrfInstanceCreated && rt.k8s != nil {
		vrfInst := &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bgpVRFInstanceName(rt.vpc, rt.vpcAttachment),
				Namespace: rt.namespace,
			},
		}
		if err := rt.k8s.Delete(ctx, vrfInst); client.IgnoreNotFound(err) != nil {
			slog.Error("Rollback: failed to delete BGPVRFInstance", "err", err,
				"name", vrfInst.Name, "namespace", rt.namespace)
		}
	}

	// 3. Delete SRv6 ingress route (only if we got a SID)
	if rt.srv6SID != "" {
		if err := srv6.RouteIngressDel(rt.srv6SID); err != nil {
			slog.Error("Rollback: failed to delete SRv6 ingress route", "err", err,
				"sid", rt.srv6SID)
		}
	}

	// 4. Delete host veth (veth mode only)
	if rt.ifaceType == interfaceTypeVeth {
		if err := veth.Delete(rt.vpc, rt.vpcAttachment); err != nil {
			slog.Error("Rollback: failed to delete veth", "err", err,
				"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
		}
	}

	// 5. Delete tap (tap mode only)
	if rt.ifaceType == interfaceTypeTap {
		if err := tap.Delete(rt.vpc, rt.vpcAttachment); err != nil {
			slog.Error("Rollback: failed to delete tap", "err", err,
				"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
		}
	}

	// 6. Delete VRF (flushes all routes, removes VRF interface)
	if err := vrf.Delete(rt.vpc, rt.vpcAttachment); err != nil {
		slog.Error("Rollback: failed to delete VRF", "err", err,
			"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)
	}
}

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
	InterfaceType string        `json:"interface_type,omitempty"` // interfaceTypeVeth or interfaceTypeTap
	Terminations  []Termination `json:"terminations,omitempty"`
	IPAM          IPAM          `json:"ipam"`
	SRv6Locator   string        `json:"srv6_locator"`
	Namespace     string        `json:"namespace,omitempty"`
}

func RunPlugin() {
	skel.PluginMainFuncs(
		skel.CNIFuncs{
			Add:   cmdAdd,
			Check: cmdCheck,
			Del:   cmdDel,
		},
		version.All,
		"CNI galactic plugin "+metadata.Version,
	)
}

func parseConf(data []byte) (*PluginConf, error) {
	conf := &PluginConf{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("parse CNI config: %w", err)
	}
	if conf.InterfaceType == "" {
		conf.InterfaceType = interfaceTypeVeth
	}
	switch conf.InterfaceType {
	case interfaceTypeVeth, interfaceTypeTap:
	default:
		return nil, fmt.Errorf(
			"invalid interface_type %q: must be %q or %q",
			conf.InterfaceType, interfaceTypeVeth, interfaceTypeTap,
		)
	}
	return conf, nil
}

// bgpVRFInstanceName returns the deterministic name for a BGPVRFInstance.
// Each VPCAttachment is unique per interface across the cluster, so the
// (vpc, vpcAttachment) pair is a reliable 1:1 key.
func bgpVRFInstanceName(vpc, vpcAttachment string) string {
	return fmt.Sprintf("%s-%s", vpc, vpcAttachment)
}

// bgpAdvertisementName returns the deterministic name for a BGPAdvertisement.
// Each VPCAttachment is unique per interface across the cluster, so the
// (vpc, vpcAttachment) pair is a reliable 1:1 key.
func bgpAdvertisementName(vpc, vpcAttachment string) string {
	return fmt.Sprintf("%s-%s", vpc, vpcAttachment)
}

// routeTarget returns the RT in "ASN:NN" format using the low 32 bits of the
// VPC identifier. All nodes in the same VRF produce the same value, enabling
// VPC-scoped route import/export. vpcHex is the 48-bit hex VPC identifier.
func routeTarget(asNumber int64, vpcHex string) (string, error) {
	v, err := strconv.ParseUint(vpcHex, 16, 64)
	if err != nil {
		return "", fmt.Errorf("parse VPC hex %q: %w", vpcHex, err)
	}
	return fmt.Sprintf("%d:%d", asNumber, uint32(v)), nil
}

// bgpConfig holds the BGP values the CNI needs to populate BGP CRDs.
type bgpConfig struct {
	asNumber   uint32
	routerName string
}

// lookupBGPRouter finds the BGPRouter targeting this node in the given namespace.
// Returns an error if none is found or if multiple are found (ambiguous).
func lookupBGPRouter(ctx context.Context, k8s client.Client, nodeName, namespace string) (bgpConfig, error) {
	routerList := &bgpv1alpha1.BGPRouterList{}
	if err := k8s.List(ctx, routerList, client.InNamespace(namespace)); err != nil {
		return bgpConfig{}, fmt.Errorf("list BGPRouters in namespace %s: %w", namespace, err)
	}

	var matches []bgpv1alpha1.BGPRouter
	for _, r := range routerList.Items {
		if r.Spec.TargetRef.Name == nodeName {
			matches = append(matches, r)
		}
	}

	switch len(matches) {
	case 0:
		return bgpConfig{}, fmt.Errorf("no BGPRouter found for node %s in namespace %s", nodeName, namespace)
	case 1:
		// expected
	default:
		return bgpConfig{}, fmt.Errorf("ambiguous BGP config: %d BGPRouters target node %s in namespace %s",
			len(matches), nodeName, namespace)
	}

	return bgpConfig{
		asNumber:   uint32(matches[0].Spec.LocalASN),
		routerName: matches[0].Name,
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
		return errors.New("NODE_NAME environment variable is not set")
	}

	namespace := pluginConf.Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}

	// Track resources for selective rollback on failure.
	tracker := &resourceTracker{
		vpc:           pluginConf.VPC,
		vpcAttachment: pluginConf.VPCAttachment,
		ifaceType:     pluginConf.InterfaceType,
		namespace:     namespace,
	}

	// Selective rollback: clean up only resources that were created.
	// We need a context for k8s operations in rollback; the k8s client
	// will be populated by publishBGPState before it's needed.
	rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), cniTimeout)
	defer func() {
		if err != nil {
			tracker.cleanup(rollbackCtx)
			rollbackCancel()
		}
	}()

	if err := vrf.Add(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		return fmt.Errorf("add VRF: %w", err)
	}
	tracker.vrfCreated = true

	// Create the appropriate interface type (veth or tap).
	switch pluginConf.InterfaceType {
	case interfaceTypeVeth:
		if err := veth.Add(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.MTU); err != nil {
			return fmt.Errorf("add veth: %w", err)
		}
	case interfaceTypeTap:
		if err := tap.Add(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.MTU); err != nil {
			return fmt.Errorf("add tap: %w", err)
		}
	}

	hostName := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("get host interface %q: %w", hostName, err)
	}
	hostMac := hostLink.Attrs().HardwareAddr.String()
	hostMTU := hostLink.Attrs().MTU

	dev := hostName
	for _, termination := range pluginConf.Terminations {
		if err := route.Add(pluginConf.VPC, pluginConf.VPCAttachment, termination.Network, termination.Via, dev); err != nil {
			return fmt.Errorf("add route %s: %w", termination.Network, err)
		}
		tracker.routesCreated++
	}

	// Host-device delegation and IPAM are veth-only.
	// In tap mode the guest VM manages its own networking.
	var ipamResult *ipamResult
	switch pluginConf.InterfaceType {
	case interfaceTypeVeth:
		guestName := intf.GenerateInterfaceNameGuest(pluginConf.VPC, pluginConf.VPCAttachment)
		ipamResult, err = buildVethResult(args, pluginConf, hostName, guestName, hostMac, hostMTU)
		if err != nil {
			return err
		}
	case interfaceTypeTap:
		result := buildTapResult(pluginConf, hostName, hostMac, hostMTU)
		if err := types.PrintResult(result, cniVersion100); err != nil {
			return fmt.Errorf("print CNI result: %w", err)
		}
		// Tap mode: no IPAM, no BGP — the guest VM manages its own networking.
		return nil
	}

	return publishBGPState(args, pluginConf, nodeName, namespace, ipamResult, tracker)
}

// cmdCheck validates that the container's network state matches what was
// established during cmdAdd. Per the CNI spec, CHECK is called by the runtime
// to probe the status of an existing container and should return an error if
// managed resources are missing or in an invalid state.
func cmdCheck(args *skel.CmdArgs) error {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	var errs []error

	// Check VRF interface exists.
	if err := vrf.Exists(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		errs = append(errs, fmt.Errorf("vrf %s-%s: %w", pluginConf.VPC, pluginConf.VPCAttachment, err))
	}

	// Check the host-side interface exists.
	hostName := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)
	if _, err := netlink.LinkByName(hostName); err != nil {
		errs = append(errs, fmt.Errorf("host interface %q: %w", hostName, err))
	}

	// For veth mode, verify the guest interface is in the container netns.
	if pluginConf.InterfaceType == interfaceTypeVeth {
		guestName := intf.GenerateInterfaceNameGuest(pluginConf.VPC, pluginConf.VPCAttachment)
		if err := checkGuestInterface(args.Netns, guestName); err != nil {
			errs = append(errs, fmt.Errorf("guest interface %q: %w", guestName, err))
		}

		// Verify termination routes exist in the VRF table.
		if err := checkTerminationRoutes(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.Terminations); err != nil {
			errs = append(errs, fmt.Errorf("termination routes: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("CHECK failed: %w", errors.Join(errs...))
	}
	return nil
}

// checkGuestInterface verifies that the named interface exists inside the
// given network namespace. Returns nil when the interface is present.
func checkGuestInterface(netnsPath, ifName string) error {
	containerNS, err := ns.GetNS(netnsPath)
	if err != nil {
		return fmt.Errorf("get container netns %q: %w", netnsPath, err)
	}
	defer containerNS.Close() //nolint:errcheck // netns close on teardown

	return containerNS.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("create netlink handle: %w", err)
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		if _, err := handle.LinkByName(ifName); err != nil {
			return fmt.Errorf("find interface %q: %w", ifName, err)
		}
		return nil
	})
}

// checkTerminationRoutes verifies that all termination routes exist in the
// VRF table for the given VPC/VPCAttachment pair.
func checkTerminationRoutes(vpc, vpcAttachment string, terminations []Termination) error {
	tableID, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		return fmt.Errorf("get VRF table ID: %w", err)
	}

	handle, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("create netlink handle: %w", err)
	}
	defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

	routes, err := handle.RouteList(nil, netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}

	dev := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	for _, term := range terminations {
		viaIP := net.ParseIP(term.Via)
		if viaIP == nil {
			return fmt.Errorf("invalid termination gateway %q", term.Via)
		}
		found := false
		for _, r := range routes {
			if r.Table == int(tableID) &&
				r.Dst != nil &&
				r.Dst.String() == term.Network &&
				r.Gw != nil &&
				r.Gw.Equal(viaIP) &&
				r.LinkIndex > 0 {
				// Verify the link name matches (defers to the veth/tap device).
				if link, linkErr := handle.LinkByIndex(r.LinkIndex); linkErr == nil && link.Attrs().Name == dev {
					found = true
					break
				}
			}
		}
		if !found {
			return fmt.Errorf("missing route %s via %s in VRF table %d", term.Network, term.Via, tableID)
		}
	}
	return nil
}

// publishBGPState configures the host veth gateway, sets up the SRv6 ingress
// route, and creates the BGPVRFInstance and BGPAdvertisement CRDs. This is
// veth-only; tap mode returns before reaching this path.
func publishBGPState(
	args *skel.CmdArgs, pluginConf *PluginConf, nodeName, namespace string, ipamResult *ipamResult,
	tracker *resourceTracker,
) error {
	if err := configureHostVethGateway(pluginConf.VPC, pluginConf.VPCAttachment, ipamResult); err != nil {
		return err
	}

	vpcHex, err := intf.Base62ToHex(pluginConf.VPC)
	if err != nil {
		return fmt.Errorf("decode VPC: %w", err)
	}
	vpcAttHex, err := intf.Base62ToHex(pluginConf.VPCAttachment)
	if err != nil {
		return fmt.Errorf("decode VPCAttachment: %w", err)
	}
	srv6SIDStr, err := setupSRv6Ingress(pluginConf.SRv6Locator, vpcHex, vpcAttHex)
	if err != nil {
		return err
	}
	if srv6SIDStr != "" {
		tracker.srv6SID = srv6SIDStr
	}

	k8s, err := newK8sClient()
	if err != nil {
		return err
	}
	tracker.k8s = k8s
	ctx, cancel := context.WithTimeout(context.Background(), cniTimeout)
	defer cancel()

	bgp, err := lookupBGPRouter(ctx, k8s, nodeName, namespace)
	if err != nil {
		return err
	}

	rtValue, err := routeTarget(int64(bgp.asNumber), vpcHex)
	if err != nil {
		return fmt.Errorf("compute route target: %w", err)
	}

	// Create the BGPVRFInstance to configure the VRF with its route distinguisher
	// and import/export route targets. This must be created before advertisements
	// so the BGP runtime has the VRF context when originating EVPN paths.
	vrfName := bgpVRFInstanceName(pluginConf.VPC, pluginConf.VPCAttachment)
	vrfInst := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vrfName,
			Namespace: namespace,
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, k8s, vrfInst, func() error {
		vrfInst.Spec = bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget: bgpv1alpha1.RouterTarget{
				RouterRef: &bgpv1alpha1.RouterRef{Name: bgp.routerName},
			},
			RouteDistinguisher: rtValue,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: rtValue}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: rtValue}},
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("apply BGPVRFInstance: %w", err)
	}
	tracker.vrfInstanceCreated = true

	// Create the BGPAdvertisement to originate the pod's subnet prefix.
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bgpAdvertisementName(pluginConf.VPC, pluginConf.VPCAttachment),
			Namespace: namespace,
		},
	}
	podSubnet := ""
	if ipamResult != nil {
		podSubnet = ipamResult.subnet.String()
	}
	_, err = controllerutil.CreateOrUpdate(ctx, k8s, adv, func() error {
		adv.Spec = bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: bgp.routerName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(podSubnet)},
			Communities:   []bgpv1alpha1.Community{bgpv1alpha1.Community(rtValue)},
		}
		if ipamResult != nil || srv6SIDStr != "" {
			if adv.Annotations == nil {
				adv.Annotations = make(map[string]string)
			}
			// Store the allocated subnet keyed by container ID so cmdDel can look it up.
			if ipamResult != nil {
				adv.Annotations[subnetAnnotationKey(args.ContainerID)] = podSubnet
			}
			// Store the End.DT46 SID so galactic-router uses it as the EVPN GWIPAddress.
			if srv6SIDStr != "" {
				adv.Annotations[annotationSRv6SID] = srv6SIDStr
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("apply BGPAdvertisement: %w", err)
	}
	tracker.advCreated = true

	return nil
}

func cmdDel(args *skel.CmdArgs) error {
	// DEL is idempotent per the CNI spec: always return success.
	// Missing resources are not errors. We collect all cleanup errors,
	// log them, and return nil so the CNI runtime does not retry.
	var errs []error

	// Parse config — if we can't parse it we still return success but
	// won't be able to clean up any resources.
	pluginConf, parseErr := parseConf(args.StdinData)
	if parseErr != nil {
		slog.Error("DEL: failed to parse CNI config, skipping cleanup", "err", parseErr,
			"containerID", args.ContainerID)
		// Cannot determine what to clean up without a valid config.
		result := &type100.Result{}
		_ = types.PrintResult(result, cniVersion100)
		return nil
	}

	namespace := pluginConf.Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}

	k8s, k8sErr := newK8sClient()
	if k8sErr != nil {
		slog.Error("DEL: failed to create k8s client, skipping IPAM deallocation and CRD cleanup", "err", k8sErr,
			"containerID", args.ContainerID)
		errs = append(errs, fmt.Errorf("create k8s client: %w", k8sErr))
	}

	// Deallocate IPAM subnet before any other cleanup (veth-only).
	if k8s != nil && pluginConf.InterfaceType == interfaceTypeVeth && (pluginConf.IPAM.Type != "" || enableLocalIPAM) {
		deallocateIPAM(args, pluginConf, k8s)
	}

	// Best-effort cleanup of all resources.
	if k8s != nil {
		ctx, cancel := context.WithTimeout(context.Background(), cniTimeout)
		defer cancel()

		// Delete the BGPAdvertisement first to withdraw prefixes, then the VRF instance.
		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bgpAdvertisementName(pluginConf.VPC, pluginConf.VPCAttachment),
				Namespace: namespace,
			},
		}
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(adv), adv); client.IgnoreNotFound(err) != nil {
			slog.Error("DEL: failed to get BGPAdvertisement", "err", err,
				"name", adv.Name, "namespace", namespace)
			errs = append(errs, fmt.Errorf("get BGPAdvertisement %s: %w", adv.Name, err))
		} else if err := k8s.Delete(ctx, adv); client.IgnoreNotFound(err) != nil {
			slog.Error("DEL: failed to delete BGPAdvertisement", "err", err,
				"name", adv.Name, "namespace", namespace)
			errs = append(errs, fmt.Errorf("delete BGPAdvertisement %s: %w", adv.Name, err))
		}

		vrfInst := &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bgpVRFInstanceName(pluginConf.VPC, pluginConf.VPCAttachment),
				Namespace: namespace,
			},
		}
		if err := k8s.Delete(ctx, vrfInst); client.IgnoreNotFound(err) != nil {
			slog.Error("DEL: failed to delete BGPVRFInstance", "err", err,
				"name", vrfInst.Name, "namespace", namespace)
			errs = append(errs, fmt.Errorf("delete BGPVRFInstance %s: %w", vrfInst.Name, err))
		}
	}

	dev := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)

	// host-device DEL is veth-only; tap has no guest interface to remove.
	if pluginConf.InterfaceType == interfaceTypeVeth {
		if err := hostDevice("DEL", args, pluginConf); err != nil {
			slog.Error("DEL: failed to delete host-device", "err", err,
				"containerID", args.ContainerID)
			errs = append(errs, fmt.Errorf("host-device DEL: %w", err))
		}
	}

	for _, termination := range pluginConf.Terminations {
		if err := route.Delete(
			pluginConf.VPC, pluginConf.VPCAttachment,
			termination.Network, termination.Via, dev,
		); err != nil {
			slog.Error("DEL: failed to delete route", "err", err,
				"network", termination.Network, "via", termination.Via)
			errs = append(errs, fmt.Errorf("delete route %s: %w", termination.Network, err))
		}
	}

	switch pluginConf.InterfaceType {
	case interfaceTypeVeth:
		if pluginConf.SRv6Locator != "" {
			if vpcHex, hexErr := intf.Base62ToHex(pluginConf.VPC); hexErr == nil {
				if vpcAttHex, attErr := intf.Base62ToHex(pluginConf.VPCAttachment); attErr == nil {
					if sid, sidErr := intf.EncodeSRv6Endpoint(pluginConf.SRv6Locator, vpcHex, vpcAttHex); sidErr == nil {
						if err := srv6.RouteIngressDel(sid); err != nil {
							slog.Error("DEL: failed to delete SRv6 ingress route", "err", err,
								"sid", sid)
							errs = append(errs, fmt.Errorf("delete SRv6 ingress route: %w", err))
						}
					}
				}
			}
		}
		if err := veth.Delete(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
			slog.Error("DEL: failed to delete veth", "err", err,
				"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
			errs = append(errs, fmt.Errorf("delete veth: %w", err))
		}
	case interfaceTypeTap:
		if err := tap.Delete(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
			slog.Error("DEL: failed to delete tap", "err", err,
				"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
			errs = append(errs, fmt.Errorf("delete tap: %w", err))
		}
	}

	if err := vrf.Delete(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		slog.Error("DEL: failed to delete VRF", "err", err,
			"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
		errs = append(errs, fmt.Errorf("delete VRF: %w", err))
	}

	result := &type100.Result{}
	_ = types.PrintResult(result, cniVersion100)

	if len(errs) > 0 {
		slog.Error("DEL: completed with cleanup errors",
			"count", len(errs), "containerID", args.ContainerID)
	}

	return nil
}

// ipamResult holds the IPAM allocation details for building the CNI result.
type ipamResult struct {
	subnet  *net.IPNet
	gateway net.IP
	routes  []*net.IPNet
}

// buildResult constructs the CNI result, including IPAM data if configured.
func buildResult(
	pluginConf *PluginConf,
	ipRes *ipamResult,
	hostName, guestName string,
	hostMac, guestMac string,
	hostMTU, guestMTU int,
	netns string,
) *type100.Result {
	result := &type100.Result{
		CNIVersion: pluginConf.CNIVersion,
		Interfaces: []*type100.Interface{
			{
				Name:    hostName,
				Mac:     hostMac,
				Mtu:     hostMTU,
				Sandbox: "",
			},
			{
				Name:    guestName,
				Mac:     guestMac,
				Mtu:     guestMTU,
				Sandbox: netns,
			},
		},
	}
	if ipRes != nil {
		ipConfig := &type100.IPConfig{
			Address:   *ipRes.subnet,
			Gateway:   ipRes.gateway,
			Interface: type100.Int(1), // index into Interfaces (guest veth)
		}
		result.IPs = []*type100.IPConfig{ipConfig}
		if len(ipRes.routes) > 0 {
			result.Routes = make([]*types.Route, 0, len(ipRes.routes))
			for _, dst := range ipRes.routes {
				result.Routes = append(result.Routes, &types.Route{
					Dst: *dst,
				})
			}
		}
	}
	return result
}

// buildVethResult handles veth-specific result building: host-device
// delegation, IPAM, guest interface reading, and result printing.
// Returns the IPAM result for BGP advertisement, or nil if no IPAM.
func buildVethResult(
	args *skel.CmdArgs,
	pluginConf *PluginConf,
	hostName, guestName string,
	hostMac string,
	hostMTU int,
) (*ipamResult, error) {
	// Only call host-device ADD if the guest interface is still in the host
	// namespace. If a prior attempt already moved it to the container netns but
	// failed at a later step, we must not try to move it again.
	if _, linkErr := netlink.LinkByName(guestName); linkErr == nil {
		// Clean up any stale interface in the container netns left by a
		// previous run. The host-device plugin renames the moved interface
		// to args.IfName, so a prior run may have left that name behind.
		if err := cleanupContainerNetns(args.Netns, args.IfName); err != nil {
			return nil, fmt.Errorf("cleanup container netns: %w", err)
		}
		if err := hostDevice("ADD", args, pluginConf); err != nil {
			return nil, fmt.Errorf("host-device ADD: %w", err)
		}
	}

	// Configure IP address on the guest interface inside the container netns.
	var ipamResult *ipamResult
	if pluginConf.IPAM.Type != "" || enableLocalIPAM {
		result, err := configureIPAM(args, pluginConf, args.IfName)
		if err != nil {
			return nil, fmt.Errorf("configure IPAM: %w", err)
		}
		ipamResult = result
	}

	// Read guest veth attributes inside the container netns.
	guestMac, guestMTU, err := readGuestInterface(args.Netns, args.IfName)
	if err != nil {
		return nil, fmt.Errorf("read guest interface: %w", err)
	}
	result := buildResult(pluginConf, ipamResult, hostName, args.IfName, hostMac, guestMac, hostMTU, guestMTU, args.Netns)
	if err := types.PrintResult(result, cniVersion100); err != nil {
		return nil, fmt.Errorf("print CNI result: %w", err)
	}

	return ipamResult, nil
}

// buildTapResult constructs the CNI result for tap mode: a single host
// interface with no IPAM or guest endpoint.
func buildTapResult(
	pluginConf *PluginConf,
	hostName, hostMac string,
	hostMTU int,
) *type100.Result {
	return &type100.Result{
		CNIVersion: pluginConf.CNIVersion,
		Interfaces: []*type100.Interface{
			{
				Name:    hostName,
				Mac:     hostMac,
				Mtu:     hostMTU,
				Sandbox: "",
			},
		},
	}
}

// configureIPAM allocates a subnet and configures the guest interface inside the
// container network namespace. When enableLocalIPAM is true and no explicit
// ipam block is configured, falls back to a built-in pool allocator using
// default pool CIDR and subnet length.
func configureIPAM(args *skel.CmdArgs, pluginConf *PluginConf, guestName string) (*ipamResult, error) {
	var pool *ipam.PoolAllocator
	var subnet *net.IPNet
	var err error

	// When local IPAM is enabled but no explicit ipam type is configured,
	// use the built-in pool allocator with defaults.
	poolType := pluginConf.IPAM.Type
	if poolType == "" && enableLocalIPAM {
		poolType = ipamTypePool
	}

	switch poolType {
	case "static":
		alloc := ipam.NewStaticAllocator()
		allocIP, err := alloc.Allocate(args.ContainerID, pluginConf.IPAM.StaticIP)
		if err != nil {
			return nil, fmt.Errorf("allocate static IP: %w", err)
		}
		subnet = &net.IPNet{
			IP:   allocIP,
			Mask: net.CIDRMask(64, 128),
		}
	case ipamTypePool:
		poolCIDR := pluginConf.IPAM.Pool
		gateway := pluginConf.IPAM.Gateway
		subnetLen := pluginConf.IPAM.SubnetLen
		if poolCIDR == "" && enableLocalIPAM {
			poolCIDR = localIPAMDefaultPool
		}
		if subnetLen == 0 && enableLocalIPAM {
			subnetLen = localIPAMDefaultSubnetLen
		}
		pool, err = ipam.NewPoolAllocator(poolCIDR, gateway, subnetLen)
		if err != nil {
			return nil, fmt.Errorf("create pool allocator: %w", err)
		}
		subnet, err = pool.Allocate(args.ContainerID)
		if err != nil {
			return nil, fmt.Errorf("allocate from pool: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown IPAM type: %s", pluginConf.IPAM.Type)
	}

	var gateway net.IP
	if pool != nil {
		gateway = pool.Gateway()
	}

	var routes []*net.IPNet
	if gateway != nil {
		defaultRoute := &net.IPNet{
			IP:   net.IPv6zero,
			Mask: net.CIDRMask(0, 128),
		}
		routes = append(routes, defaultRoute)
	}

	if err := configureInterfaceInNetns(args.Netns, guestName, subnet, gateway); err != nil {
		return nil, err
	}

	return &ipamResult{
		subnet:  subnet,
		gateway: gateway,
		routes:  routes,
	}, nil
}

// configureInterfaceInNetns applies an IP address and routes to the guest
// interface inside the container network namespace.
func configureInterfaceInNetns(netnsPath, ifName string, ipNet *net.IPNet, gateway net.IP) error {
	containerNS, err := ns.GetNS(netnsPath)
	if err != nil {
		return fmt.Errorf("get container netns %q: %w", netnsPath, err)
	}
	defer containerNS.Close() //nolint:errcheck // netns close on teardown

	return containerNS.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("create netlink handle: %w", err)
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("find guest interface %q: %w", ifName, err)
		}

		if err := handle.AddrAdd(link, &netlink.Addr{IPNet: ipNet}); err != nil {
			return fmt.Errorf("add IP %s to %q: %w", ipNet, ifName, err)
		}

		if err := handle.LinkSetUp(link); err != nil {
			return fmt.Errorf("set interface %q up: %w", ifName, err)
		}

		// Install default route via gateway.
		if gateway != nil {
			defaultRoute := &netlink.Route{
				Dst:       nil, // default route
				Gw:        gateway,
				LinkIndex: link.Attrs().Index,
			}
			if err := handle.RouteAdd(defaultRoute); err != nil {
				return fmt.Errorf("add default route via %s: %w", gateway, err)
			}
		}

		return nil
	})
}

// readGuestInterface reads the MAC and MTU of the guest veth endpoint
// inside the container network namespace.
func readGuestInterface(netnsPath, ifName string) (string, int, error) {
	containerNS, err := ns.GetNS(netnsPath)
	if err != nil {
		return "", 0, fmt.Errorf("open container netns %s: %w", netnsPath, err)
	}
	defer containerNS.Close() //nolint:errcheck // netns close on teardown

	var mac string
	var mtu int
	err = containerNS.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("create netlink handle: %w", err)
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("find interface %s: %w", ifName, err)
		}
		attrs := link.Attrs()
		mac = attrs.HardwareAddr.String()
		mtu = attrs.MTU
		return nil
	})
	return mac, mtu, err
}

// cleanupContainerNetns removes any existing interface with the given name
// from the container network namespace. This is needed to handle stale state
// from previous CNI ADD runs that may have left interfaces behind.
func cleanupContainerNetns(netnsPath, ifName string) error {
	containerNS, err := ns.GetNS(netnsPath)
	if err != nil {
		return fmt.Errorf("get container netns %q: %w", netnsPath, err)
	}
	defer containerNS.Close() //nolint:errcheck // netns close on teardown

	return containerNS.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("create netlink handle: %w", err)
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName(ifName)
		if err != nil {
			// Interface does not exist in container netns — nothing to clean up.
			return nil
		}
		if err := handle.LinkDel(link); err != nil {
			return fmt.Errorf("delete stale interface %q in container netns: %w", ifName, err)
		}
		return nil
	})
}

// deallocateIPAM releases the IPAM allocation for the given container.
// Reads the allocated subnet from the BGPAdvertisement CRD annotation, then
// deallocates it from the in-memory pool. When enableLocalIPAM is true and
// no explicit ipam block is configured, uses the default pool CIDR.
func deallocateIPAM(args *skel.CmdArgs, pluginConf *PluginConf, k8s client.Client) {
	// Look up the allocated subnet from the BGPAdvertisement annotation.
	subnetCIDR := getAllocatedSubnetFromCRD(args.ContainerID, pluginConf, k8s)
	if subnetCIDR == "" {
		// No allocation found — either allocation was never completed,
		// or the advertisement was already deleted. Nothing to clean up.
		return
	}

	ipamType := pluginConf.IPAM.Type
	if ipamType == "" && enableLocalIPAM {
		ipamType = ipamTypePool
	}

	switch ipamType {
	case ipamTypePool:
		poolCIDR := pluginConf.IPAM.Pool
		if poolCIDR == "" && enableLocalIPAM {
			poolCIDR = localIPAMDefaultPool
		}
		pa, err := ipam.NewPoolAllocator(poolCIDR, pluginConf.IPAM.Gateway, pluginConf.IPAM.SubnetLen)
		if err != nil {
			// Pool creation failed — allocation was never completed, nothing to clean up.
			return
		}
		pa.Deallocate(subnetCIDR)
	case "static":
		// Static allocations don't need deallocation.
	}
}

// getAllocatedSubnetFromCRD reads the allocated subnet for the given container
// from the BGPAdvertisement CRD annotation. Returns empty string if not found.
func getAllocatedSubnetFromCRD(containerID string, pluginConf *PluginConf, k8s client.Client) string {
	namespace := pluginConf.Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}

	ctx, cancel := context.WithTimeout(context.Background(), cniTimeout)
	defer cancel()

	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bgpAdvertisementName(pluginConf.VPC, pluginConf.VPCAttachment),
			Namespace: namespace,
		},
	}
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(adv), adv); err != nil {
		return ""
	}

	return adv.Annotations[subnetAnnotationKey(containerID)]
}

// configureHostVethGateway assigns the gateway address as a /128 host address on
// the host-side veth and installs an explicit pod-subnet route into the VRF table.
//
// Using /128 (not the pod subnet mask) prevents the kernel from auto-creating a
// subnet-router anycast entry in the VRF local table. When the pod address equals
// the subnet network address the anycast absorbs seg6local-decapped inner packets
// before they reach the pod veth. The explicit subnet route replaces the one the
// kernel would have created from the wider mask.
func configureHostVethGateway(vpc, vpcAttachment string, res *ipamResult) error {
	if res == nil || res.gateway == nil {
		return nil
	}
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("get host veth %q: %w", hostName, err)
	}
	gwNet := &net.IPNet{IP: res.gateway, Mask: net.CIDRMask(128, 128)}
	if err := netlink.AddrAdd(hostLink, &netlink.Addr{IPNet: gwNet}); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("add gateway address to host veth %q: %w", hostName, err)
		}
	}
	tableID, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		return fmt.Errorf("get VRF table ID for pod subnet route: %w", err)
	}
	if err := netlink.RouteReplace(&netlink.Route{
		Dst:       res.subnet,
		LinkIndex: hostLink.Attrs().Index,
		Table:     int(tableID),
	}); err != nil {
		return fmt.Errorf("add pod subnet route to VRF table: %w", err)
	}
	return nil
}

// setupSRv6Ingress installs the End.DT46 SRv6 ingress decap route for the given
// locator and returns the SID string. Returns empty string when locator is empty.
func setupSRv6Ingress(locator, vpcHex, vpcAttHex string) (string, error) {
	if locator == "" {
		return "", nil
	}
	sid, err := intf.EncodeSRv6Endpoint(locator, vpcHex, vpcAttHex)
	if err != nil {
		return "", fmt.Errorf("encode SRv6 endpoint: %w", err)
	}
	if err := srv6.RouteIngressAdd(sid); err != nil {
		return "", fmt.Errorf("add SRv6 ingress route: %w", err)
	}
	return sid, nil
}

type HostDevicePluginConf struct {
	types.PluginConf
	Device string `json:"device"`
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
	if _, err := invokeExec.ExecPlugin(
		context.Background(), hostDeviceExecutable(), conf,
		invokeArgs.AsEnv(),
	); err != nil {
		return err
	}
	return nil
}
