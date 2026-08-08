// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cnibgp holds the BGP/SRv6/eBPF publish logic shared by every
// master plugin in the galactic CNI chain (galactic-cni, veth;
// galactic-tap-cni, tap) — interface-agnostic aside from
// EgressKindForInterfaceType's eBPF egress_kind lookup.
//
// Like internal/cniipam, this is a plain library today, imported directly by
// the master plugins rather than a chain-invoked plugin of its own — that
// lands in a follow-up step (cmd/galactic-bgp, new CHECK logic for the CRDs/
// eBPF state this package writes, and replacing PublishConfig.InterfaceType
// with an inference from prevResult.interfaces[] shape so no config field
// carries it at all). Callers pass in a k8s client already scoped to a
// scheme that includes go.datum.net/network/api/v1alpha1 — this package
// never builds its own client.
package cnibgp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/cni/crdnames"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// cniTimeout bounds each individual k8s API retry attempt in
// PublishBGPStateK8s.
const cniTimeout = 10 * time.Second

// maxRetries is the maximum number of retry attempts for transient k8s API
// errors during the BGP state publish phase. The total number of attempts
// is maxRetries+1 (initial + retries).
const maxRetries = 2

// ifaceTypeVeth and ifaceTypeTap are the two values PublishConfig.InterfaceType
// accepts. Duplicated here (rather than imported) since they're plain
// protocol-level string literals every caller already knows independently.
const (
	ifaceTypeVeth = "veth"
	ifaceTypeTap  = "tap"
)

// PublishConfig carries the subset of a caller's own CNI config that BGP
// publish needs. Each master plugin passes its own values in.
type PublishConfig struct {
	VPC           string
	VPCAttachment string
	// InterfaceType selects the eBPF vrf_table egress_kind (veth vs tap) —
	// see EgressKindForInterfaceType. A follow-up step replaces this with an
	// inference from prevResult.interfaces[] shape instead of a config field.
	InterfaceType string
}

// PublishResult records what PublishBGPState/PublishBGPStateK8s actually
// created, so callers can fold it into their own rollback bookkeeping — the
// rollback for a partially-failed ADD still belongs to whichever master
// plugin's ADD is failing, even though the BGP publish logic itself lives
// here.
type PublishResult struct {
	VRFInstanceCreated   bool
	AdvertisementCreated bool
	// EBPFRegistered, EBPFBlock, and EBPFArgument record the eBPF uSID
	// datapath's vrf_table registration, if one actually happened (the
	// BGPRouter may not be configured, in which case EBPFRegistered stays
	// false). See UnregisterEBPFDatapath for rolling this back.
	EBPFRegistered bool
	EBPFBlock      uint64
	EBPFArgument   uint16
}

// isTransientError reports whether err is a transient failure that may
// resolve itself on retry (API server unavailable, timeout, network blip).
// Returns false for validation errors, not-found, and other permanent
// failures that should not be retried.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	unwrapped := errors.Unwrap(err)
	if unwrapped != nil {
		if errors.Is(unwrapped, context.DeadlineExceeded) || errors.Is(unwrapped, context.Canceled) {
			return true
		}
	}
	if apierrors.IsServiceUnavailable(err) ||
		apierrors.IsInternalError(err) ||
		apierrors.IsServerTimeout(err) ||
		apierrors.IsTooManyRequests(err) {
		return true
	}
	if netErr, ok := unwrapped.(interface{ Temporary() bool }); ok && netErr.Temporary() {
		return true
	}
	return false
}

// retryK8sOps runs fn with up to maxRetries+1 attempts, retrying on
// transient k8s API errors with exponential backoff. The context passed to
// fn has a timeout derived from timeout. Non-transient errors are returned
// immediately without retry.
func retryK8sOps(timeout time.Duration, fn func(ctx context.Context) error) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 100 * time.Millisecond
			time.Sleep(backoff)
			slog.Warn("Retrying k8s operations", "attempt", attempt+1, "backoff", backoff)
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		lastErr = fn(ctx)
		cancel()
		if lastErr == nil {
			return nil
		}
		if !isTransientError(lastErr) {
			return lastErr
		}
	}
	return lastErr
}

// bgpConfig holds the BGP values a caller needs to populate BGP CRDs.
type bgpConfig struct {
	asNumber    uint32
	routerName  string
	srv6Locator string
	nodeID      int32
}

// routeTarget returns the RT in "ASN:NN" format using the low 32 bits of the
// VPC identifier. All nodes in the same VRF produce the same value, enabling
// VPC-scoped route import/export. vpcHex is the 16-bit hex VPC identifier.
func routeTarget(asNumber int64, vpcHex string) (string, error) {
	v, err := strconv.ParseUint(vpcHex, 16, 64)
	if err != nil {
		return "", fmt.Errorf("parse VPC hex %q: %w", vpcHex, err)
	}
	return fmt.Sprintf("%d:%d", asNumber, uint32(v)), nil
}

// allocateArgument returns the 12-bit Argument value for the VPC attachment
// named vrfInstanceName under routerName: the value already registered if a
// BGPVRFInstance with that exact name exists (an idempotent CNI ADD retry,
// or a repeat ADD on an attachment that is already live), or — if none does
// — the lowest unused value in [uformat.ArgumentMin, uformat.ArgumentMax]
// among that router's other BGPVRFInstances.
func allocateArgument(
	ctx context.Context, k8s client.Client, namespace, routerName, vrfInstanceName string,
) (int32, error) {
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return 0, fmt.Errorf("list BGPVRFInstances in namespace %s: %w", namespace, err)
	}

	used := make(map[int32]struct{}, len(list.Items))
	for _, inst := range list.Items {
		if inst.Spec.RouterRef == nil || inst.Spec.RouterRef.Name != routerName {
			continue
		}
		if inst.Name == vrfInstanceName {
			return inst.Spec.VRFID, nil
		}
		used[inst.Spec.VRFID] = struct{}{}
	}

	for arg := int32(uformat.ArgumentMin); arg <= int32(uformat.ArgumentMax); arg++ {
		if _, ok := used[arg]; !ok {
			return arg, nil
		}
	}
	return 0, fmt.Errorf("allocate SID argument: router %s has no free Argument in [%#x,%#x] (all %d in use)",
		routerName, uint16(uformat.ArgumentMin), uint16(uformat.ArgumentMax), len(used))
}

// checkArgumentCollision detects whether a race condition occurred where
// another BGPVRFInstance on the same router was assigned the same VRFID
// concurrently. Any other instance found still holding this VRFID is
// treated as a collision.
func checkArgumentCollision(
	ctx context.Context, k8s client.Client, namespace, routerName, vrfName string, vrfID int32,
) error {
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("list BGPVRFInstances to verify argument uniqueness: %w", err)
	}
	for _, inst := range list.Items {
		if inst.Spec.RouterRef == nil || inst.Spec.RouterRef.Name != routerName {
			continue
		}
		if inst.Name != vrfName && inst.Spec.VRFID == vrfID {
			return fmt.Errorf("argument collision: VRFID %d claimed by both %s and %s, retrying", vrfID, inst.Name, vrfName)
		}
	}
	return nil
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
	default:
		return bgpConfig{}, fmt.Errorf("ambiguous BGP config: %d BGPRouters target node %s in namespace %s",
			len(matches), nodeName, namespace)
	}

	slog.Debug("BGP: router matched", "nodeName", nodeName, "router", matches[0].Name,
		"asNumber", matches[0].Spec.LocalASN, "srv6Locator", matches[0].Spec.SRv6Locator, "nodeID", matches[0].Spec.NodeID)

	return bgpConfig{
		asNumber:    uint32(matches[0].Spec.LocalASN),
		routerName:  matches[0].Name,
		srv6Locator: matches[0].Spec.SRv6Locator,
		nodeID:      matches[0].Spec.NodeID,
	}, nil
}

// buildVRFInstanceSpec constructs the BGPVRFInstanceSpec for a VPC attachment.
func buildVRFInstanceSpec(routerName, rtValue string, vrfID int32) bgpv1alpha1.BGPVRFInstanceSpec {
	return bgpv1alpha1.BGPVRFInstanceSpec{
		RouterTarget: bgpv1alpha1.RouterTarget{
			RouterRef: &bgpv1alpha1.RouterRef{Name: routerName},
		},
		VRFID:              vrfID,
		ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: rtValue}},
		ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: rtValue}},
	}
}

// buildAdvertisementSpec constructs the BGPAdvertisementSpec for a VPC
// attachment's pod subnet(s) — one IPv6 prefix, plus an IPv4 prefix when the
// attachment is dual-stack.
func buildAdvertisementSpec(
	routerName, rtValue string, prefixes []string, vrfID int32,
) bgpv1alpha1.BGPAdvertisementSpec {
	function := bgpv1alpha1.SRv6FunctionEndDT46
	bgpPrefixes := make([]bgpv1alpha1.Prefix, len(prefixes))
	for i, p := range prefixes {
		bgpPrefixes[i] = bgpv1alpha1.Prefix(p)
	}
	return bgpv1alpha1.BGPAdvertisementSpec{
		RouterRef:     bgpv1alpha1.RouterRef{Name: routerName},
		AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
		Prefixes:      bgpPrefixes,
		Communities:   []bgpv1alpha1.Community{bgpv1alpha1.Community(rtValue)},
		VRFID:         &vrfID,
		Function:      &function,
	}
}

// PublishBGPState configures the host gateway, sets up the SRv6 ingress
// route, and creates the BGPVRFInstance and BGPAdvertisement CRDs. The host
// gateway configuration is interface-agnostic (works for both veth and
// tap) — callers that already invoked ConfigureHostGateway themselves
// (tap mode, which needs the gateway configured before printing its own CNI
// result) should call PublishBGPStateK8s directly instead, to avoid
// configuring it twice.
func PublishBGPState(
	args *skel.CmdArgs, cfg PublishConfig, nodeName, namespace string, ipamResult *cniipam.IPAMResult,
	guestHWAddr net.HardwareAddr, k8s client.Client,
) (PublishResult, error) {
	if err := ConfigureHostGateway(cfg.VPC, cfg.VPCAttachment, ipamResult, guestHWAddr); err != nil {
		return PublishResult{}, err
	}

	vpcHex, err := intf.Base62ToHex(cfg.VPC)
	if err != nil {
		return PublishResult{}, fmt.Errorf("decode VPC: %w", err)
	}

	return PublishBGPStateK8s(args, cfg, nodeName, namespace, ipamResult, vpcHex, k8s)
}

// ipamAdvertisementPrefixes derives the BGPAdvertisement prefixes to
// originate, plus the per-family values to record in the annotations, from
// ipamResult. ipamResult is nil when the attachment has no IPAM allocation
// (e.g. a tap workload that manages its own addressing), in which case
// prefixes is empty.
func ipamAdvertisementPrefixes(ipamResult *cniipam.IPAMResult) (prefixes []string, ipv6Subnet, ipv4Addr string) {
	if ipamResult == nil {
		return nil, "", ""
	}
	if ipamResult.IPv6Subnet != nil {
		ipv6Subnet = ipamResult.IPv6Subnet.String()
		prefixes = append(prefixes, ipv6Subnet)
	}
	if ipamResult.IPv4Address != nil {
		ipv4Addr = ipamResult.IPv4Address.String()
		prefixes = append(prefixes, ipv4Addr+"/32")
	}
	return prefixes, ipv6Subnet, ipv4Addr
}

// allAdvertisedPrefixes derives the full set of BGP-advertised prefixes for
// a BGPAdvertisement CRD from every subnet annotation currently present on
// it, rather than from just the container currently being processed — see
// crdnames' doc comment for why a single BGPAdvertisement can be shared by
// more than one container.
func allAdvertisedPrefixes(annotations map[string]string) []string {
	var prefixes []string
	for key, value := range annotations {
		switch {
		case strings.HasPrefix(key, crdnames.AnnotationAllocatedSubnetIPv6+"."):
			prefixes = append(prefixes, value)
		case strings.HasPrefix(key, crdnames.AnnotationAllocatedSubnetIPv4+"."):
			prefixes = append(prefixes, value+"/32")
		}
	}
	sort.Strings(prefixes)
	return prefixes
}

// PublishBGPStateK8s creates the BGPVRFInstance and BGPAdvertisement CRDs
// with retry on transient k8s API errors. The host gateway must already be
// configured before calling this (via ConfigureHostGateway, or PublishBGPState
// which calls it first).
func PublishBGPStateK8s(
	args *skel.CmdArgs, cfg PublishConfig, nodeName, namespace string, ipamResult *cniipam.IPAMResult,
	vpcHex string, k8s client.Client,
) (PublishResult, error) {
	var result PublishResult
	err := retryK8sOps(cniTimeout, func(ctx context.Context) error {
		bgp, err := lookupBGPRouter(ctx, k8s, nodeName, namespace)
		if err != nil {
			return err
		}

		vrfID, err := allocateArgument(
			ctx, k8s, namespace, bgp.routerName, crdnames.BGPVRFInstanceName(cfg.VPC, cfg.VPCAttachment))
		if err != nil {
			return err
		}

		rtValue, err := routeTarget(int64(bgp.asNumber), vpcHex)
		if err != nil {
			return fmt.Errorf("compute route target: %w", err)
		}

		vrfName := crdnames.BGPVRFInstanceName(cfg.VPC, cfg.VPCAttachment)
		vrfInst := &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      vrfName,
				Namespace: namespace,
			},
		}
		_, err = controllerutil.CreateOrUpdate(ctx, k8s, vrfInst, func() error {
			vrfInst.Spec = buildVRFInstanceSpec(bgp.routerName, rtValue, vrfID)
			return nil
		})
		if err != nil {
			return fmt.Errorf("apply BGPVRFInstance: %w", err)
		}
		result.VRFInstanceCreated = true
		slog.Debug("BGP: BGPVRFInstance applied", "name", vrfName, "namespace", namespace,
			"vrfID", vrfID, "routeTarget", rtValue, "router", bgp.routerName)

		if err := checkArgumentCollision(ctx, k8s, namespace, bgp.routerName, vrfName, vrfID); err != nil {
			return err
		}

		registered, ebpfBlock, err := registerEBPFDatapath(
			bgp, cfg.VPC, cfg.VPCAttachment, cfg.InterfaceType, uint16(vrfID), attach.PinDir)
		if err != nil {
			return fmt.Errorf("register eBPF uSID datapath: %w", err)
		}
		if registered {
			result.EBPFRegistered = true
			result.EBPFBlock = ebpfBlock
			result.EBPFArgument = uint16(vrfID)
		}

		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crdnames.BGPAdvertisementName(cfg.VPC, cfg.VPCAttachment),
				Namespace: namespace,
			},
		}
		prefixes, ipv6Subnet, ipv4Addr := ipamAdvertisementPrefixes(ipamResult)
		var mergedPrefixes []string
		_, err = controllerutil.CreateOrUpdate(ctx, k8s, adv, func() error {
			if adv.Annotations == nil {
				adv.Annotations = make(map[string]string)
			}
			adv.Annotations[crdnames.NetNSKey(args.ContainerID)] = args.Netns
			if ipv6Subnet != "" {
				adv.Annotations[crdnames.SubnetKeyIPv6(args.ContainerID)] = ipv6Subnet
			}
			if ipv4Addr != "" {
				adv.Annotations[crdnames.SubnetKeyIPv4(args.ContainerID)] = ipv4Addr
			}
			mergedPrefixes = allAdvertisedPrefixes(adv.Annotations)
			adv.Spec = buildAdvertisementSpec(bgp.routerName, rtValue, mergedPrefixes, vrfID)
			return nil
		})
		if err != nil {
			return fmt.Errorf("apply BGPAdvertisement: %w", err)
		}
		result.AdvertisementCreated = true
		slog.Debug("BGP: BGPAdvertisement applied", "name", adv.Name, "namespace", namespace,
			"prefixes", mergedPrefixes, "addedPrefixes", prefixes, "containerID", args.ContainerID)

		slog.Info("ADD: BGP state published", "containerID", args.ContainerID,
			"vpc", cfg.VPC, "vpcAttachment", cfg.VPCAttachment)
		return nil
	})
	return result, err
}

// routeConflicts reports whether an existing route conflicts with the desired
// pod-subnet route. A conflict occurs when the destination matches but the
// gateway or link index differs.
func routeConflicts(existing, desired *netlink.Route) bool {
	if existing.Dst == nil || desired.Dst == nil {
		return false
	}
	if existing.Dst.String() != desired.Dst.String() {
		return false
	}
	if (existing.Gw != nil) != (desired.Gw != nil) {
		return true
	}
	if existing.Gw != nil && !existing.Gw.Equal(desired.Gw) {
		return true
	}
	if existing.LinkIndex != 0 && desired.LinkIndex != 0 && existing.LinkIndex != desired.LinkIndex {
		return true
	}
	return false
}

// ConfigureHostGateway assigns each configured family's gateway address as a
// host address (/128 for IPv6, /32 for IPv4 on veth) on the host-side
// interface (veth or tap) and installs an explicit pod-subnet route for that
// family into the VRF table. IPv4 is skipped entirely when the attachment is
// IPv6-only. guestHWAddr is nil for tap attachments.
func ConfigureHostGateway(vpc, vpcAttachment string, res *cniipam.IPAMResult, guestHWAddr net.HardwareAddr) error {
	if res == nil {
		return nil
	}
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("get host interface %q: %w", hostName, err)
	}
	tableID, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		return fmt.Errorf("get VRF table ID for pod subnet route: %w", err)
	}

	if res.IPv6Gateway != nil {
		gwNet := &net.IPNet{IP: res.IPv6Gateway, Mask: net.CIDRMask(128, 128)}
		if err := installGatewayRoute(hostLink, gwNet, res.IPv6Subnet, netlink.FAMILY_V6, int(tableID), 0); err != nil {
			return err
		}
		if guestHWAddr != nil {
			if err := installGatewayNeighbor(hostLink, res.IPv6Subnet.IP, netlink.FAMILY_V6, guestHWAddr); err != nil {
				return err
			}
		}
	}
	if res.IPv4Gateway != nil {
		ipv4Mask, addrFlags := ipv4GatewayAddrParams(hostLink)
		gwNet := &net.IPNet{IP: res.IPv4Gateway, Mask: ipv4Mask}
		ipv4Subnet := &net.IPNet{IP: res.IPv4Address, Mask: net.CIDRMask(32, 32)}
		if err := installGatewayRoute(hostLink, gwNet, ipv4Subnet, netlink.FAMILY_V4, int(tableID), addrFlags); err != nil {
			return err
		}
		if guestHWAddr != nil {
			if err := installGatewayNeighbor(hostLink, res.IPv4Address, netlink.FAMILY_V4, guestHWAddr); err != nil {
				return err
			}
		}
	}
	return nil
}

// installGatewayNeighbor installs a permanent neighbor table entry mapping
// podIP to guestHWAddr on hostLink — see the design plan's note on why the
// eBPF ingress datapath needs this pre-installed rather than relying on
// dynamic ARP/NDP.
func installGatewayNeighbor(hostLink netlink.Link, podIP net.IP, family int, guestHWAddr net.HardwareAddr) error {
	neigh := &netlink.Neigh{
		LinkIndex:    hostLink.Attrs().Index,
		Family:       family,
		State:        netlink.NUD_PERMANENT,
		IP:           podIP,
		HardwareAddr: guestHWAddr,
	}
	if err := netlink.NeighSet(neigh); err != nil {
		return fmt.Errorf("add permanent neighbor %s -> %s on host interface %q: %w",
			podIP, guestHWAddr, hostLink.Attrs().Name, err)
	}
	return nil
}

// ipv4GatewayAddrParams returns the IPv4 gateway mask and netlink address
// flags to use for hostLink. Tap interfaces get a /25 with
// IFA_F_NOPREFIXROUTE; veth interfaces keep the plain /32 host address with
// no flags.
func ipv4GatewayAddrParams(hostLink netlink.Link) (net.IPMask, int) {
	if _, isTap := hostLink.(*netlink.Tuntap); isTap {
		return net.CIDRMask(25, 32), unix.IFA_F_NOPREFIXROUTE
	}
	return net.CIDRMask(32, 32), 0
}

// installGatewayRoute assigns gwNet as a host address on hostLink and
// installs an explicit route to subnet into the given VRF table, for one
// address family. Idempotent.
func installGatewayRoute(hostLink netlink.Link, gwNet, subnet *net.IPNet, family, tableID, addrFlags int) error {
	hostName := hostLink.Attrs().Name
	if err := netlink.AddrAdd(hostLink, &netlink.Addr{IPNet: gwNet, Flags: addrFlags}); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("add gateway address %s to host interface %q: %w", gwNet, hostName, err)
		}
	}

	desiredRoute := &netlink.Route{
		Dst:       subnet,
		LinkIndex: hostLink.Attrs().Index,
		Table:     tableID,
	}

	existingRoutes, err := netlink.RouteListFiltered(
		family,
		&netlink.Route{Table: tableID},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return fmt.Errorf("list routes in VRF table: %w", err)
	}
	for _, r := range existingRoutes {
		if r.Dst == nil {
			continue
		}
		if r.Dst.String() != desiredRoute.Dst.String() {
			continue
		}
		if routeConflicts(&r, desiredRoute) {
			return fmt.Errorf(
				"existing route %v to %s conflicts with desired route %v",
				r, desiredRoute.Dst, desiredRoute,
			)
		}
		return nil
	}

	if err := netlink.RouteAdd(desiredRoute); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return nil
		}
		return fmt.Errorf("add pod subnet route to VRF table: %w", err)
	}
	return nil
}

// registerEBPFDatapath registers this attachment against the eBPF uSID
// datapath's pinned maps. registered is false, with a nil error, only when
// this router has no srv6Locator/nodeID configured at all — SRv6 is
// intentionally not set up for this attachment. Any other failure is
// returned as an error.
func registerEBPFDatapath(
	bgp bgpConfig, vpc, vpcAttachment, ifaceType string, argument uint16, pinDir string,
) (registered bool, block uint64, err error) {
	if bgp.srv6Locator == "" || bgp.nodeID == 0 {
		return false, 0, nil
	}

	if bgp.nodeID < uformat.NodeIDMin || bgp.nodeID > uformat.NodeIDMax {
		return false, 0, fmt.Errorf("eBPF registration: nodeID %d out of range [%#x,%#x]",
			bgp.nodeID, uint16(uformat.NodeIDMin), uint16(uformat.NodeIDMax))
	}

	egressKind, err := EgressKindForInterfaceType(ifaceType)
	if err != nil {
		return false, 0, fmt.Errorf("determine eBPF egress kind: %w", err)
	}

	prefix, err := netip.ParsePrefix(bgp.srv6Locator)
	if err != nil {
		return false, 0, fmt.Errorf("parse SRv6 locator %q for eBPF registration: %w", bgp.srv6Locator, err)
	}
	block, err = uformat.Block(prefix.Addr())
	if err != nil {
		return false, 0, fmt.Errorf("derive eBPF uSID Block from locator %q: %w", bgp.srv6Locator, err)
	}

	vrfTableID, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		return false, 0, fmt.Errorf("look up VRF table id for eBPF registration: %w", err)
	}

	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		return false, 0, fmt.Errorf("open pinned eBPF uSID maps: %w", err)
	}
	defer func() { _ = closer.Close() }()

	if err := registry.Locator.Register(block, uint16(bgp.nodeID)); err != nil {
		return false, 0, fmt.Errorf("register eBPF locator_table entry: %w", err)
	}
	if err := registry.Function.Register(block, uformat.FunctionEndDT46); err != nil {
		return false, 0, fmt.Errorf("register eBPF function_table entry: %w", err)
	}

	if err := registry.VRF.Register(block, argument, vrfTableID, egressKind); err != nil {
		return false, 0, fmt.Errorf("register eBPF vrf_table entry: %w", err)
	}
	return true, block, nil
}

// EgressKindForInterfaceType maps a "veth"/"tap" interface type string to the
// vrf_table egress_kind value usid.c's step 9 uses to pick between
// bpf_redirect_peer (veth, crosses into the container's netns) and plain
// bpf_redirect (tap, which never leaves this netns).
func EgressKindForInterfaceType(ifaceType string) (uint32, error) {
	switch ifaceType {
	case ifaceTypeVeth, "":
		return usidmap.EgressKindVeth, nil
	case ifaceTypeTap:
		return usidmap.EgressKindTap, nil
	default:
		return 0, fmt.Errorf("unknown interface type %q", ifaceType)
	}
}

// UnregisterEBPFDatapath removes the vrf_table entry registerEBPFDatapath
// wrote for this (block, argument) pair, from a caller's failed-ADD
// rollback path. Idempotent: not an error if the entry is already gone.
//
// expectedVRFTableID must be this attachment's own VRF table id (recomputed
// by the caller via vrf.TableID). Only deletes the entry when it still
// resolves to expectedVRFTableID, and leaves it alone otherwise — see the
// original resourceTracker.cleanup's doc comment for the race this guards
// against.
func UnregisterEBPFDatapath(block uint64, argument uint16, expectedVRFTableID uint32, pinDir string) error {
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned eBPF uSID maps: %w", err)
	}
	defer func() { _ = closer.Close() }()

	entry, ok, err := registry.VRF.Get(block, argument)
	if err != nil {
		return fmt.Errorf("read eBPF vrf_table entry before unregister: %w", err)
	}
	if !ok {
		return nil
	}
	if entry.VRFTableID != expectedVRFTableID {
		slog.Warn("Rollback: eBPF vrf_table entry no longer belongs to this attachment, leaving it in place",
			"block", block, "argument", argument,
			"expectedVRFTableID", expectedVRFTableID, "currentVRFTableID", entry.VRFTableID)
		return nil
	}

	if err := registry.VRF.Unregister(block, argument); err != nil {
		return fmt.Errorf("unregister eBPF vrf_table entry: %w", err)
	}
	return nil
}
