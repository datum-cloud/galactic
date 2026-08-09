// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cnibgp implements galactic-bgp, the SRv6/BGP/eBPF publish plugin
// in the galactic CNI chain. It is chain-invoked (per CNI conflist order)
// after the master plugin (galactic-cni or galactic-tap-cni), not called
// as a library — it has zero kernel-interface dependency: every address it
// advertises comes from prevResult (see prevresult.go), never from a
// runtime call into the interface it doesn't own. Host-interface gateway
// configuration lives in internal/cni/hostgw instead, called directly by
// the master plugins, for exactly this reason.
package cnibgp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/cni/crdnames"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// maxRetries is the maximum number of retry attempts for transient k8s API
// errors during the BGP state publish phase. The total number of attempts
// is maxRetries+1 (initial + retries).
const maxRetries = 2

// ifaceTypeVeth and ifaceTypeTap are the two values publishConfig.ifaceType
// accepts, inferred from prevResult (see prevresult.go) rather than a
// config field.
const (
	ifaceTypeVeth = "veth"
	ifaceTypeTap  = "tap"
)

// publishConfig carries the subset of this plugin's own config that
// publishing needs.
type publishConfig struct {
	vpc, vpcAttachment string
	// ifaceType selects the eBPF vrf_table egress_kind (veth vs tap) — see
	// egressKindForInterfaceType. Inferred from prevResult, never a config
	// field.
	ifaceType string
}

// publishResult records what publishBGPState actually created, so cmdAdd
// can fold it into its own rollback tracker.
type publishResult struct {
	vrfInstanceCreated   bool
	advertisementCreated bool
	// ebpfRegistered, ebpfBlock, and ebpfArgument record the eBPF uSID
	// datapath's vrf_table registration, if one actually happened (the
	// BGPRouter may not be configured, in which case ebpfRegistered stays
	// false). See unregisterEBPFDatapath for rolling this back.
	ebpfRegistered bool
	ebpfBlock      uint64
	ebpfArgument   uint16
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

// ipamAdvertisementPrefixes derives the BGPAdvertisement prefixes to
// originate, plus the per-family values to record in the annotations, from
// ipamResult (reconstructed from prevResult — see prevresult.go). ipamResult
// is nil when the attachment has no IPAM allocation (e.g. a tap workload
// that manages its own addressing), in which case prefixes is empty.
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

// publishBGPState creates the BGPVRFInstance and BGPAdvertisement CRDs and
// registers the eBPF uSID datapath entry, with retry on transient k8s API
// errors. Assumes the host gateway is already configured (internal/cni/
// hostgw, called by the master plugin before this ever runs).
func publishBGPState(
	args *skel.CmdArgs, cfg publishConfig, nodeName, namespace string, ipamResult *cniipam.IPAMResult,
	vpcHex string, k8s client.Client,
) (publishResult, error) {
	var result publishResult
	err := retryK8sOps(cniTimeout, func(ctx context.Context) error {
		bgp, err := lookupBGPRouter(ctx, k8s, nodeName, namespace)
		if err != nil {
			return err
		}

		vrfID, err := allocateArgument(
			ctx, k8s, namespace, bgp.routerName, crdnames.BGPVRFInstanceName(cfg.vpc, cfg.vpcAttachment))
		if err != nil {
			return err
		}

		rtValue, err := routeTarget(int64(bgp.asNumber), vpcHex)
		if err != nil {
			return fmt.Errorf("compute route target: %w", err)
		}

		vrfName := crdnames.BGPVRFInstanceName(cfg.vpc, cfg.vpcAttachment)
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
		result.vrfInstanceCreated = true
		slog.Debug("BGP: BGPVRFInstance applied", "name", vrfName, "namespace", namespace,
			"vrfID", vrfID, "routeTarget", rtValue, "router", bgp.routerName)

		if err := checkArgumentCollision(ctx, k8s, namespace, bgp.routerName, vrfName, vrfID); err != nil {
			return err
		}

		registered, ebpfBlock, err := registerEBPFDatapath(
			bgp, cfg.vpc, cfg.vpcAttachment, cfg.ifaceType, uint16(vrfID), ebpfPinDir)
		if err != nil {
			return fmt.Errorf("register eBPF uSID datapath: %w", err)
		}
		if registered {
			result.ebpfRegistered = true
			result.ebpfBlock = ebpfBlock
			result.ebpfArgument = uint16(vrfID)
		}

		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crdnames.BGPAdvertisementName(cfg.vpc, cfg.vpcAttachment),
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
		result.advertisementCreated = true
		slog.Debug("BGP: BGPAdvertisement applied", "name", adv.Name, "namespace", namespace,
			"prefixes", mergedPrefixes, "addedPrefixes", prefixes, "containerID", args.ContainerID)

		slog.Info("ADD: BGP state published", "containerID", args.ContainerID,
			"vpc", cfg.vpc, "vpcAttachment", cfg.vpcAttachment)
		return nil
	})
	return result, err
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

	egressKind, err := egressKindForInterfaceType(ifaceType)
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

// egressKindForInterfaceType maps a "veth"/"tap" interface type string to the
// vrf_table egress_kind value usid.c's step 9 uses to pick between
// bpf_redirect_peer (veth, crosses into the container's netns) and plain
// bpf_redirect (tap, which never leaves this netns).
func egressKindForInterfaceType(ifaceType string) (uint32, error) {
	switch ifaceType {
	case ifaceTypeVeth:
		return usidmap.EgressKindVeth, nil
	case ifaceTypeTap:
		return usidmap.EgressKindTap, nil
	default:
		return 0, fmt.Errorf("unknown interface type %q", ifaceType)
	}
}

// unregisterEBPFDatapath removes the vrf_table entry registerEBPFDatapath
// wrote for this (block, argument) pair, from cmdAdd's failed-ADD rollback
// path. Idempotent: not an error if the entry is already gone.
//
// expectedVRFTableID must be this attachment's own VRF table id (recomputed
// by the caller via vrf.TableID). Only deletes the entry when it still
// resolves to expectedVRFTableID, and leaves it alone otherwise — see
// resourceTracker.cleanup's doc comment for the race this guards against.
func unregisterEBPFDatapath(block uint64, argument uint16, expectedVRFTableID uint32, pinDir string) error {
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
