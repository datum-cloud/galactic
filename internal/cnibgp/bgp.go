// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cnibgp implements galactic-bgp, the SRv6/BGP/eBPF publish plugin in
// the galactic CNI chain. It is chain-invoked after the master plugin
// (galactic-veth or galactic-tap), never called as a library. Every address it
// advertises comes from prevResult, so it never configures the interface it
// does not own; host-interface gateway configuration lives in internal/hostgw,
// called directly by the master plugins.
//
// Two narrow exceptions touch kernel state here. registerEBPFDatapath resolves
// the host-side interface's ifindex with a read-only netlink.LinkByName to key
// its ifindex_vrf_table row, because the (Block, Argument) values that row
// pairs with are known only at that call site, and the interface name is
// deterministic. installNAT66EgressRoute writes a real kernel route, because
// the optional routing plugin in this chain may be absent from a conflist and
// the route must exist wherever a NAT66 shard is configured.
package cnibgp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// maxRetries is the number of retry attempts for transient Kubernetes API
// errors during the publish phase. Total attempts are maxRetries+1.
const maxRetries = 2

// ifaceTypeVeth and ifaceTypeTap are the values publishConfig.ifaceType
// accepts. Inferred from prevResult, not from a config field.
const (
	ifaceTypeVeth = "veth"
	ifaceTypeTap  = "tap"
)

// publishConfig carries the subset of this plugin's own config that
// publishing needs.
type publishConfig struct {
	vpc, vpcAttachment string
	// ifaceType selects the vrf_table egress_kind, veth or tap. Inferred from
	// prevResult, never a config field.
	ifaceType string
}

// publishResult records what publishBGPState created, so cmdAdd can fold it
// into its rollback tracker. It records nothing about the vrf_table
// registration: that entry is shared by every attachment on this VPC and node,
// so a failed ADD must never unregister it.
type publishResult struct {
	advertisementCreated bool
	// vrfInstanceCreated is true only when this ADD's CreateOrUpdate for the
	// shared BGPVRFInstance actually created it, meaning this is the first
	// attachment on this VPC and node rather than one reusing a live sibling's
	// CRD. Rollback may delete the CRD only in that case.
	vrfInstanceCreated bool
	// sid is the computed SRv6 uSID for this attachment. Valid only when this
	// node's BGPRouter has an SRv6 locator and node ID configured, the same
	// condition registerEBPFDatapath skips on. Consumed by the EndpointSlice
	// publish step, which runs after publishBGPState returns rather than
	// inside its retry closure.
	sid netip.Addr
}

// isTransientError reports whether err may resolve on retry: API server
// unavailable, a timeout, or a network blip. Validation errors, not-found, and
// other permanent failures return false.
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

// retryK8sOps runs fn up to maxRetries+1 times, backing off between attempts
// that fail with a transient Kubernetes API error. Each call gets a context
// bounded by timeout. A non-transient error returns immediately.
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

// routeTarget returns the route target in "ASN:NN" form, from the low 32 bits
// of the 16-bit hex VPC identifier vpcHex. Every node in the same VRF derives
// the same value, which is what scopes route import and export to a VPC.
func routeTarget(asNumber int64, vpcHex string) (string, error) {
	v, err := strconv.ParseUint(vpcHex, 16, 64)
	if err != nil {
		return "", fmt.Errorf("parse VPC hex %q: %w", vpcHex, err)
	}
	return fmt.Sprintf("%d:%d", asNumber, uint32(v)), nil
}

// allocateArgument returns the 12-bit Argument value for the VPC attachment
// named vrfInstanceName under routerName. An existing BGPVRFInstance of that
// name keeps its value, which makes a repeat ADD idempotent. Otherwise the
// lowest value in [uformat.ArgumentMin, uformat.ArgumentMax] unused by that
// router's other instances is returned.
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

// checkArgumentCollision reports whether another BGPVRFInstance on the same
// router already holds vrfID, which happens when two first attachments race
// onto the same free slot. Any other instance still holding the value counts
// as a collision.
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
// attachment's pod subnets: one IPv6 prefix, plus an IPv4 prefix when the
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

// ipamAdvertisementPrefixes derives the prefixes to originate, plus the
// per-family values recorded in annotations, from ipamResult. A nil ipamResult
// means the attachment has no IPAM allocation, such as a tap workload managing
// its own addressing, and yields no prefixes.
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

// allAdvertisedPrefixes derives the full prefix set for a BGPAdvertisement
// from every subnet annotation on it, not just from the container being
// processed, because one BGPAdvertisement can be shared by several containers.
//
// The result is deduplicated by CIDR value. spec.Prefixes is
// x-kubernetes-list-type=set, so the API server rejects a duplicate outright.
// A replacement pod usually gets the same subnet its predecessor held, whose
// per-container annotation can still be present, and without this dedup those
// two identical values would both land in Prefixes and fail every ADD retry
// for the attachment.
func allAdvertisedPrefixes(annotations map[string]string) []string {
	seen := make(map[string]struct{})
	var prefixes []string
	addUnique := func(p string) {
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		prefixes = append(prefixes, p)
	}
	for key, value := range annotations {
		switch {
		case strings.HasPrefix(key, crdnames.AnnotationAllocatedSubnetIPv6+"."):
			addUnique(value)
		case strings.HasPrefix(key, crdnames.AnnotationAllocatedSubnetIPv4+"."):
			addUnique(value + "/32")
		}
	}
	sort.Strings(prefixes)
	return prefixes
}

// netNSExistsFn is a variable so tests can override it without needing a
// real netns bind-mount under /var/run/netns.
var netNSExistsFn = gc.NetNSExists

// pruneDeadContainerAnnotations removes every per-container annotation, netns
// and allocated subnet alike, whose recorded netns path no longer exists on
// this node.
//
// Garbage collection deletes only the whole CRD, and only once every container
// that ever referenced it is gone, which never happens while the attachment
// still has a live pod. Without pruning, annotations on a frequently churned
// attachment grow without bound, and a replacement pod reusing a dead
// sibling's subnet leaves allAdvertisedPrefixes' dedup as the only thing
// preventing a rejected update. This runs on the write path that already holds
// the current annotation set, so it self-heals the moment a container
// attaches.
func pruneDeadContainerAnnotations(annotations map[string]string) {
	prefix := crdnames.AnnotationNetNS + "."
	for key, netnsPath := range annotations {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if netNSExistsFn(netnsPath) {
			continue
		}
		containerIDSuffix := strings.TrimPrefix(key, prefix)
		delete(annotations, key)
		delete(annotations, crdnames.AnnotationAllocatedSubnetIPv6+"."+containerIDSuffix)
		delete(annotations, crdnames.AnnotationAllocatedSubnetIPv4+"."+containerIDSuffix)
	}
}

// publishBGPState creates the BGPVRFInstance and BGPAdvertisement CRDs and
// registers the eBPF uSID datapath entry, retrying transient Kubernetes API
// errors. The host gateway must already be configured by the master plugin.
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

		// Keyed by (vpc, node) rather than (vpc, attachment): the kernel VRF
		// is shared by every attachment on this VPC on this node, so they all
		// converge on one CRD and one Argument.
		vrfName := crdnames.BGPVRFInstanceName(cfg.vpc, nodeName)
		vrfID, err := allocateArgument(ctx, k8s, namespace, bgp.routerName, vrfName)
		if err != nil {
			return err
		}

		rtValue, err := routeTarget(int64(bgp.asNumber), vpcHex)
		if err != nil {
			return fmt.Errorf("compute route target: %w", err)
		}

		vrfInst := &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      vrfName,
				Namespace: namespace,
			},
		}
		op, err := controllerutil.CreateOrUpdate(ctx, k8s, vrfInst, func() error {
			vrfInst.Spec = buildVRFInstanceSpec(bgp.routerName, rtValue, vrfID)
			return nil
		})
		if err != nil {
			return fmt.Errorf("apply BGPVRFInstance: %w", err)
		}
		if op == controllerutil.OperationResultCreated {
			result.vrfInstanceCreated = true
		}
		slog.Debug("BGP: BGPVRFInstance applied", "name", vrfName, "namespace", namespace,
			"vrfID", vrfID, "routeTarget", rtValue, "router", bgp.routerName, "operation", op)

		// A collision means allocateArgument's read-then-write raced another
		// VPC's first attachment onto the same free slot. That is possible
		// only on a genuine create, never when reusing a live sibling's CRD,
		// whose VRFID was validated when it was created.
		if err := checkArgumentCollision(ctx, k8s, namespace, bgp.routerName, vrfName, vrfID); err != nil {
			return err
		}

		// Computed ahead of registerEBPFDatapath so this attachment's own
		// prefixes can be registered as local pass-through egress routes.
		prefixes, ipv6Subnet, ipv4Addr := ipamAdvertisementPrefixes(ipamResult)

		// Nothing to publish when this node's router has no SRv6 locator or
		// node ID, so leave result.sid invalid rather than compute a SID for
		// an attachment that has no SRv6 endpoint.
		if bgp.srv6Locator != "" && bgp.nodeID != 0 {
			sid, err := srv6.ComputeSID(bgp.srv6Locator, bgp.nodeID, vrfID, bgpv1alpha1.SRv6FunctionEndDT46)
			if err != nil {
				return fmt.Errorf("compute SRv6 uSID: %w", err)
			}
			result.sid = sid
		}

		// Not tracked for rollback: the vrf_table entry is shared by every
		// attachment on this VPC and node, like the BGPVRFInstance above.
		if _, err := registerEBPFDatapath(
			bgp, cfg.vpc, cfg.vpcAttachment, cfg.ifaceType, uint16(vrfID), ebpfPinDir, prefixes,
		); err != nil {
			return fmt.Errorf("register eBPF uSID datapath: %w", err)
		}

		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crdnames.BGPAdvertisementName(cfg.vpc, cfg.vpcAttachment, nodeName),
				Namespace: namespace,
			},
		}
		var mergedPrefixes []string
		advOp, err := controllerutil.CreateOrUpdate(ctx, k8s, adv, func() error {
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
			// The attachment's config carries no "ipam" block, such as a tap
			// workload managing its own addressing. Mark the advertisement so
			// its empty spec.prefixes reads as intentional rather than as
			// addressing that failed to arrive. Cleared once any ADD for this
			// attachment does carry an allocation.
			if ipamResult == nil {
				adv.Annotations[crdnames.AnnotationNoAddressing] = crdnames.AnnotationNoAddressingValue
			} else {
				delete(adv.Annotations, crdnames.AnnotationNoAddressing)
			}
			// Prune dead siblings first, so a replaced pod's stale annotation
			// cannot collide with this ADD's usually identical prefix.
			pruneDeadContainerAnnotations(adv.Annotations)
			mergedPrefixes = allAdvertisedPrefixes(adv.Annotations)
			adv.Spec = buildAdvertisementSpec(bgp.routerName, rtValue, mergedPrefixes, vrfID)
			return nil
		})
		if err != nil {
			return fmt.Errorf("apply BGPAdvertisement: %w", err)
		}
		// Gated on a genuine create, like vrfInstanceCreated above. A
		// BGPAdvertisement is reused across pod churn on the same attachment,
		// so marking it created on a mere update would let rollback delete one
		// still backing a live container's route.
		if advOp == controllerutil.OperationResultCreated {
			result.advertisementCreated = true
		}
		slog.Debug("BGP: BGPAdvertisement applied", "name", adv.Name, "namespace", namespace,
			"prefixes", mergedPrefixes, "addedPrefixes", prefixes, "containerID", args.ContainerID, "operation", advOp)

		slog.Info("ADD: BGP state published", "containerID", args.ContainerID,
			"vpc", cfg.vpc, "vpcAttachment", cfg.vpcAttachment)
		return nil
	})
	return result, err
}

// registerEBPFDatapath registers this attachment against the eBPF uSID
// datapath's pinned maps. registered is false with a nil error only when this
// router has no SRv6 locator or node ID configured, meaning SRv6 is
// deliberately not set up for it. Any other failure returns an error.
//
// prefixes are this attachment's IPAM-derived CIDRs, computed by the caller.
// Each is registered as a local pass-through egress_route_table entry in this
// VPC's VRF, so the attachment's own prefix wins the longest-prefix lookup
// over the VRF's ::/0 NAT66 default. Without them, a sibling attachment in the
// same VRF on the same node, reachable over an ordinary connected route, has
// its traffic hijacked by that default and redirected toward a NAT66 shard
// instead of delivered locally. An empty slice is valid and registers
// nothing.
func registerEBPFDatapath(
	bgp bgpConfig, vpc, vpcAttachment, ifaceType string, argument uint16, pinDir string, prefixes []string,
) (registered bool, err error) {
	if bgp.srv6Locator == "" || bgp.nodeID == 0 {
		return false, nil
	}

	if bgp.nodeID < uformat.NodeIDMin || bgp.nodeID > uformat.NodeIDMax {
		return false, fmt.Errorf("eBPF registration: nodeID %d out of range [%#x,%#x]",
			bgp.nodeID, uint16(uformat.NodeIDMin), uint16(uformat.NodeIDMax))
	}

	egressKind, err := egressKindForInterfaceType(ifaceType)
	if err != nil {
		return false, fmt.Errorf("determine eBPF egress kind: %w", err)
	}

	prefix, err := netip.ParsePrefix(bgp.srv6Locator)
	if err != nil {
		return false, fmt.Errorf("parse SRv6 locator %q for eBPF registration: %w", bgp.srv6Locator, err)
	}
	block, err := uformat.Block(prefix.Addr())
	if err != nil {
		return false, fmt.Errorf("derive eBPF uSID Block from locator %q: %w", bgp.srv6Locator, err)
	}

	vrfTableID, err := vrf.TableID(vpc)
	if err != nil {
		return false, fmt.Errorf("look up VRF table id for eBPF registration: %w", err)
	}

	// Installs or refreshes this VRF's NAT66 default egress route. The
	// optional routing plugin in this chain may be absent from a given
	// conflist, and this route must exist wherever a shard is configured, so
	// it is written here.
	if err := installNAT66EgressRoute(vrfTableID); err != nil {
		return false, fmt.Errorf("install NAT66 default egress route: %w", err)
	}

	if err := registerLocalEgressRoutes(pinDir, vrfTableID, prefixes); err != nil {
		return false, fmt.Errorf("register local pass-through egress route: %w", err)
	}

	// The host-side interface's ifindex keys this attachment's
	// ifindex_vrf_table row. See the package doc comment for why this
	// read-only netlink call is an accepted exception.
	hostIfindex, err := hostInterfaceIndex(vpc, vpcAttachment)
	if err != nil {
		return false, fmt.Errorf("resolve host interface ifindex for eBPF registration: %w", err)
	}

	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		return false, fmt.Errorf("open pinned eBPF uSID maps: %w", err)
	}
	defer func() { _ = closer.Close() }()

	if err := registry.Locator.Register(block, uint16(bgp.nodeID)); err != nil {
		return false, fmt.Errorf("register eBPF locator_table entry: %w", err)
	}
	if err := registry.Function.Register(block, uformat.FunctionEndDT46); err != nil {
		return false, fmt.Errorf("register eBPF function_table entry: %w", err)
	}

	if err := registry.VRF.Register(block, argument, vrfTableID, egressKind); err != nil {
		return false, fmt.Errorf("register eBPF vrf_table entry: %w", err)
	}

	ifindexTable, ifindexCloser, err := ifindexvrfmap.OpenPinned(pinDir)
	if err != nil {
		return false, fmt.Errorf("open pinned eBPF ifindex_vrf_table: %w", err)
	}
	defer func() { _ = ifindexCloser.Close() }()
	if err := ifindexTable.Register(hostIfindex, block, argument); err != nil {
		return false, fmt.Errorf("register eBPF ifindex_vrf_table entry: %w", err)
	}

	// Attach usid_egress to this attachment's host-side interface. This is
	// what translates a reply's source address on the way back out.
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	if err := attachUsidEgress(pinDir, hostName); err != nil {
		return false, fmt.Errorf("attach eBPF usid_egress to host interface %q: %w", hostName, err)
	}

	// Register this node's SRv6 source address. A per-node constant rather
	// than a per-attachment one, but idempotent and cheap enough to redo on
	// every ADD instead of adding a once-per-node lifecycle hook.
	//
	// Non-fatal, unlike the registrations above. Resolving the address needs a
	// converged main-table IPv6 default route, which a node can transiently
	// lack before its underlay session comes up. Failing every pod attach on
	// the node until then is worse than the alternative, where only traffic
	// needing the route fails. usid_egress fails open for exactly this gap,
	// and a later ADD succeeds once the route exists.
	if err := registerNodeSourceAddress(pinDir); err != nil {
		slog.Warn("ADD: could not register this node's own SRv6 source address; "+
			"egress routing will fail open until this succeeds", "err", err)
	}

	// Register this node's fabric-uplink next hop. Same per-node,
	// redo-on-every-ADD, non-fatal shape as registerNodeSourceAddress above,
	// for the same reason: resolving it needs a converged underlay neighbor.
	// usid_egress falls through to egress_route_table while the entry is
	// absent.
	if err := registerPublicUplink(pinDir); err != nil {
		slog.Warn("ADD: could not register this node's own public uplink; "+
			"a DSR backend's VIP-sourced reply traffic will fail open to egress_route_table until this succeeds",
			"err", err)
	}

	return true, nil
}

// registerNodeSourceAddress resolves this node's underlay-facing SRv6 source
// address and writes it into node_src_addr_table, the value usid_egress stamps
// into every outer header it pushes. While the entry is missing, every
// egress_route_table hit fails open instead of encapsulating, so no installed
// egress route can carry traffic. pinDir is the bpffs directory holding the
// pinned map. Failure here does not fail the CNI ADD; see the call site.
func registerNodeSourceAddress(pinDir string) error {
	addr, err := srv6.ResolveNodeSourceAddress()
	if err != nil {
		return fmt.Errorf("resolve node source address: %w", err)
	}
	nodeSrc, closer, err := egressroutemap.OpenPinnedNodeSourceAddress(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned node_src_addr_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	return nodeSrc.Set(addr)
}

// registerPublicUplink resolves this node's fabric-uplink next hop and writes
// it into public_uplink_table, the value usid_egress redirects a DSR backend's
// VIP-sourced reply toward once apply_vip_xlat has rewritten that reply's
// source address, bypassing egress_route_table's NAT66 default. Without it,
// such a reply is re-translated through a NAT66 shard instead of reaching the
// real client. pinDir is the bpffs directory holding the pinned map. Failure
// here does not fail the CNI ADD; see the call site.
func registerPublicUplink(pinDir string) error {
	linkIndex, dmac, smac, err := srv6.ResolvePublicUplink()
	if err != nil {
		return fmt.Errorf("resolve public uplink: %w", err)
	}
	uplink, closer, err := egressroutemap.OpenPinnedPublicUplink(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned public_uplink_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	return uplink.Set(linkIndex, dmac, smac)
}

// attachUsidEgress loads usid_egress from its pin and attaches it to
// ifaceName's TC ingress hook. attach.Load pins the program there so a
// short-lived process like this one can reach it without reloading.
//
// The forward path works without this, because nothing on it depends on a
// reply leaving with its source address translated. Only a full round trip
// needs it, and a missing attachment stalls the handshake, with the client
// discarding replies that arrive from an address it never contacted.
//
// Idempotent, so it is safe to call on every attachment ADD.
func attachUsidEgress(pinDir, ifaceName string) error {
	program, err := ebpf.LoadPinnedProgram(filepath.Join(pinDir, attach.UsidEgressPinName), nil)
	if err != nil {
		return fmt.Errorf("load pinned usid_egress program: %w", err)
	}
	defer func() { _ = program.Close() }()

	return attach.AttachEgress(program, ifaceName)
}

// registerLocalEgressRoutes registers each of prefixes as a local pass-through
// egress_route_table entry in Linux VRF table vrfTableID, so an attachment's
// own prefix outranks the VRF's NAT66 default. pinDir is the bpffs directory
// holding the pinned map. Idempotent, so a repeat ADD, or a sibling
// re-registering an unrelated prefix in the same VRF, is safe.
//
// It opens the map through egressroutemap rather than the srv6 wrappers, which
// resolve their pin directory from a package var instead of a parameter:
// registerEBPFDatapath is designed to run against an arbitrary pinDir.
//
// prefixes are the CIDR strings ipamAdvertisementPrefixes already produced, so
// a parse failure means that function emitted something unparseable. It is a
// hard error here rather than a silent skip.
func registerLocalEgressRoutes(pinDir string, vrfTableID uint32, prefixes []string) error {
	if len(prefixes) == 0 {
		return nil
	}
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned egress_route_table: %w", err)
	}
	defer func() { _ = closer.Close() }()

	for _, p := range prefixes {
		_, prefix, err := net.ParseCIDR(p)
		if err != nil {
			return fmt.Errorf("parse prefix %q: %w", p, err)
		}
		if err := table.RegisterPassThrough(vrfTableID, prefix); err != nil {
			return fmt.Errorf("register local pass-through route for %s: %w", p, err)
		}
	}
	return nil
}

// installNAT66EgressRoute installs or refreshes vrfTableID's default egress
// route toward the configured NAT66 shards. Idempotent, so it is safe on every
// attachment ADD sharing this VRF.
//
// No shard configured is not an error: the shard list parses to an empty slice
// and srv6.EgressDefaultRouteAdd no-ops. A shard SID that is invalid, or that
// has no reachable route yet, fails this attachment's ADD rather than leaving
// the VRF with no egress at all.
func installNAT66EgressRoute(vrfTableID uint32) error {
	// cniConfig is nil until InitCNIConfig runs, which several unit tests
	// calling registerEBPFDatapath directly never do. Treated as "no shard
	// configured" rather than a panic.
	if cniConfig == nil {
		return nil
	}
	shardSIDs, err := parseShardSIDs(cniConfig.NAT66ShardSIDs)
	if err != nil {
		return fmt.Errorf("parse %s: %w", config.EnvCNINAT66ShardSIDs, err)
	}
	if len(shardSIDs) == 0 {
		return nil
	}
	return srv6.EgressDefaultRouteAdd(vrfTableID, shardSIDs)
}

// parseShardSIDs splits a comma-separated NAT66 shard SID list into addresses,
// trimming whitespace and skipping blank entries, so a trailing comma or stray
// space in the operator-supplied value does not fail every attachment ADD in
// the cluster. An entry that survives trimming but is not a valid IP address
// is a real misconfiguration and fails loudly.
func parseShardSIDs(raw string) ([]net.IP, error) {
	var sids []net.IP
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		sid := net.ParseIP(part)
		if sid == nil {
			return nil, fmt.Errorf("invalid NAT66 shard SID %q", part)
		}
		sids = append(sids, sid)
	}
	return sids, nil
}

// hostInterfaceIndex resolves this attachment's host-side veth or tap
// interface's kernel ifindex by name, using the same deterministic name the
// master plugin used to create it, so no value needs threading through
// prevResult to find it again.
func hostInterfaceIndex(vpc, vpcAttachment string) (uint32, error) {
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		return 0, fmt.Errorf("look up host interface %q: %w", hostName, err)
	}
	return uint32(link.Attrs().Index), nil
}

// egressKindForInterfaceType maps a "veth" or "tap" interface type to the
// vrf_table egress_kind value the datapath uses to choose between
// bpf_redirect_peer, which crosses into the container's netns, and plain
// bpf_redirect, which does not.
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
