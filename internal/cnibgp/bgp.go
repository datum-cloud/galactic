// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cnibgp implements galactic-bgp, the SRv6/BGP/eBPF publish plugin
// in the galactic CNI chain. It is chain-invoked (per CNI conflist order)
// after the master plugin (galactic-veth or galactic-tap), not called
// as a library — it has zero kernel-interface *configuration* dependency:
// every address it advertises comes from prevResult (see prevresult.go),
// never from a runtime call into the interface it doesn't own.
// Host-interface gateway configuration lives in internal/hostgw instead,
// called directly by the master plugins, for exactly this reason.
//
// One narrow, deliberate exception: registerEBPFDatapath (bgp.go) resolves
// this attachment's own host-side interface's ifindex via a read-only
// netlink.LinkByName lookup, to key its ifindex_vrf_table registration
// (internal/plumbing/ebpf/ifindexvrfmap) on it. This is not a configuration
// call — it neither creates, moves, nor mutates the interface the master
// plugin already built, only reads its already-assigned kernel identity —
// and the interface's name is fully deterministic
// (intf.GenerateInterfaceNameHost(vpc, vpcAttachment), the same helper the
// master plugin itself used to create it), so no prevResult plumbing is
// needed to learn it. Kept here rather than threaded back through
// prevResult because the (Block, Argument) values ifindex_vrf_table's row
// pairs with are only known at this call site (registerEBPFDatapath is
// where vrf_table's own registration for this same attachment already
// happens), mirroring the design note's own point-6 guidance to key
// ifindex_vrf_table at that exact call site.
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
// can fold it into its own rollback tracker. There is no record of the eBPF
// vrf_table registration: it's shared by every attachment on this VPC/node
// (see crdnames.BGPVRFInstanceName) with no "did I just create this"
// signal the way a k8s object's CreateOrUpdate result gives us, so a failed
// ADD must never unregister it — see resourceTracker.cleanup's doc comment.
type publishResult struct {
	advertisementCreated bool
	// vrfInstanceCreated is true only when this ADD's own CreateOrUpdate
	// call for the (shared) BGPVRFInstance reported OperationResultCreated —
	// i.e. this is the first attachment on this VPC/node, not one reusing an
	// already-live sibling's CRD. See resourceTracker.cleanup's doc comment
	// for why that distinction, not "CreateOrUpdate succeeded" alone, is
	// what makes rollback-deletion safe.
	vrfInstanceCreated bool
	// sid is the computed SRv6 uSID for this attachment (see
	// internal/plumbing/srv6.ComputeSID), valid (netip.Addr.IsValid()) only
	// when this node's BGPRouter has SRv6Locator/nodeID configured — the
	// same condition registerEBPFDatapath's own skip case checks. Consumed
	// by the EndpointSlice publish step (endpointslice.go), which runs as
	// its own step after publishBGPState returns, not folded into its retry
	// closure — see Phase 4's rollback-risk note in the #854 plan for why.
	sid netip.Addr
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
//
// The result is deduplicated by CIDR value. spec.Prefixes is
// x-kubernetes-list-type=set, so a duplicate value is rejected outright by
// the API server: when a replaced pod's IPAM allocation lands on the same
// subnet its predecessor held (the common case — IPAM re-allocates the same
// subnet for the same vpcAttachment identity), the predecessor's own
// per-containerID annotation is often still present (see
// pruneDeadContainerAnnotations's doc comment for why that can outlast the
// pod), and without this dedup the two identical-value annotations would
// both land in Prefixes and permanently fail every CNI ADD retry for this
// attachment. Deduplicating here is a hard backstop independent of whether
// pruning above has run yet.
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

// pruneDeadContainerAnnotations removes every per-container annotation
// (netns plus allocated-subnet-ipv6/ipv4) belonging to a containerID whose
// recorded netns path no longer exists on this node.
//
// Without this, a replaced pod's dead sibling containerID's annotations
// survive on the shared BGPAdvertisement forever: galactic-router's GC
// controller (internal/gc.CollectOrphanedCRDs) only ever deletes the whole
// CRD, and only once every container that has ever referenced it is dead —
// which never happens while the vpcAttachment has any live pod, i.e.
// exactly the pod-replacement case this exists to handle. So the set of
// per-container annotations on a long-lived, frequently-churned
// vpcAttachment (e.g. a Deployment) grows without bound, and whenever a
// replacement pod's IPAM allocation reuses a dead sibling's subnet (the
// common case), allAdvertisedPrefixes' dedup is the only thing standing
// between that and a rejected update. Pruning here, on the write path that
// already holds this attachment's current annotation set, is what actually
// keeps it bounded and self-heals the moment a new container attaches —
// independent of GC's periodic tick, which for this case never fires at
// all.
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

		// The BGPVRFInstance name is keyed by (vpc, node) — not (vpc,
		// vpcAttachment) — since the underlying kernel VRF is shared by every
		// attachment on this VPC on this node. allocateArgument's own
		// idempotent-by-name lookup means every attachment sharing a VPC/node
		// converges on the same CRD and the same Argument.
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

		// A collision here means allocateArgument's read-then-write raced
		// against another VPC's first attachment on this same node landing
		// on the same "lowest free slot" before either write was visible to
		// the other — only possible when this CreateOrUpdate was a genuine
		// create (result.vrfInstanceCreated), never when reusing an
		// already-live sibling's CRD (whose VRFID was already validated
		// when it was first created). Rollback needs that distinction to
		// safely self-heal this race — see resourceTracker.cleanup.
		if err := checkArgumentCollision(ctx, k8s, namespace, bgp.routerName, vrfName, vrfID); err != nil {
			return err
		}

		// Computed here, ahead of registerEBPFDatapath below, so this
		// attachment's own prefix(es) can be registered as local
		// pass-through egress_route_table entries — see
		// registerEBPFDatapath's own doc comment for why.
		prefixes, ipv6Subnet, ipv4Addr := ipamAdvertisementPrefixes(ipamResult)

		// Reuses registerEBPFDatapath's own "SRv6 not configured, skip
		// silently" sentinel: if this node's router has no
		// srv6Locator/nodeID configured, there's nothing to publish, so
		// leave result.sid at its zero value (IsValid() == false) rather
		// than computing a SID for an attachment that has no SRv6 endpoint.
		if bgp.srv6Locator != "" && bgp.nodeID != 0 {
			sid, err := srv6.ComputeSID(bgp.srv6Locator, bgp.nodeID, vrfID, bgpv1alpha1.SRv6FunctionEndDT46)
			if err != nil {
				return fmt.Errorf("compute SRv6 uSID: %w", err)
			}
			result.sid = sid
		}

		// The return values aren't tracked for rollback: the vrf_table entry
		// they'd describe is shared by every attachment on this VPC/node,
		// same as the BGPVRFInstance above — see resourceTracker.cleanup's
		// doc comment for why a failed ADD must never unregister it.
		if _, err := registerEBPFDatapath(
			bgp, cfg.vpc, cfg.vpcAttachment, cfg.ifaceType, uint16(vrfID), ebpfPinDir, prefixes,
		); err != nil {
			return fmt.Errorf("register eBPF uSID datapath: %w", err)
		}

		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crdnames.BGPAdvertisementName(cfg.vpc, cfg.vpcAttachment),
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
			// ipamResult is nil when this attachment's config carries no
			// "ipam" block at all (e.g. a tap workload managing its own
			// addressing) — mark the advertisement so its empty
			// spec.prefixes reads as intentional, not as addressing that
			// silently failed to arrive (#342). Cleared the moment any ADD
			// for this attachment does carry an allocation.
			if ipamResult == nil {
				adv.Annotations[crdnames.AnnotationNoAddressing] = crdnames.AnnotationNoAddressingValue
			} else {
				delete(adv.Annotations, crdnames.AnnotationNoAddressing)
			}
			// Prune dead siblings before merging: a replaced pod's stale
			// annotation must not be allowed to collide with this ADD's own
			// (often identical, since IPAM re-allocates the same subnet for
			// the same vpcAttachment identity) prefix — see
			// pruneDeadContainerAnnotations's doc comment.
			pruneDeadContainerAnnotations(adv.Annotations)
			mergedPrefixes = allAdvertisedPrefixes(adv.Annotations)
			adv.Spec = buildAdvertisementSpec(bgp.routerName, rtValue, mergedPrefixes, vrfID)
			return nil
		})
		if err != nil {
			return fmt.Errorf("apply BGPAdvertisement: %w", err)
		}
		// Gated on OperationResultCreated, mirroring vrfInstanceCreated's
		// existing pattern exactly: a BGPAdvertisement is reused (updated,
		// not created) across pod churn on the same vpcAttachment, so
		// marking it created on every successful write — including a mere
		// update of an already-live sibling's CRD — would let
		// resourceTracker.cleanup delete a BGPAdvertisement still backing a
		// different, live container's route if a later ADD step fails. See
		// the #854 plan's Phase 4 rollback-risk note.
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
// datapath's pinned maps. registered is false, with a nil error, only when
// this router has no srv6Locator/nodeID configured at all — SRv6 is
// intentionally not set up for this attachment. Any other failure is
// returned as an error.
//
// prefixes is this attachment's own IPAM-derived prefix(es)
// (ipamAdvertisementPrefixes' first return value, computed by the caller
// ahead of this call) — each is registered as a local pass-through
// egress_route_table entry (registerLocalEgressRoutes) in this VPC's
// VRF, so this attachment's own prefix always wins the LPM lookup over a shorter
// entry (in practice, the VRF's own ::/0 NAT66 default installed just
// above by installNAT66EgressRoute). Without this, a sibling attachment
// sharing this same VRF on this node — with a perfectly good kernel
// connected route already routing between them — has that traffic
// silently hijacked by the ::/0 default and redirected toward a NAT66
// shard SID instead of ever being delivered locally: found live in
// containerlab's ns30 fixture (two attachments, one VPC, one node), the
// same class of bug as usid_egress's own multicast/link-local carve-out,
// just for ordinary same-VRF unicast peers instead of NDP. nil/empty is
// valid (an attachment with no "ipam" block at all, e.g. a
// self-addressing tap workload — see ipamAdvertisementPrefixes' own doc
// comment) and simply registers nothing.
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

	// Installs (or refreshes) this VRF's NAT66 default egress route --
	// see installNAT66EgressRoute's own doc comment. A second, deliberate
	// exception to this package's doc comment's "zero kernel-interface
	// configuration dependency" claim, alongside registerEBPFDatapath's
	// existing ifindex_vrf_table registration: unlike that one, this
	// mutates a real kernel route, not just an eBPF map, but the
	// alternative (routing table setup) plugin in this chain
	// (internal/cniroute/galactic-route) is optional, and this route must
	// exist whenever any shard is configured, regardless of whether a
	// given conflist happens to include galactic-route.
	if err := installNAT66EgressRoute(vrfTableID); err != nil {
		return false, fmt.Errorf("install NAT66 default egress route: %w", err)
	}

	if err := registerLocalEgressRoutes(pinDir, vrfTableID, prefixes); err != nil {
		return false, fmt.Errorf("register local pass-through egress route: %w", err)
	}

	// The host-side interface's own ifindex, needed to key this
	// attachment's ifindex_vrf_table row below — see this package's own
	// doc comment for why this one read-only netlink call is an accepted
	// exception to galactic-bgp's otherwise prevResult-only design.
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

	// Attach usid_egress to this attachment's own host-side interface --
	// see attachUsidEgress's own doc comment for why this was, until now,
	// entirely missing: it's a real, previously-undiscovered gap, not
	// specific to NAT66 at all, in every veth/tap ServiceVIPBinding's own
	// reply path.
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	if err := attachUsidEgress(pinDir, hostName); err != nil {
		return false, fmt.Errorf("attach eBPF usid_egress to host interface %q: %w", hostName, err)
	}

	// Registers this node's own SRv6 source address into
	// node_src_addr_table -- see registerNodeSourceAddress's own doc
	// comment. A per-node constant, not per-attachment, but idempotent
	// and cheap enough (one netlink route/address query, one map write)
	// to simply redo on every attachment ADD, the same way every other
	// registration in this function already is, rather than adding a
	// separate once-per-node lifecycle hook.
	//
	// Deliberately non-fatal to this ADD, unlike every other registration
	// step above: ResolveNodeSourceAddress needs a converged main-table
	// IPv6 default route, which a node can genuinely, transiently lack
	// early in its own boot sequence (before the underlay eBGP session
	// comes up) -- failing every pod attach on the whole node until that
	// converges would be a real availability regression from today's
	// behavior, where a missing egress route only ever failed traffic to
	// the *specific* destination that needed it, never CNI ADD itself.
	// usid_egress's own "not yet configured" check already fails open
	// (TC_ACT_UNSPEC) for exactly this gap; a later attachment's ADD (or
	// this same one's next retry) succeeds here once the route exists.
	if err := registerNodeSourceAddress(pinDir); err != nil {
		slog.Warn("ADD: could not register this node's own SRv6 source address; "+
			"egress routing will fail open until this succeeds", "err", err)
	}

	// Registers this node's own fabric-uplink next hop into
	// public_uplink_table -- see registerPublicUplink's own doc comment.
	// Same per-node-constant, redo-on-every-ADD, non-fatal-on-failure
	// shape as registerNodeSourceAddress just above, and for the
	// identical reason: ResolvePublicUplink needs a converged underlay
	// neighbor, which a node can transiently lack early in its own boot
	// sequence. usid_egress's own "not configured yet" check on this map
	// (link_ifindex == 0, absent entirely) already fails open (falling
	// through to egress_route_table, the pre-existing behavior) for
	// exactly this gap.
	if err := registerPublicUplink(pinDir); err != nil {
		slog.Warn("ADD: could not register this node's own public uplink; "+
			"a DSR backend's VIP-sourced reply traffic will fail open to egress_route_table until this succeeds",
			"err", err)
	}

	return true, nil
}

// registerNodeSourceAddress resolves this node's own SRv6/underlay-facing
// source address (srv6.ResolveNodeSourceAddress) and writes it into
// node_src_addr_table (egressroutemap.NodeSourceAddress) -- the value
// usid_egress's egress-routing extension stamps into every outer header
// it pushes (docs/plans/tc-bpf-egress-srv6-encap.md). Without this, every
// egress_route_table hit fails open (TC_ACT_UNSPEC) rather than
// encapsulating at all -- see usid.c's own "not yet configured" check on
// this map -- so this must succeed before EgressDefaultRouteAdd/
// RouteEgressAdd's own installed entries can ever actually carry traffic.
// See this function's own call site for why a failure here doesn't fail
// the whole CNI ADD.
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

// registerPublicUplink resolves this node's own fabric-uplink interface's
// real next hop (srv6.ResolvePublicUplink) and writes it into
// public_uplink_table (egressroutemap.PublicUplink) -- the value
// usid_egress redirects a DSR backend's VIP-sourced reply toward,
// unconditionally, immediately after apply_vip_xlat rewrites that
// reply's source address, bypassing egress_route_table's own NAT66
// default entirely. Without this, a DSR-served ServiceVIPBinding whose
// backend lives in a VRF with a NAT66 default configured (any VRF on a
// node with NAT66ShardSIDs set, i.e. every VRF today) has its reply
// wrongly re-SNAT'd through a NAT66 shard instead of ever reaching the
// real client -- found live, confirmed via nat66_conn_table gaining a
// fresh forward-flow entry keyed on the VIP as if it were an ordinary
// tenant backend originating a new outbound connection. See this
// function's own call site for why a failure here doesn't fail the
// whole CNI ADD.
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

// attachUsidEgress loads usid_egress from its own pin (attach.Load pins it
// there, alongside every usid_ingress map, specifically so a short-lived
// process like this one can reach it -- see that function's own doc
// comment) and attaches it to ifaceName's TC ingress hook.
//
// This was a real, previously-undiscovered gap: usid_egress has existed
// since the DSR/Maglev redesign's component 0.1/2 work (NPTv6 and tap-VIP
// substitution's outbound-direction translation), but nothing anywhere in
// this codebase ever called attach.AttachEgress (or any equivalent) to
// actually put it on an interface -- confirmed live via `tc filter show`
// on a real backend's own host-side veth: no filter at all, on either
// direction. Every fix this redesign made to the *forward* path (client
// -> VIP -> backend) worked and was validated without ever exercising
// this gap, because none of them depended on the *reply* leaving with its
// source address translated back -- only once the forward path, the
// NAT66 egress route, and everything else were all working at once did a
// real end-to-end curl's TCP handshake finally depend on it, and stall
// with the reply silently discarded by the client (its source address
// never got translated from the backend's real address back to the VIP).
//
// Idempotent (attach.AttachEgress's own FilterReplace semantics) and safe
// to call on every attachment ADD, the same way every other registration
// in this function already is.
func attachUsidEgress(pinDir, ifaceName string) error {
	program, err := ebpf.LoadPinnedProgram(filepath.Join(pinDir, attach.UsidEgressPinName), nil)
	if err != nil {
		return fmt.Errorf("load pinned usid_egress program: %w", err)
	}
	defer func() { _ = program.Close() }()

	return attach.AttachEgress(program, ifaceName)
}

// registerLocalEgressRoutes registers each of prefixes as a local
// pass-through egress_route_table entry in Linux VRF table vrfTableID --
// see registerEBPFDatapath's own doc comment for why this attachment's
// own prefix needs one. Idempotent (a plain map Put under the hood) and
// safe to call on every attachment ADD, including a repeat ADD for the
// same attachment or a sibling attachment re-registering an unrelated
// prefix in the same VRF.
//
// Opens egress_route_table directly via egressroutemap, keyed on the
// caller's own pinDir -- unlike installNAT66EgressRoute below, this
// deliberately does not go through srv6's RouteEgressAdd/
// EgressDefaultRouteAdd wrappers, which resolve their own pinned-map
// directory from a package-level var defaulting to attach.PinDir rather
// than accepting one as a parameter: fine for those (always called with
// the real production bpffs mount), but wrong here, where
// registerEBPFDatapath is explicitly designed to run against an
// arbitrary pinDir (see its own usidmap.OpenPinnedRegistry/
// ifindexvrfmap.OpenPinned calls) -- mirrors registerNodeSourceAddress's
// identical choice, just below, for the same reason.
//
// prefixes are the exact CIDR strings ipamAdvertisementPrefixes already
// produces for this attachment's own BGPAdvertisement (an IPv6 subnet
// and/or an IPv4 host route) -- a parse failure here would mean that
// function produced something unparseable, which would already have
// failed the BGPAdvertisement CreateOrUpdate below with a bad prefix, so
// treating it as a hard error here rather than skipping it silently
// keeps both paths equally strict.
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

// installNAT66EgressRoute installs (or refreshes) vrfTableID's default
// egress route toward every configured NAT66 shard -- see
// config.EnvCNINAT66ShardSIDs's own doc comment for where the shard list
// comes from, and srv6.EgressDefaultRouteAdd's own doc comment for why
// this is a multipath route rather than a per-flow hash. Idempotent
// (RouteReplace under the hood) and safe to call on every attachment ADD
// sharing this VRF, the same way vrf.Add itself already is.
//
// An operator who hasn't configured any shard yet (the common case before
// this mechanism is rolled out to a given fabric) sees no error at all:
// parseShardSIDs returns an empty, nil-error slice for an empty string,
// and srv6.EgressDefaultRouteAdd itself no-ops on an empty list. A
// misconfigured shard SID (invalid address, or one with no reachable
// route yet -- e.g. this node came up before NAT66ShardReconciler's own
// BGPAdvertisement had propagated) fails this attachment's ADD outright
// rather than silently leaving the VRF with no egress at all.
func installNAT66EgressRoute(vrfTableID uint32) error {
	// cniConfig is nil unless something has already called InitCNIConfig
	// (cmd/galactic-bgp's main.go, before any cmdAdd can run) or a test set
	// it up directly -- several existing unit tests in this package call
	// registerEBPFDatapath straight through without either, mirroring
	// ops_del_test.go's own cniConfig-may-be-nil stance. Treated the same
	// as "no shard configured yet," not a panic.
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

// parseShardSIDs splits a comma-separated NAT66 shard SID list (as
// resolved into config.CNIConfig.NAT66ShardSIDs) into IP addresses,
// trimming whitespace around each entry and skipping blank ones -- so a
// trailing comma or stray space in the operator-supplied env var/conflist
// value doesn't fail every attachment ADD in the cluster. An entry that
// survives trimming but still isn't a valid IP address is a real
// misconfiguration and fails loudly rather than silently dropping one
// shard from the list.
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

// hostInterfaceIndex resolves this attachment's own host-side veth/tap
// interface's kernel ifindex, by name -- the same deterministic name
// (intf.GenerateInterfaceNameHost) the master plugin (internal/cni or
// internal/cnitap) already used to create it, so no value needs threading
// through prevResult to find it again here.
func hostInterfaceIndex(vpc, vpcAttachment string) (uint32, error) {
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		return 0, fmt.Errorf("look up host interface %q: %w", hostName, err)
	}
	return uint32(link.Attrs().Index), nil
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
