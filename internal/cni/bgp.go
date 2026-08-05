// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// maxRetries is the maximum number of retry attempts for transient k8s API
// errors during the BGP state publish phase.  The total number of attempts
// is maxRetries+1 (initial + retries).
const maxRetries = 2

// isTransientError reports whether err is a transient failure that may
// resolve itself on retry (API server unavailable, timeout, network blip).
// Returns false for validation errors, not-found, and other permanent
// failures that should not be retried.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	// Context-level failures (deadline exceeded, cancelled) are transient
	// because they usually indicate the API server was slow/unavailable.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	// Unwrap to handle wrapped errors (e.g. from controllerutil.CreateOrUpdate).
	unwrapped := errors.Unwrap(err)
	if unwrapped != nil {
		if errors.Is(unwrapped, context.DeadlineExceeded) || errors.Is(unwrapped, context.Canceled) {
			return true
		}
	}
	// Kubernetes API errors: 503 Service Unavailable, 500 Internal Server
	// Error, 504 Server Timeout, and 429 Too Many Requests.
	if apierrors.IsServiceUnavailable(err) ||
		apierrors.IsInternalError(err) ||
		apierrors.IsServerTimeout(err) ||
		apierrors.IsTooManyRequests(err) {
		return true
	}
	// Network-level transient errors (connection refused/reset, unreachable).
	if netErr, ok := unwrapped.(interface{ Temporary() bool }); ok && netErr.Temporary() {
		return true
	}
	return false
}

// retryK8sOps runs fn with up to maxRetries+1 attempts, retrying on transient
// k8s API errors with exponential backoff.  The context passed to fn has a
// timeout derived from timeout (respecting the original ctx deadline when set).
// Non-transient errors are returned immediately without retry.
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

// bgpConfig holds the BGP values the CNI needs to populate BGP CRDs.
type bgpConfig struct {
	asNumber   uint32
	routerName string
	// srv6Locator is the router's SRv6 locator block (BGPRouterSpec.SRv6Locator),
	// or empty when not configured.
	srv6Locator string
	// nodeID is the router's 8-bit PoP-local slot (BGPRouterSpec.NodeID),
	// or 0 when not configured.
	nodeID int32
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
// VPC-scoped route import/export. vpcHex is the 16-bit hex VPC identifier.
func routeTarget(asNumber int64, vpcHex string) (string, error) {
	v, err := strconv.ParseUint(vpcHex, 16, 64)
	if err != nil {
		return "", fmt.Errorf("parse VPC hex %q: %w", vpcHex, err)
	}
	return fmt.Sprintf("%d:%d", asNumber, uint32(v)), nil
}

// allocateArgument returns the 12-bit Argument value (design plan
// .local/plan-ebpf-xdp-usid-datapath.md §4.2, §5.2) for the VPC attachment
// named vrfInstanceName under routerName: the value already registered if
// a BGPVRFInstance with that exact name exists (an idempotent CNI ADD
// retry, or a repeat ADD on an attachment that is already live), or -- if
// none does -- the lowest unused value in
// [uformat.ArgumentMin, uformat.ArgumentMax] among that router's other
// BGPVRFInstances.
//
// Scoping this to one BGPRouter -- one per node, in the tenant role -- is
// what makes this a local, per-node allocation rather than a
// platform-wide one: confirmed 2026-08-02 that the eBPF datapath's
// vrf_table is populated and consulted entirely per node (a packet only
// reaches it after locator_table has already routed it to that specific
// node), so no two nodes ever need to agree on a shared Argument
// numbering authority. This mirrors
// internal/plumbing/vrf.findNextAvailableVRFID's own first-available-slot
// pattern for the Linux kernel VRF table ID, just scoped to
// BGPVRFInstance CRD state -- the same "CRD state is the source of
// truth" pattern the GC controller already uses for VRFs -- instead of
// kernel state, so this works whether or not the eBPF datapath is even
// enabled on this node.
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
			continue // not one of this node's router's VRF instances
		}
		if inst.Name == vrfInstanceName {
			// Idempotent: this attachment already has an Argument.
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
// concurrently (allocateArgument's list-then-write is not atomic against a
// second, concurrent CNI ADD racing it). Any other instance found still
// holding this VRFID is treated as a collision -- deliberately without a
// tie-breaker: allocateArgument -> create -> checkArgumentCollision runs
// sequentially within one call, so if A's create happens before B's create,
// then either B's own check (which always runs after B's own create) sees
// A's already-committed CRD and B reports a collision, or it doesn't only if
// A's check already ran (and hence already reported the collision itself)
// before B created its CRD. At least one side always detects it this way; a
// tie-breaker that lets exactly one side "win" without that guarantee (as a
// prior version of this function did) can let both sides pass when the two
// creates and checks interleave, leaving two BGPVRFInstances -- and,
// consequently, two vrf_table registrations -- permanently sharing the same
// VRFID. Both sides erroring out is harmless: the caller's non-transient
// error triggers the failed-ADD rollback (resourceTracker.cleanup), which
// deletes each side's own BGPVRFInstance, and the CNI runtime retries ADD.
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
		// expected
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
// The route distinguisher is no longer stored on the CRD; it's derived
// downstream from the router's ID and vrfID.
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
// attachment is dual-stack. RFC 9136's Type-5 route is self-describing per
// NLRI, so a single BGPAdvertisement carrying both families is valid; see
// galactic-router's buildEVPNPaths for the corresponding per-family gateway
// handling. VRFID and Function record structurally what used to live in the
// legacy galactic.datum.net/srv6-sid annotation: which VRF this advertisement
// belongs to, and which SRv6 endpoint behavior the eBPF uSID datapath
// resolves (always End.DT46, regardless of pod-subnet address family — see
// registerEBPFDatapath).
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

// newK8sClient creates a new Kubernetes client using the in-cluster config.
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

// publishBGPState configures the host gateway, sets up the SRv6 ingress route,
// and creates the BGPVRFInstance and BGPAdvertisement CRDs. The host gateway
// configuration is interface-agnostic (works for both veth and tap).
//
// K8s API operations are retried with exponential backoff on transient errors
// (503, timeout, network blip). Non-k8s operations (kernel networking) run
// once before the retry loop. Non-transient errors (validation, not-found)
// fail immediately without retry.
func publishBGPState(
	args *skel.CmdArgs, pluginConf *PluginConf, nodeName, namespace string, ipamResult *ipamResult,
	guestHWAddr net.HardwareAddr, tracker *resourceTracker,
) error {
	// ---- non-k8s operations (run once) ----
	if err := configureHostGateway(pluginConf.VPC, pluginConf.VPCAttachment, ipamResult, guestHWAddr); err != nil {
		return err
	}

	vpcHex, err := intf.Base62ToHex(pluginConf.VPC)
	if err != nil {
		return fmt.Errorf("decode VPC: %w", err)
	}

	if tracker.k8s == nil {
		return errors.New("k8s client not set in tracker")
	}

	// ---- k8s operations (retry on transient errors) ----
	// The SID Argument is allocated inside publishBGPStateK8s's retry
	// closure, not here: it depends on this node's BGPRouter (looked up
	// there) and must itself be a k8s-retried operation, since it lists
	// BGPVRFInstance CRDs.
	return publishBGPStateK8s(args, pluginConf, nodeName, namespace, ipamResult, vpcHex, tracker.k8s, tracker)
}

// ipamAdvertisementPrefixes derives the BGPAdvertisement prefixes to
// originate, plus the per-family values to record in the annotations, from
// ipamResult. ipamResult is nil when the attachment has no IPAM allocation
// (e.g. a tap workload that manages its own addressing), in which case
// prefixes is empty. Either family alone yields a single-entry prefixes
// slice; ipv6Subnet/ipv4Addr are empty when that family wasn't allocated.
func ipamAdvertisementPrefixes(ipamResult *ipamResult) (prefixes []string, ipv6Subnet, ipv4Addr string) {
	if ipamResult == nil {
		return nil, "", ""
	}
	if ipamResult.ipv6Subnet != nil {
		ipv6Subnet = ipamResult.ipv6Subnet.String()
		prefixes = append(prefixes, ipv6Subnet)
	}
	if ipamResult.ipv4Address != nil {
		// The annotation stores the bare address (matching
		// IPv4PoolAllocator's marker-file naming, so cmdDel's Deallocate
		// call finds it — see ipam_ops.go); the advertised prefix needs the
		// explicit /32 CIDR form.
		ipv4Addr = ipamResult.ipv4Address.String()
		prefixes = append(prefixes, ipv4Addr+"/32")
	}
	return prefixes, ipv6Subnet, ipv4Addr
}

// allAdvertisedPrefixes derives the full set of BGP-advertised prefixes for
// a BGPAdvertisement CRD from every subnet annotation currently present on
// it, rather than from just the container currently being processed.
//
// A single BGPAdvertisement is keyed by (vpc, vpcAttachment) alone
// (bgpAdvertisementName), so multiple containers attaching under the same
// VPCAttachment on this node — a second pod, or a second interface with its
// own vpcattachment reusing this one — all share one CRD. Each one's own
// CNI ADD must not clobber another still-live container's already-published
// prefix: annotations is the durable per-container record (subnetAnnotationKeyIPv6/IPv4),
// so recomputing Spec.Prefixes from all of them on every ADD keeps every
// live container's prefix present regardless of ADD order. cmdDel
// deliberately leaves this annotation (and thus this prefix) in place even
// after that container exits — see ops_del.go's "skipping shared resource
// cleanup (handled by GC)" — so a stale entry for an exited container can
// briefly outlive it until gc.CollectOrphanedCRDs removes the whole CRD
// once every container sharing it is gone; that's a pre-existing tradeoff
// this function doesn't change.
func allAdvertisedPrefixes(annotations map[string]string) []string {
	var prefixes []string
	for key, value := range annotations {
		switch {
		case strings.HasPrefix(key, annotationAllocatedSubnetIPv6+"."):
			prefixes = append(prefixes, value)
		case strings.HasPrefix(key, annotationAllocatedSubnetIPv4+"."):
			// Annotation stores the bare address (see ipamAdvertisementPrefixes);
			// the advertised prefix needs the explicit /32 CIDR form.
			prefixes = append(prefixes, value+"/32")
		}
	}
	// Deterministic ordering: map iteration is randomized, and an
	// unstable Spec.Prefixes order across otherwise-identical ADDs would
	// look like a spurious spec change to anything diffing this CRD.
	sort.Strings(prefixes)
	return prefixes
}

// publishBGPStateK8s creates the BGPVRFInstance and BGPAdvertisement CRDs with
// retry on transient k8s API errors. The host gateway must be configured before
// calling this (via configureHostGateway). This is interface-agnostic and can be
// used by both veth and tap code paths.
func publishBGPStateK8s(
	args *skel.CmdArgs, pluginConf *PluginConf, nodeName, namespace string, ipamResult *ipamResult,
	vpcHex string, k8s client.Client, tracker *resourceTracker,
) error {
	return retryK8sOps(cniTimeout, func(ctx context.Context) error {
		bgp, err := lookupBGPRouter(ctx, k8s, nodeName, namespace)
		if err != nil {
			return err
		}

		vrfID, err := allocateArgument(
			ctx, k8s, namespace, bgp.routerName, bgpVRFInstanceName(pluginConf.VPC, pluginConf.VPCAttachment))
		if err != nil {
			return err
		}

		rtValue, err := routeTarget(int64(bgp.asNumber), vpcHex)
		if err != nil {
			return fmt.Errorf("compute route target: %w", err)
		}

		// Create the BGPVRFInstance to configure the VRF with its VRFID and
		// import/export route targets. This must be created before advertisements
		// so the BGP runtime has the VRF context when originating EVPN paths.
		vrfName := bgpVRFInstanceName(pluginConf.VPC, pluginConf.VPCAttachment)
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
		tracker.vrfInstanceCreated = true
		slog.Debug("BGP: BGPVRFInstance applied", "name", vrfName, "namespace", namespace,
			"vrfID", vrfID, "routeTarget", rtValue, "router", bgp.routerName)

		if err := checkArgumentCollision(ctx, k8s, namespace, bgp.routerName, vrfName, vrfID); err != nil {
			return err
		}

		// eBPF uSID datapath registration -- the only forwarding path
		// (the legacy seg6local static-route path was removed once this
		// datapath covered both veth and tap attachments). registered is
		// false, with no error, only when the router has no
		// srv6Locator/nodeID configured at all -- SRv6 is intentionally
		// not set up for this attachment. Any other failure is fatal:
		// with no legacy path to fall back to, an attachment with no
		// registered datapath entry has no forwarding path at all.
		// registerEBPFDatapath is itself idempotent (Register
		// overwrites), so re-running it on a k8s-op retry is safe.
		registered, ebpfBlock, err := registerEBPFDatapath(
			bgp, pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.InterfaceType, uint16(vrfID), attach.PinDir)
		if err != nil {
			return fmt.Errorf("register eBPF uSID datapath: %w", err)
		}
		if registered {
			// Recorded so a failed-ADD rollback (resourceTracker.cleanup)
			// can unregister this exact (block, argument) pair -- see
			// Milestone 7.2.
			tracker.ebpfRegistered = true
			tracker.ebpfBlock = ebpfBlock
			tracker.ebpfArgument = uint16(vrfID)
		}

		// Create the BGPAdvertisement to originate the pod's subnet prefix(es).
		adv := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bgpAdvertisementName(pluginConf.VPC, pluginConf.VPCAttachment),
				Namespace: namespace,
			},
		}
		prefixes, ipv6Subnet, ipv4Addr := ipamAdvertisementPrefixes(ipamResult)
		var mergedPrefixes []string
		_, err = controllerutil.CreateOrUpdate(ctx, k8s, adv, func() error {
			if adv.Annotations == nil {
				adv.Annotations = make(map[string]string)
			}
			// Record the netns path this container attached with, so the GC
			// controller can check whether it still exists rather than
			// guessing a name from the container ID (see
			// gc.ContainerNetNSExistsByPath).
			adv.Annotations[netnsAnnotationKey(args.ContainerID)] = args.Netns
			// Store the allocated addresses keyed by container ID so cmdDel can
			// look them up, one annotation per family so DEL can deallocate
			// each independently.
			if ipv6Subnet != "" {
				adv.Annotations[subnetAnnotationKeyIPv6(args.ContainerID)] = ipv6Subnet
			}
			if ipv4Addr != "" {
				adv.Annotations[subnetAnnotationKeyIPv4(args.ContainerID)] = ipv4Addr
			}
			// Recompute Spec.Prefixes from every container's annotations, not
			// just this one's own — see allAdvertisedPrefixes. Must run after
			// this container's own annotations are set above, and be read
			// back into mergedPrefixes for the log line below since this
			// closure may run more than once (RetryOnConflict).
			mergedPrefixes = allAdvertisedPrefixes(adv.Annotations)
			adv.Spec = buildAdvertisementSpec(bgp.routerName, rtValue, mergedPrefixes, vrfID)
			return nil
		})
		if err != nil {
			return fmt.Errorf("apply BGPAdvertisement: %w", err)
		}
		tracker.advCreated = true
		slog.Debug("BGP: BGPAdvertisement applied", "name", adv.Name, "namespace", namespace,
			"prefixes", mergedPrefixes, "addedPrefixes", prefixes, "containerID", args.ContainerID)

		slog.Info("ADD: BGP state published", "containerID", args.ContainerID,
			"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
		return nil
	})
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

// configureHostGateway assigns each configured family's gateway address as a
// host address (/128 for IPv6, /32 for IPv4 on veth) on the host-side
// interface (veth or tap) and installs an explicit pod-subnet route for that
// family into the VRF table. IPv4 is skipped entirely when the attachment is
// IPv6-only.
//
// Using a full-length host address (not the pod subnet mask) prevents the
// kernel from auto-creating a subnet-router anycast entry in the VRF local
// table. When the pod address equals the subnet network address the anycast
// absorbs seg6local-decapped inner packets before they reach the guest
// interface. The explicit subnet route replaces the one the kernel would
// have created from the wider mask.
//
// For tap interfaces, the IPv4 gateway is instead assigned as a /25 so the
// address reported on the interface reflects a real subnet (VM guests expect
// this). That reintroduces the wider-mask hazard described above, so the
// address is added with IFA_F_NOPREFIXROUTE: the kernel skips auto-creating
// the connected /25 route entirely, leaving the explicit pod-subnet route
// below as the only thing that governs delivery to this VM's address.
//
// guestHWAddr is the guest-side veth's MAC address, used to prime a
// permanent neighbor table entry for the pod's own address (see
// installGatewayNeighbor). It is nil for tap attachments, which have no
// separate guest-side link in this netns to resolve a MAC from -- tap's
// neighbor resolution, if it turns out to need the same fix, is out of
// scope here since this fix targets the veth-only bug it was found from.
func configureHostGateway(vpc, vpcAttachment string, res *ipamResult, guestHWAddr net.HardwareAddr) error {
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

	if res.ipv6Gateway != nil {
		gwNet := &net.IPNet{IP: res.ipv6Gateway, Mask: net.CIDRMask(128, 128)}
		if err := installGatewayRoute(hostLink, gwNet, res.ipv6Subnet, netlink.FAMILY_V6, int(tableID), 0); err != nil {
			return err
		}
		if guestHWAddr != nil {
			if err := installGatewayNeighbor(hostLink, res.ipv6Subnet.IP, netlink.FAMILY_V6, guestHWAddr); err != nil {
				return err
			}
		}
	}
	if res.ipv4Gateway != nil {
		ipv4Mask, addrFlags := ipv4GatewayAddrParams(hostLink)
		gwNet := &net.IPNet{IP: res.ipv4Gateway, Mask: ipv4Mask}
		ipv4Subnet := &net.IPNet{IP: res.ipv4Address, Mask: net.CIDRMask(32, 32)}
		if err := installGatewayRoute(hostLink, gwNet, ipv4Subnet, netlink.FAMILY_V4, int(tableID), addrFlags); err != nil {
			return err
		}
		if guestHWAddr != nil {
			if err := installGatewayNeighbor(hostLink, res.ipv4Address, netlink.FAMILY_V4, guestHWAddr); err != nil {
				return err
			}
		}
	}
	return nil
}

// installGatewayNeighbor installs a permanent neighbor table entry mapping
// podIP to guestHWAddr on hostLink.
//
// The eBPF uSID ingress datapath (internal/plumbing/ebpf/prog/usid.c)
// decapsulates SRv6 traffic and calls bpf_fib_lookup() to resolve the
// egress path for the inner packet, then redirects it straight to the
// resolved neighbor -- entirely in-kernel, never touching the normal
// forwarding stack. bpf_fib_lookup() does not itself trigger ARP/NDP
// resolution the way ordinary kernel packet forwarding does (that
// resolution happens as a side effect of the slow-path forwarding this
// datapath deliberately bypasses), so without a pre-existing neighbor table
// entry it fails with BPF_FIB_LKUP_RET_NO_NEIGH and the datapath counts and
// drops the packet (DROP_REASON_FIB_LOOKUP_FAILED) -- confirmed live: every
// cross-region packet to a pod that had never otherwise triggered NDP for
// its own address was silently and permanently blackholed, since nothing
// else in this attach path ever resolves it. A permanent entry (installed
// once, at CNI ADD, using the guest veth's own known MAC) means this
// resolution never depends on dynamic ARP/NDP at all.
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
// flags to use for hostLink. Tap interfaces get a /25 (so the address
// reported on the interface reflects a real subnet) with
// IFA_F_NOPREFIXROUTE, which stops the kernel from auto-creating a connected
// route for the wider mask — see the anycast-avoidance note on
// configureHostGateway for why that route must not exist. Veth interfaces
// keep the plain /32 host address with no flags.
func ipv4GatewayAddrParams(hostLink netlink.Link) (net.IPMask, int) {
	if _, isTap := hostLink.(*netlink.Tuntap); isTap {
		return net.CIDRMask(25, 32), unix.IFA_F_NOPREFIXROUTE
	}
	return net.CIDRMask(32, 32), 0
}

// installGatewayRoute assigns gwNet as a host address on hostLink and
// installs an explicit route to subnet into the given VRF table, for one
// address family. Idempotent: existing matching routes/addresses are left
// alone, and conflicting ones return an error rather than being overwritten.
// addrFlags is passed through to the netlink address (e.g. IFA_F_NOPREFIXROUTE
// to suppress the kernel's auto-created connected route for a wider mask).
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

	// Check for existing routes with the same destination before installing.
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
		// Route already exists with matching attributes — idempotent, skip.
		return nil
	}

	if err := netlink.RouteAdd(desiredRoute); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return nil // already installed by a concurrent caller
		}
		return fmt.Errorf("add pod subnet route to VRF table: %w", err)
	}
	return nil
}

// registerEBPFDatapath registers this attachment against the eBPF uSID
// datapath's pinned maps (design plan §5.1) -- the only forwarding path
// (the legacy seg6local static-route path was removed once this covered
// both veth and tap attachments, Milestone 6.1's tap-mode redirect fix).
//
// Design plan §4.4 assigns locator_table/function_table population to "the
// control daemon, at startup + on locator change." The actual control
// daemon (galactic-cni's "run" subcommand) does not read BGPRouter/watch
// for locator changes -- it only loads/attaches/pins the program -- so
// those two maps would otherwise sit permanently empty and every packet
// would locator_table-miss and pass through unchanged. This function
// registers all three tables (locator_table, function_table, vrf_table)
// from here instead, since the CNI ADD path already independently
// resolves bgp.srv6Locator/bgp.nodeID via lookupBGPRouter on every
// invocation -- an intentional deviation from the design plan's literal
// placement, not an oversight, tracked for revisiting once a real
// control-daemon-side CRD watch exists.
//
// argument is the same real, allocated 12-bit value (Milestone 6.1's
// allocateArgument) the router independently recomputes the BGP-advertised
// SID from (internal/reconcile) -- both must agree on the same value or a
// remote node's encapsulated traffic decodes into the wrong VRF.
//
// registerEBPFDatapath's return values let the caller record exactly what
// (if anything) was registered, so a later failed-ADD rollback
// (resourceTracker.cleanup, Milestone 7.2) can unregister the same
// (block, argument) pair without having to recompute or guess it.
// registered is false, with a nil error, only when this router has no
// srv6Locator/nodeID configured at all -- SRv6 is intentionally not set up
// for this attachment. Any other failure is returned as an error: with no
// legacy path to fall back to, the caller must treat that as fatal.
func registerEBPFDatapath(
	bgp bgpConfig, vpc, vpcAttachment, ifaceType string, argument uint16, pinDir string,
) (registered bool, block uint64, err error) {
	if bgp.srv6Locator == "" || bgp.nodeID == 0 {
		return false, 0, nil
	}

	// Validate the raw int32 nodeID against uformat's actual encode-time
	// range *before* the uint16 narrowing below, mirroring srv6.ComputeSID's
	// own bounds check on this exact value (internal/plumbing/srv6/usid.go).
	// registry.Locator.Register below validates its uint16 argument via
	// uformat.ValidateNodeID too, but only after this narrowing has already
	// happened -- an out-of-[uint16] nodeID (e.g. 65537) wraps to some
	// other, often perfectly in-range uint16 (1, here) that check can't
	// tell apart from a legitimately-registered node's real Node-ID. Left
	// unchecked here, that silently registers a locator_table entry for a
	// Node-ID this router was never actually assigned, while ComputeSID
	// (used independently by the router to build the SID it advertises)
	// rejects the same raw value outright -- so nothing ever advertises
	// reachability for the bogus entry this node just committed to
	// forwarding, and it may collide with a different node's genuine one.
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

// egressKindForInterfaceType maps the CNI's InterfaceType field to the
// vrf_table egress_kind value usid.c's step 9 uses to pick between
// bpf_redirect_peer (veth, crosses into the container's netns) and plain
// bpf_redirect (tap, which never leaves this netns -- internal/cni/tap
// creates it here and never moves it). This is what closes the tap-mode
// redirect_failed gap (Milestone 6.1's fix, design plan §4.2 step 9).
func egressKindForInterfaceType(ifaceType string) (uint32, error) {
	switch ifaceType {
	case interfaceTypeVeth, "":
		// Empty matches config.go's own default-to-veth behavior for an
		// omitted interface_type field.
		return usidmap.EgressKindVeth, nil
	case interfaceTypeTap:
		return usidmap.EgressKindTap, nil
	default:
		return 0, fmt.Errorf("unknown interface type %q", ifaceType)
	}
}

// unregisterEBPFDatapath removes the vrf_table entry registerEBPFDatapath
// wrote for this (block, argument) pair, from the failed-ADD rollback path
// (resourceTracker.cleanup, Milestone 7.2). Unlike registerEBPFDatapath,
// this has no flag/config short-circuit of its own -- callers only invoke
// it when resourceTracker recorded a real registration
// (resourceTracker.ebpfRegistered), so by construction the flag was on and
// the maps were reachable at Register time. Idempotent: not an error if
// the entry is already gone (VRFTable.Unregister's own documented
// behavior).
//
// expectedVRFTableID must be this attachment's own VRF table id (recomputed
// by the caller via vrf.TableID, not read back from the tracker, since it's
// cheap and deterministic to recompute and the whole point here is not to
// trust stale state). A retried k8s-op attempt (retryK8sOps) can re-run the
// same publishBGPStateK8s closure without re-registering the eBPF entry
// (registerEBPFDatapath only runs again if that attempt gets far enough),
// so by the time a later attempt's checkArgumentCollision failure triggers
// this rollback, the (block, argument) slot this attachment originally
// wrote may have since been overwritten by the very other attachment the
// collision was detected against (vrf_table's key is just (block,
// argument); Register always overwrites). Unregistering unconditionally in
// that case would delete a live attachment's forwarding entry instead of
// this rolled-back one's own -- so this only deletes the entry when it
// still resolves to expectedVRFTableID, and leaves it alone otherwise.
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
		return nil // already gone
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
