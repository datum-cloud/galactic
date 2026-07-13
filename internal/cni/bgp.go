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
	"strconv"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
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
// VPC-scoped route import/export. vpcHex is the 48-bit hex VPC identifier.
func routeTarget(asNumber int64, vpcHex string) (string, error) {
	v, err := strconv.ParseUint(vpcHex, 16, 64)
	if err != nil {
		return "", fmt.Errorf("parse VPC hex %q: %w", vpcHex, err)
	}
	return fmt.Sprintf("%d:%d", asNumber, uint32(v)), nil
}

// vrfIDFromAttachment decodes the base62-encoded VPCAttachment identifier
// into the numeric 16-bit VRFID required by BGPVRFInstanceSpec.VRFID and
// BGPAdvertisementSpec.VRFID.
func vrfIDFromAttachment(vpcAttachment string) (int32, error) {
	hex, err := intf.Base62ToHex(vpcAttachment)
	if err != nil {
		return 0, fmt.Errorf("decode VPCAttachment %q: %w", vpcAttachment, err)
	}
	v, err := strconv.ParseUint(hex, 16, 16)
	if err != nil {
		return 0, fmt.Errorf("parse VPCAttachment hex %q as VRFID: %w", hex, err)
	}
	return int32(v), nil
}

// resolveSRv6SID determines the SRv6 SID to use for this endpoint's ingress
// decap route.
//
//   - An explicit, non-empty explicitSID (from CNI config's srv6_sid) always
//     wins and is used verbatim — this is a documented, supported override.
//   - Otherwise, when the router has both srv6Locator and nodeID configured,
//     the SID is computed from the locator, nodeID, and vrfID using the
//     End.DT46 function — the only endpoint behavior CNI's kernel ingress
//     route ever installs (see setupSRv6Ingress/srv6.RouteIngressAdd).
//   - Otherwise, an empty string is returned with no error, matching today's
//     behavior of skipping SRv6 ingress setup entirely.
func resolveSRv6SID(explicitSID string, bgp bgpConfig, vrfID int32) (string, error) {
	if explicitSID != "" {
		return explicitSID, nil
	}
	if bgp.srv6Locator == "" || bgp.nodeID == 0 {
		return "", nil
	}
	sid, err := srv6.ComputeSID(bgp.srv6Locator, bgp.nodeID, vrfID, bgpv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		return "", fmt.Errorf("compute SRv6 SID: %w", err)
	}
	return sid.String(), nil
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
// attachment's pod subnet. VRFID and Function record structurally what used
// to live in the legacy galactic.datum.net/srv6-sid annotation: which VRF
// this advertisement belongs to, and which SRv6 endpoint behavior the CNI
// kernel ingress route installs (always End.DT46, regardless of pod-subnet
// address family — see setupSRv6Ingress/srv6.RouteIngressAdd).
func buildAdvertisementSpec(routerName, rtValue, podSubnet string, vrfID int32) bgpv1alpha1.BGPAdvertisementSpec {
	function := bgpv1alpha1.SRv6FunctionEndDT46
	return bgpv1alpha1.BGPAdvertisementSpec{
		RouterRef:     bgpv1alpha1.RouterRef{Name: routerName},
		AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
		Prefixes:      []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(podSubnet)},
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

// publishBGPState configures the host veth gateway, sets up the SRv6 ingress
// route, and creates the BGPVRFInstance and BGPAdvertisement CRDs. This is
// veth-only; tap mode returns before reaching this path.
//
// K8s API operations are retried with exponential backoff on transient errors
// (503, timeout, network blip). Non-k8s operations (kernel networking) run
// once before the retry loop. Non-transient errors (validation, not-found)
// fail immediately without retry.
func publishBGPState(
	args *skel.CmdArgs, pluginConf *PluginConf, nodeName, namespace string, ipamResult *ipamResult,
	tracker *resourceTracker,
) error {
	// ---- non-k8s operations (run once) ----
	if err := configureHostVethGateway(pluginConf.VPC, pluginConf.VPCAttachment, ipamResult); err != nil {
		return err
	}

	vpcHex, err := intf.Base62ToHex(pluginConf.VPC)
	if err != nil {
		return fmt.Errorf("decode VPC: %w", err)
	}

	vrfID, err := vrfIDFromAttachment(pluginConf.VPCAttachment)
	if err != nil {
		return err
	}

	k8s, err := newK8sClient()
	if err != nil {
		return err
	}
	tracker.k8s = k8s

	// ---- k8s operations (retry on transient errors) ----
	return retryK8sOps(cniTimeout, func(ctx context.Context) error {
		bgp, err := lookupBGPRouter(ctx, k8s, nodeName, namespace)
		if err != nil {
			return err
		}

		rtValue, err := routeTarget(int64(bgp.asNumber), vpcHex)
		if err != nil {
			return fmt.Errorf("compute route target: %w", err)
		}

		// SID resolution needs the router's srv6Locator/nodeID, so it happens
		// here rather than in the non-k8s section above. RouteIngressAdd is
		// idempotent, so re-running it on retry is safe.
		sidStr, err := resolveSRv6SID(pluginConf.SRv6SID, bgp, vrfID)
		if err != nil {
			return err
		}
		srv6SIDStr, err := setupSRv6Ingress(sidStr, pluginConf.VPC, pluginConf.VPCAttachment)
		if err != nil {
			return err
		}
		if srv6SIDStr != "" {
			tracker.srv6SID = srv6SIDStr
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
			adv.Spec = buildAdvertisementSpec(bgp.routerName, rtValue, podSubnet, vrfID)
			if adv.Annotations == nil {
				adv.Annotations = make(map[string]string)
			}
			// Record the netns path this container attached with, so the GC
			// controller can check whether it still exists rather than
			// guessing a name from the container ID (see
			// gc.ContainerNetNSExistsByPath).
			adv.Annotations[netnsAnnotationKey(args.ContainerID)] = args.Netns
			// Store the allocated subnet keyed by container ID so cmdDel can look it up.
			if ipamResult != nil {
				adv.Annotations[subnetAnnotationKey(args.ContainerID)] = podSubnet
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("apply BGPAdvertisement: %w", err)
		}
		tracker.advCreated = true

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
	desiredRoute := &netlink.Route{
		Dst:       res.subnet,
		LinkIndex: hostLink.Attrs().Index,
		Table:     int(tableID),
	}

	// Check for existing routes with the same destination before installing.
	existingRoutes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V6,
		&netlink.Route{Table: int(tableID)},
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

// setupSRv6Ingress installs the End.DT46 SRv6 ingress decap route for the given
// USID and returns the SID string. Returns empty string when SID is not configured.
func setupSRv6Ingress(sid, vpc, vpcAttachment string) (string, error) {
	if sid == "" {
		return "", nil
	}
	if err := srv6.RouteIngressAdd(sid, vpc, vpcAttachment); err != nil {
		return "", fmt.Errorf("add SRv6 ingress route: %w", err)
	}
	return sid, nil
}
