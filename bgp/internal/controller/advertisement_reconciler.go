package controller

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bgpv1alpha1 "go.miloapis.com/bgp/api/v1alpha1"
)

const (
	// AdvertisementFinalizer is added to BGPAdvertisement resources to ensure
	// prefixes are withdrawn from GoBGP before the resource is deleted from etcd.
	AdvertisementFinalizer = "bgp.miloapis.com/advertisement-cleanup"

	// lastPrefixesAnnotation records the comma-separated list of prefixes last
	// advertised to GoBGP, enabling change detection on spec update.
	lastPrefixesAnnotation = "bgp.miloapis.com/last-prefixes"

	// BGPAdvertisementAdvertised is the condition type indicating advertisement state.
	BGPAdvertisementAdvertised = "Advertised"
)

// AdvertisementReconciler reconciles BGPAdvertisement resources into GoBGP AddPath/DeletePath calls.
type AdvertisementReconciler struct {
	client.Client
	GoBGP         *GoBGPClient
	LocalEndpoint string
}

// Reconcile handles BGPAdvertisement events.
func (r *AdvertisementReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var advert bgpv1alpha1.BGPAdvertisement
	if err := r.Get(ctx, req.NamespacedName, &advert); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	c := r.GoBGP.Client()
	if c == nil {
		return ctrl.Result{}, fmt.Errorf("GoBGP not connected")
	}

	// Handle deletion: withdraw all prefixes and remove finalizer.
	if !advert.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.handleDelete(ctx, c, &advert)
	}

	// Ensure finalizer is present before making any GoBGP calls.
	if !controllerutil.ContainsFinalizer(&advert, AdvertisementFinalizer) {
		patch := client.MergeFrom(advert.DeepCopy())
		controllerutil.AddFinalizer(&advert, AdvertisementFinalizer)
		if err := r.Patch(ctx, &advert, patch); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		// Re-read after patch.
		if err := r.Get(ctx, req.NamespacedName, &advert); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	// Resolve the local node's IPv6 address (used as next-hop).
	localIP, err := r.localEndpointAddress(ctx)
	if err != nil {
		return r.setAdvertisedFalse(ctx, &advert, fmt.Sprintf("resolve local IPv6: %v", err))
	}

	// Compute set differences against last-advertised annotation.
	lastPrefixes := parsePrefixAnnotation(advert.Annotations[lastPrefixesAnnotation])
	currentPrefixes := sliceToSet(advert.Spec.Prefixes)

	// Withdraw prefixes that were removed from the spec.
	toWithdraw := setDifference(lastPrefixes, currentPrefixes)
	for prefix := range toWithdraw {
		if err := addPathIPv6Prefix(ctx, c, prefix, localIP, true, nil, nil); err != nil {
			log.Printf("bgp/advert: withdraw removed prefix %s for %s: %v", prefix, advert.Name, err)
		}
	}

	// Advertise all current prefixes (idempotent).
	count := 0
	for _, prefix := range advert.Spec.Prefixes {
		if err := addPathIPv6Prefix(ctx, c, prefix, localIP, false, advert.Spec.Communities, advert.Spec.LocalPref); err != nil {
			log.Printf("bgp/advert: advertise prefix %s for %s: %v", prefix, advert.Name, err)
			return r.setAdvertisedFalse(ctx, &advert, fmt.Sprintf("advertise prefix %s: %v", prefix, err))
		}
		count++
	}

	// Update last-prefixes annotation.
	patch := client.MergeFrom(advert.DeepCopy())
	if advert.Annotations == nil {
		advert.Annotations = make(map[string]string)
	}
	advert.Annotations[lastPrefixesAnnotation] = strings.Join(advert.Spec.Prefixes, ",")
	if err := r.Patch(ctx, &advert, patch); err != nil {
		log.Printf("bgp/advert: patch annotations: %v", err)
	}

	// Re-read after annotation patch.
	if err := r.Get(ctx, req.NamespacedName, &advert); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// If peerSelector is set, ensure the synthesized export BGPRoutePolicy exists.
	if advert.Spec.PeerSelector != nil {
		if err := r.ensureExportPolicy(ctx, &advert); err != nil {
			return r.setAdvertisedFalse(ctx, &advert, fmt.Sprintf("ensure export policy: %v", err))
		}
	}

	// Update status.
	statusPatch := client.MergeFrom(advert.DeepCopy())
	advert.Status.AdvertisedPrefixCount = int32(count)
	apimeta.SetStatusCondition(&advert.Status.Conditions, metav1.Condition{
		Type:               BGPAdvertisementAdvertised,
		Status:             metav1.ConditionTrue,
		Reason:             "Advertised",
		Message:            fmt.Sprintf("%d prefix(es) injected into GoBGP RIB", count),
		ObservedGeneration: advert.Generation,
	})
	if err := r.Status().Patch(ctx, &advert, statusPatch); err != nil {
		log.Printf("bgp/advert: patch status: %v", err)
	}

	RecordAdvertisedPrefixes(advert.Name, count)
	log.Printf("bgp/advert: reconciled %s (%d prefix(es))", advert.Name, count)
	return ctrl.Result{}, nil
}

// handleDelete withdraws all last-advertised prefixes from GoBGP and removes the finalizer.
func (r *AdvertisementReconciler) handleDelete(ctx context.Context, c gobgpapi.GobgpApiClient, advert *bgpv1alpha1.BGPAdvertisement) error {
	if !controllerutil.ContainsFinalizer(advert, AdvertisementFinalizer) {
		return nil
	}

	// Determine which prefixes to withdraw: union of last-advertised annotation
	// and current spec (in case of rapid delete before annotation update).
	lastPrefixes := parsePrefixAnnotation(advert.Annotations[lastPrefixesAnnotation])
	for _, p := range advert.Spec.Prefixes {
		lastPrefixes[p] = struct{}{}
	}

	// We need a local IP for the withdrawal path. If we can't resolve it, still proceed
	// with a best-effort approach using a zero address.
	localIP, err := r.localEndpointAddress(ctx)
	if err != nil {
		log.Printf("bgp/advert: handleDelete: resolve local IPv6: %v — withdrawing with zero IP", err)
		localIP = net.IPv6zero
	}

	for prefix := range lastPrefixes {
		if err := addPathIPv6Prefix(ctx, c, prefix, localIP, true, nil, nil); err != nil {
			log.Printf("bgp/advert: withdraw %s on delete: %v", prefix, err)
		}
	}

	// Delete the synthesized export policy if it exists.
	policyName := exportPolicyName(advert.Name)
	var policy bgpv1alpha1.BGPRoutePolicy
	if err := r.Get(ctx, types.NamespacedName{Name: policyName}, &policy); err == nil {
		if deleteErr := r.Delete(ctx, &policy); deleteErr != nil && !errors.IsNotFound(deleteErr) {
			log.Printf("bgp/advert: delete synthesized policy %s: %v", policyName, deleteErr)
		}
	}

	RecordAdvertisedPrefixes(advert.Name, 0)

	patch := client.MergeFrom(advert.DeepCopy())
	controllerutil.RemoveFinalizer(advert, AdvertisementFinalizer)
	return r.Patch(ctx, advert, patch)
}

// ensureExportPolicy creates or updates the synthesized BGPRoutePolicy that restricts
// the advertisement to only peers matching peerSelector.
func (r *AdvertisementReconciler) ensureExportPolicy(ctx context.Context, advert *bgpv1alpha1.BGPAdvertisement) error {
	policyName := exportPolicyName(advert.Name)

	prefixMatches := make([]bgpv1alpha1.PrefixMatch, 0, len(advert.Spec.Prefixes))
	for _, p := range advert.Spec.Prefixes {
		prefixMatches = append(prefixMatches, bgpv1alpha1.PrefixMatch{CIDR: p})
	}

	desired := &bgpv1alpha1.BGPRoutePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: policyName,
			Labels: map[string]string{
				"bgp.miloapis.com/synthesized-by": advert.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(advert, bgpv1alpha1.GroupVersion.WithKind("BGPAdvertisement")),
			},
		},
		Spec: bgpv1alpha1.BGPRoutePolicySpec{
			Type:         "Export",
			PeerSelector: advert.Spec.PeerSelector,
			Statements: []bgpv1alpha1.PolicyStatement{
				{
					PrefixSet: prefixMatches,
					Action:    "Accept",
				},
			},
		},
	}

	var existing bgpv1alpha1.BGPRoutePolicy
	err := r.Get(ctx, types.NamespacedName{Name: policyName}, &existing)
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("get synthesized policy %s: %w", policyName, err)
		}
		if createErr := r.Create(ctx, desired); createErr != nil && !errors.IsAlreadyExists(createErr) {
			return fmt.Errorf("create synthesized policy %s: %w", policyName, createErr)
		}
		log.Printf("bgp/advert: created synthesized export policy %s", policyName)
		return nil
	}

	// Update if spec differs.
	patch := client.MergeFrom(existing.DeepCopy())
	existing.Spec = desired.Spec
	if err := r.Patch(ctx, &existing, patch); err != nil {
		return fmt.Errorf("patch synthesized policy %s: %w", policyName, err)
	}
	return nil
}

// setAdvertisedFalse sets the Advertised condition to False and requeues.
func (r *AdvertisementReconciler) setAdvertisedFalse(ctx context.Context, advert *bgpv1alpha1.BGPAdvertisement, msg string) (reconcile.Result, error) {
	patch := client.MergeFrom(advert.DeepCopy())
	apimeta.SetStatusCondition(&advert.Status.Conditions, metav1.Condition{
		Type:               BGPAdvertisementAdvertised,
		Status:             metav1.ConditionFalse,
		Reason:             "Error",
		Message:            msg,
		ObservedGeneration: advert.Generation,
	})
	if err := r.Status().Patch(ctx, advert, patch); err != nil {
		log.Printf("bgp/advert: patch status: %v", err)
	}
	RecordAdvertisedPrefixes(advert.Name, 0)
	return ctrl.Result{}, fmt.Errorf("%s", msg)
}

// mapSessionToAdvertisements returns reconcile requests for BGPAdvertisements
// with a non-nil peerSelector when a BGPSession changes.
func (r *AdvertisementReconciler) mapSessionToAdvertisements(ctx context.Context, obj client.Object) []reconcile.Request {
	var advertList bgpv1alpha1.BGPAdvertisementList
	if err := r.List(ctx, &advertList); err != nil {
		log.Printf("bgp/advert: list BGPAdvertisements for session change: %v", err)
		return nil
	}

	var requests []reconcile.Request
	for _, advert := range advertList.Items {
		if advert.Spec.PeerSelector != nil {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: advert.Name},
			})
		}
	}
	return requests
}

// localEndpointAddress looks up the BGPEndpoint identified by LocalEndpoint and
// returns its spec.address as a net.IP.
func (r *AdvertisementReconciler) localEndpointAddress(ctx context.Context) (net.IP, error) {
	endpointName := r.LocalEndpoint
	var ep bgpv1alpha1.BGPEndpoint
	if err := r.Get(ctx, types.NamespacedName{Name: endpointName}, &ep); err != nil {
		return nil, fmt.Errorf("get BGPEndpoint %s: %w", endpointName, err)
	}
	ip := net.ParseIP(ep.Spec.Address)
	if ip == nil {
		return nil, fmt.Errorf("BGPEndpoint %s has invalid address %q", endpointName, ep.Spec.Address)
	}
	return ip, nil
}

// SetupWithManager registers the AdvertisementReconciler with the controller-runtime manager.
func (r *AdvertisementReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPAdvertisement{}).
		Watches(
			&bgpv1alpha1.BGPSession{},
			handler.EnqueueRequestsFromMapFunc(r.mapSessionToAdvertisements),
		).
		Complete(r)
}

// addPathIPv6Prefix injects (or withdraws) an IPv6 CIDR prefix into GoBGP's global RIB.
// When isWithdraw is true, the path is withdrawn. communities and localPref are optional
// path attributes. This is the canonical AddPath helper for the controller package.
func addPathIPv6Prefix(ctx context.Context, c gobgpapi.GobgpApiClient, cidr string, localIP net.IP, isWithdraw bool, communities []string, localPref *uint32) error {
	_, prefix, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse prefix %s: %w", cidr, err)
	}
	prefixLen, _ := prefix.Mask.Size()

	nlri, err := anypb.New(&gobgpapi.IPAddressPrefix{
		PrefixLen: uint32(prefixLen),
		Prefix:    prefix.IP.String(),
	})
	if err != nil {
		return fmt.Errorf("marshal NLRI: %w", err)
	}

	origin, err := anypb.New(&gobgpapi.OriginAttribute{Origin: 0}) // IGP
	if err != nil {
		return fmt.Errorf("marshal origin: %w", err)
	}

	mpReach, err := anypb.New(&gobgpapi.MpReachNLRIAttribute{
		Family: &gobgpapi.Family{
			Afi:  gobgpapi.Family_AFI_IP6,
			Safi: gobgpapi.Family_SAFI_UNICAST,
		},
		NextHops: []string{localIP.String()},
		Nlris:    []*anypb.Any{nlri},
	})
	if err != nil {
		return fmt.Errorf("marshal mp_reach: %w", err)
	}

	pattrs := []*anypb.Any{origin, mpReach}

	// Encode communities if provided.
	if len(communities) > 0 {
		commVals := make([]uint32, 0, len(communities))
		for _, comm := range communities {
			v, parseErr := parseCommunity(comm)
			if parseErr != nil {
				log.Printf("bgp/advert: skip invalid community %q: %v", comm, parseErr)
				continue
			}
			commVals = append(commVals, v)
		}
		if len(commVals) > 0 {
			commAttr, err := anypb.New(&gobgpapi.CommunitiesAttribute{Communities: commVals})
			if err != nil {
				return fmt.Errorf("marshal communities: %w", err)
			}
			pattrs = append(pattrs, commAttr)
		}
	}

	// Encode LOCAL_PREF if provided.
	if localPref != nil {
		lpAttr, err := anypb.New(&gobgpapi.LocalPrefAttribute{LocalPref: *localPref})
		if err != nil {
			return fmt.Errorf("marshal localPref: %w", err)
		}
		pattrs = append(pattrs, lpAttr)
	}

	_, err = c.AddPath(ctx, &gobgpapi.AddPathRequest{
		TableType: gobgpapi.TableType_GLOBAL,
		Path: &gobgpapi.Path{
			Family: &gobgpapi.Family{
				Afi:  gobgpapi.Family_AFI_IP6,
				Safi: gobgpapi.Family_SAFI_UNICAST,
			},
			Nlri:       nlri,
			Pattrs:     pattrs,
			IsWithdraw: isWithdraw,
		},
	})
	return err
}

// parseCommunity parses a BGP community string "AS:value" into a uint32.
func parseCommunity(s string) (uint32, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid community format %q (expected AS:value)", s)
	}
	var asn, val uint32
	if _, err := fmt.Sscanf(parts[0], "%d", &asn); err != nil {
		return 0, fmt.Errorf("parse ASN in community %q: %w", s, err)
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &val); err != nil {
		return 0, fmt.Errorf("parse value in community %q: %w", s, err)
	}
	return (asn << 16) | (val & 0xFFFF), nil
}

// exportPolicyName returns the deterministic BGPRoutePolicy name for a BGPAdvertisement.
func exportPolicyName(advertName string) string {
	return "bgpadvert-" + advertName + "-export"
}

// parsePrefixAnnotation parses the comma-separated last-prefixes annotation value.
func parsePrefixAnnotation(annotation string) map[string]struct{} {
	result := make(map[string]struct{})
	if annotation == "" {
		return result
	}
	for _, p := range strings.Split(annotation, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			result[p] = struct{}{}
		}
	}
	return result
}

// sliceToSet converts a string slice to a set map.
func sliceToSet(items []string) map[string]struct{} {
	result := make(map[string]struct{}, len(items))
	for _, item := range items {
		result[item] = struct{}{}
	}
	return result
}

// setDifference returns items in a that are not in b.
func setDifference(a, b map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{})
	for k := range a {
		if _, ok := b[k]; !ok {
			result[k] = struct{}{}
		}
	}
	return result
}
