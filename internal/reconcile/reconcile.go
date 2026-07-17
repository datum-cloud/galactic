// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reconcile translates BGP CRDs into DesiredRouter values
// that can be applied to a RouterRuntime backend.
package reconcile

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// legacySRv6SIDAnnotation is the pre-VRFID/Function fallback annotation used
// when a BGPAdvertisement or its BGPRouter has not yet been migrated to the
// RFC 9800 NEXT-CSID uSID fields (VRFID/Function on the advertisement,
// SRv6Locator/NodeID on the router). This keeps existing containerlab
// labs/e2e fixtures working since their BGPRouter definitions may not yet set
// NodeID.
const legacySRv6SIDAnnotation = "galactic.datum.net/srv6-sid"

// Reconciler assembles DesiredRouter values from BGP CRDs.
type Reconciler struct {
	client       client.Client
	nodeName     string
	routerMode   string
	localAddress string
}

// New returns a Reconciler for the given node, router mode, and local BGP address.
// localAddress, when non-empty, is used as the EVPN next-hop instead of the
// node's first IPv6 InternalIP — required when the node InternalIP is not
// reachable via the SRv6 transit mesh (e.g. Kind/ContainerLab Docker bridge).
func New(c client.Client, nodeName, routerMode, localAddress string) *Reconciler {
	return &Reconciler{
		client:       c,
		nodeName:     nodeName,
		routerMode:   routerMode,
		localAddress: localAddress,
	}
}

// BuildDesiredRouter assembles the full DesiredRouter from BGP CRDs for
// the given BGPRouter. It returns (nil, nil) if the router should be silently
// skipped (wrong node or wrong role). It returns (nil, err) on error.
func (r *Reconciler) BuildDesiredRouter(
	ctx context.Context, router *bgpv1alpha1.BGPRouter,
) (*model.DesiredRouter, error) {
	// Node check: skip routers that don't target this node.
	if router.Spec.TargetRef.Name != r.nodeName {
		return nil, nil
	}

	// Role check.
	wantRole := bgpv1alpha1.RouterRole(r.routerMode)
	if !slices.Contains(router.Spec.Roles, wantRole) {
		return nil, nil
	}
	if len(router.Spec.Roles) > 1 {
		return nil, fmt.Errorf("multi-role routers not supported: router %s/%s has roles %v",
			router.Namespace, router.Name, router.Spec.Roles)
	}

	namespace := router.Namespace

	// Gather peers.
	peers, err := r.gatherPeers(ctx, router)
	if err != nil {
		return nil, fmt.Errorf("gather peers for router %s/%s: %w", namespace, router.Name, err)
	}

	// Gather policies.
	policies, err := r.gatherPolicies(ctx, router)
	if err != nil {
		return nil, fmt.Errorf("gather policies for router %s/%s: %w", namespace, router.Name, err)
	}

	// Gather advertisements.
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := r.client.List(ctx, advList,
		client.InNamespace(namespace),
		client.MatchingFields{".spec.routerRef.name": router.Name},
	); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements for router %s/%s: %w", namespace, router.Name, err)
	}

	// Gather VRF instances. A node hosts one BGPVRFInstance per VPC attachment,
	// which can number in the thousands, so every instance targeting this
	// router must be carried into DesiredRouter — not just the first.
	vrfList := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := r.client.List(ctx, vrfList,
		client.InNamespace(namespace),
		client.MatchingFields{".spec.routerRef.name": router.Name},
	); err != nil {
		return nil, fmt.Errorf("list BGPVRFInstances for router %s/%s: %w", namespace, router.Name, err)
	}
	vrfInstances := make([]model.DesiredVRFInstance, len(vrfList.Items))
	for i, v := range vrfList.Items {
		vrfInstances[i] = buildVRFInstance(v)
	}

	// Resolve the EVPN next-hop. When localAddress is set (e.g. from
	// BGP_LOCAL_ADDRESS), use it directly — it is the transit-reachable
	// address. Fall back to the node's first IPv6 InternalIP only when
	// localAddress is not configured.
	var nextHop string
	if r.localAddress != "" {
		nextHop = r.localAddress
	} else {
		var err error
		nextHop, err = r.resolveNodeIPv6(ctx, router.Spec.TargetRef.Name)
		if err != nil {
			return nil, fmt.Errorf("resolve node IPv6 address for %s: %w", router.Spec.TargetRef.Name, err)
		}
	}

	// Require a next-hop when any advertisement uses the EVPN address family.
	if nextHop == "" {
		for _, adv := range advList.Items {
			if adv.Spec.AddressFamily.AFI == bgpv1alpha1.AFIL2VPN {
				return nil, fmt.Errorf("node %s has no IPv6 InternalIP; EVPN advertisements require it",
					router.Spec.TargetRef.Name)
			}
		}
	}

	// Build DesiredRouter.
	desired := &model.DesiredRouter{
		Namespace:       namespace,
		Name:            router.Name,
		LocalASN:        router.Spec.LocalASN,
		RouterID:        router.Spec.RouterID,
		AddressFamilies: router.Spec.AddressFamilies,
		Peers:           peers,
		VRFInstances:    vrfInstances,
		Policies:        policies,
	}

	// Build advertisements.
	for _, adv := range advList.Items {
		if err := validateAFI(adv.Spec.AddressFamily); err != nil {
			return nil, fmt.Errorf("BGPAdvertisement %s/%s invalid address family: %w", namespace, adv.Name, err)
		}
		prefixes := make([]string, len(adv.Spec.Prefixes))
		for i, p := range adv.Spec.Prefixes {
			prefixes[i] = string(p)
		}
		communities := make([]string, len(adv.Spec.Communities))
		for i, c := range adv.Spec.Communities {
			communities[i] = string(c)
		}
		srv6SID, err := resolveSRv6SID(router, &adv)
		if err != nil {
			return nil, fmt.Errorf("BGPAdvertisement %s/%s: %w", namespace, adv.Name, err)
		}
		desired.Advertisements = append(desired.Advertisements, model.DesiredAdvertisement{
			Name:            adv.Name,
			AddressFamily:   adv.Spec.AddressFamily,
			Prefixes:        prefixes,
			Communities:     communities,
			LocalPreference: int32PtrToUint32Ptr(adv.Spec.LocalPreference),
			NextHop:         nextHop,
			SRv6SID:         srv6SID,
			VRFID:           adv.Spec.VRFID,
		})
	}

	return desired, nil
}

// gatherPeers collects BGPPeers that bind to this router via routerRef or routerSelector.
func (r *Reconciler) gatherPeers(ctx context.Context, router *bgpv1alpha1.BGPRouter) ([]model.DesiredPeer, error) {
	namespace := router.Namespace

	peerList := &bgpv1alpha1.BGPPeerList{}
	if err := r.client.List(ctx, peerList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPPeers: %w", err)
	}

	var peers []model.DesiredPeer
	for _, peer := range peerList.Items {
		if !peerTargetsRouter(&peer, router) {
			continue
		}
		if err := validateAFIsAll(peer.Spec.AddressFamilies); err != nil {
			return nil, fmt.Errorf("BGPPeer %s/%s invalid address family: %w", namespace, peer.Name, err)
		}
		if err := validateTimers(peer.Spec.HoldTime, peer.Spec.KeepaliveTime); err != nil {
			return nil, fmt.Errorf("BGPPeer %s/%s invalid timers: %w", namespace, peer.Name, err)
		}

		dp := model.DesiredPeer{
			Name:            peer.Name,
			PeerASN:         peer.Spec.PeerASN,
			Address:         peer.Spec.Address,
			RemotePort:      1790,
			AddressFamilies: peer.Spec.AddressFamilies,
		}
		if peer.Spec.RemotePort != nil {
			dp.RemotePort = *peer.Spec.RemotePort
		}
		if peer.Spec.HoldTime != nil {
			dp.HoldTime = peer.Spec.HoldTime.Duration
		}
		if peer.Spec.KeepaliveTime != nil {
			dp.KeepaliveTime = peer.Spec.KeepaliveTime.Duration
		}

		// Resolve auth secret.
		if peer.Spec.AuthSecretRef != nil {
			secret := &corev1.Secret{}
			if err := r.client.Get(ctx, types.NamespacedName{
				Namespace: namespace,
				Name:      peer.Spec.AuthSecretRef.Name,
			}, secret); err != nil {
				return nil, fmt.Errorf("get auth secret %s/%s for peer %s: %w",
					namespace, peer.Spec.AuthSecretRef.Name, peer.Name, err)
			}
			dp.AuthPassword = string(secret.Data["password"])
		}

		peers = append(peers, dp)
	}
	return peers, nil
}

// gatherPolicies collects BGPRoutePolicies that bind to this router.
func (r *Reconciler) gatherPolicies(ctx context.Context, router *bgpv1alpha1.BGPRouter) ([]model.DesiredPolicy, error) {
	namespace := router.Namespace

	policyList := &bgpv1alpha1.BGPPolicyList{}
	if err := r.client.List(ctx, policyList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPRoutePolicies: %w", err)
	}

	var policies []model.DesiredPolicy
	for _, policy := range policyList.Items {
		if !policyTargetsRouter(&policy, router) {
			continue
		}

		terms := make([]model.DesiredPolicyTerm, len(policy.Spec.Terms))
		for i, term := range policy.Spec.Terms {
			if term.Match.Any && len(term.Match.AddressFamilies) > 0 {
				return nil, fmt.Errorf("BGPPolicy %s/%s term %d: any=true is mutually exclusive with addressFamilies",
					namespace, policy.Name, term.Sequence)
			}
			dt := model.DesiredPolicyTerm{
				Sequence: term.Sequence,
				Match: model.DesiredPolicyMatch{
					Any:             term.Match.Any,
					AddressFamilies: term.Match.AddressFamilies,
				},
				Action: term.Action,
			}
			if term.Set != nil {
				ds := &model.DesiredPolicySetActions{}
				if term.Set.Communities != nil {
					ds.CommunitiesAdd = term.Set.Communities.Add
					ds.CommunitiesRemove = term.Set.Communities.Remove
				}
				ds.LocalPreference = int32PtrToUint32Ptr(term.Set.LocalPreference)
				dt.Set = ds
			}
			terms[i] = dt
		}
		// Sort terms ascending by Sequence.
		sort.Slice(terms, func(i, j int) bool { return terms[i].Sequence < terms[j].Sequence })

		policies = append(policies, model.DesiredPolicy{
			Name:      policy.Name,
			Direction: policy.Spec.Direction,
			Terms:     terms,
		})
	}
	return policies, nil
}

// resolveNodeIPv6 returns the primary IPv6 InternalIP for the named node.
func (r *Reconciler) resolveNodeIPv6(ctx context.Context, nodeName string) (string, error) {
	node := &corev1.Node{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
		return "", fmt.Errorf("get node %s: %w", nodeName, err)
	}
	for _, addr := range node.Status.Addresses {
		if addr.Type != corev1.NodeInternalIP {
			continue
		}
		ip, err := netip.ParseAddr(addr.Address)
		if err != nil {
			continue
		}
		if ip.Is6() {
			return addr.Address, nil
		}
	}
	return "", nil
}

// peerTargetsRouter returns true if the peer binds to the given router via
// routerRef or routerSelector.
func peerTargetsRouter(peer *bgpv1alpha1.BGPPeer, router *bgpv1alpha1.BGPRouter) bool {
	if peer.Spec.RouterRef != nil {
		return peer.Spec.RouterRef.Name == router.Name
	}
	if peer.Spec.RouterSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
			MatchLabels:      peer.Spec.RouterSelector.MatchLabels,
			MatchExpressions: peer.Spec.RouterSelector.MatchExpressions,
		})
		if err != nil {
			return false
		}
		return sel.Matches(labels.Set(router.Labels))
	}
	return false
}

// policyTargetsRouter returns true if the policy binds to the given router.
func policyTargetsRouter(policy *bgpv1alpha1.BGPPolicy, router *bgpv1alpha1.BGPRouter) bool {
	if policy.Spec.RouterRef != nil {
		return policy.Spec.RouterRef.Name == router.Name
	}
	if policy.Spec.RouterSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
			MatchLabels:      policy.Spec.RouterSelector.MatchLabels,
			MatchExpressions: policy.Spec.RouterSelector.MatchExpressions,
		})
		if err != nil {
			return false
		}
		return sel.Matches(labels.Set(router.Labels))
	}
	return false
}

// buildVRFInstance converts a BGPVRFInstance CRD into a DesiredVRFInstance.
// VRFID carries straight through; the runtime derives the RFC 4364 Type 1
// route distinguisher ("routerID:vrfID") from it rather than the CRD storing
// one directly.
func buildVRFInstance(v bgpv1alpha1.BGPVRFInstance) model.DesiredVRFInstance {
	importRTs := make([]string, len(v.Spec.ImportRouteTargets))
	for j, rt := range v.Spec.ImportRouteTargets {
		importRTs[j] = rt.Value
	}
	exportRTs := make([]string, len(v.Spec.ExportRouteTargets))
	for j, rt := range v.Spec.ExportRouteTargets {
		exportRTs[j] = rt.Value
	}
	return model.DesiredVRFInstance{
		Name:               v.Name,
		VRFID:              v.Spec.VRFID,
		ImportRouteTargets: importRTs,
		ExportRouteTargets: exportRTs,
	}
}

// resolveSRv6SID computes the SRv6 SID to place in the EVPN GWIPAddress field
// for adv on router. When adv.Spec.VRFID and adv.Spec.Function are both set,
// and router.Spec.SRv6Locator and router.Spec.NodeID are both configured, the
// SID is derived via srv6.ComputeSID (RFC 9800 NEXT-CSID uSID compression).
// Otherwise it falls back to the legacy srv6-sid annotation.
func resolveSRv6SID(router *bgpv1alpha1.BGPRouter, adv *bgpv1alpha1.BGPAdvertisement) (string, error) {
	if adv.Spec.VRFID == nil || adv.Spec.Function == nil ||
		router.Spec.SRv6Locator == "" || router.Spec.NodeID == 0 {
		return adv.Annotations[legacySRv6SIDAnnotation], nil
	}
	sid, err := srv6.ComputeSID(router.Spec.SRv6Locator, router.Spec.NodeID, *adv.Spec.VRFID, *adv.Spec.Function)
	if err != nil {
		return "", fmt.Errorf("compute SRv6 SID: %w", err)
	}
	return sid.String(), nil
}

// validateAFI checks that the AFI/SAFI is one of the supported combinations.
func validateAFI(af bgpv1alpha1.AddressFamily) error {
	switch {
	case af.AFI == bgpv1alpha1.AFIIPv4 && af.SAFI == bgpv1alpha1.SAFIUnicast:
		return nil
	case af.AFI == bgpv1alpha1.AFIIPv6 && af.SAFI == bgpv1alpha1.SAFIUnicast:
		return nil
	case af.AFI == bgpv1alpha1.AFIL2VPN && af.SAFI == bgpv1alpha1.SAFIEVPN:
		return nil
	default:
		return fmt.Errorf("unsupported AFI/SAFI: %s/%s", af.AFI, af.SAFI)
	}
}

// validateAFIsAll validates each address family in a slice.
func validateAFIsAll(afs []bgpv1alpha1.AddressFamily) error {
	for _, af := range afs {
		if err := validateAFI(af); err != nil {
			return err
		}
	}
	return nil
}

// int32PtrToUint32Ptr converts *int32 to *uint32 for LOCAL_PREF, which the
// BGP API expresses as int32 but GoBGP and BGP RFC 4271 use uint32.
func int32PtrToUint32Ptr(v *int32) *uint32 {
	if v == nil {
		return nil
	}
	u := uint32(*v)
	return &u
}

// validateTimers checks that KeepaliveTime <= HoldTime/3 when HoldTime > 0.
func validateTimers(holdTime, keepaliveTime *metav1.Duration) error {
	if holdTime == nil || keepaliveTime == nil {
		return nil
	}
	hold := holdTime.Duration
	keepalive := keepaliveTime.Duration
	if hold == 0 {
		return nil
	}
	maxKeepalive := hold / 3
	if keepalive > maxKeepalive {
		return fmt.Errorf("keepaliveTime %v must be <= holdTime/3 (%v)", keepalive, maxKeepalive)
	}
	return nil
}
