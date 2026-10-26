// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/gateway"
)

const serviceAddressFinalizer = "galactic.datum.net/address-withdrawal"
const serviceAddressLabel = "galactic.datum.net/service-address"
const sharedAddressLeaseDuration = 30 * time.Second
const sharedAddressRenewInterval = 5 * time.Second

type ownedVIPEngine interface {
	SetOwnedVIPs(context.Context, []netip.Addr) error
	SetBlockedVIPs(context.Context, []netip.Addr) error
}

type addressInventory map[string]*bgpv1alpha1.NetworkServiceAddress

func (r *NetworkGatewayReconciler) prepareAddressInventory(
	ctx context.Context,
	namespace string,
	rules []bgpv1alpha1.NetworkService,
) (addressInventory, error) {
	list := &bgpv1alpha1.NetworkServiceAddressList{}
	if err := r.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	addresses := addressInventory{}
	var owned []netip.Addr
	for i := range list.Items {
		address := &list.Items[i]
		vip, err := netip.ParseAddr(address.Spec.VIPAddress)
		if err != nil || !vip.Is6() || vip.Is4In6() {
			return nil, fmt.Errorf("invalid shared VIP %q", address.Spec.VIPAddress)
		}
		owned = append(owned, vip)
		if address.DeletionTimestamp.IsZero() && !controllerutil.ContainsFinalizer(address, serviceAddressFinalizer) {
			base := address.DeepCopy()
			controllerutil.AddFinalizer(address, serviceAddressFinalizer)
			patch := client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})
			if err := r.Patch(ctx, address, patch); err != nil {
				return nil, err
			}
		}
		if _, exists := addresses[vip.String()]; exists {
			addresses[vip.String()] = nil
		} else {
			addresses[vip.String()] = address
		}
	}
	for _, rule := range rules {
		if rule.Spec.AddressGroup == nil {
			continue
		}
		for _, value := range rule.Spec.VIPAddresses {
			if vip, err := netip.ParseAddr(value); err == nil {
				owned = append(owned, vip)
			}
		}
	}
	if engine, ok := r.Engine.(ownedVIPEngine); ok {
		if err := engine.SetOwnedVIPs(ctx, owned); err != nil {
			return nil, err
		}
		if err := engine.SetBlockedVIPs(ctx, owned); err != nil {
			return nil, err
		}
	} else if len(owned) > 0 {
		return nil, errors.New("gateway lacks shared-address isolation")
	}
	return addresses, nil
}

func listenerInterval(listener bgpv1alpha1.NetworkServiceAddressListener) (uint16, uint16, error) {
	if listener.Protocol != bgpv1alpha1.NetworkServiceProtocolTCP &&
		listener.Protocol != bgpv1alpha1.NetworkServiceProtocolUDP {
		return 0, 0, errors.New("unsupported listener protocol")
	}
	if p := listener.PortRange; p != nil {
		if listener.Port != 0 || listener.Protocol != bgpv1alpha1.NetworkServiceProtocolUDP || p.Start < 1 ||
			p.End < p.Start ||
			p.End > 65535 {
			return 0, 0, errors.New("invalid listener range")
		}
		return uint16(p.Start), uint16(p.End), nil
	}
	if listener.Port < 1 || listener.Port > 65535 {
		return 0, 0, errors.New("invalid listener port")
	}
	return uint16(listener.Port), uint16(listener.Port), nil
}

func validAddressInventory(address *bgpv1alpha1.NetworkServiceAddress) error {
	if address == nil || !address.DeletionTimestamp.IsZero() {
		return errors.New("address inventory is missing, conflicted or withdrawing")
	}
	g := &address.Spec.Group
	if g.UID == "" || g.Generation < 1 || g.Revision == "" || len(g.Listeners) == 0 || len(g.Listeners) > 16 {
		return errors.New("address inventory identity is incomplete")
	}
	for i, listener := range g.Listeners {
		start, end, err := listenerInterval(listener)
		if err != nil {
			return err
		}
		for _, other := range g.Listeners[:i] {
			otherStart, otherEnd, err := listenerInterval(other)
			if err != nil {
				return err
			}
			if other.Name == listener.Name ||
				other.Protocol == listener.Protocol && intervalsIntersect(start, end, otherStart, otherEnd) {
				return errors.New("address inventory contains intersecting listeners")
			}
		}
	}
	return nil
}

func addressRuleError(rule *bgpv1alpha1.NetworkService, addresses addressInventory) error {
	group := rule.Spec.AddressGroup
	if group == nil {
		for _, vip := range rule.Spec.VIPAddresses {
			if _, owned := addresses[canonicalVIP(vip)]; owned {
				return errors.New("VIP is reserved by an address inventory")
			}
		}
		if rule.Spec.PortRange != nil {
			return errors.New("UDP range requires an address inventory")
		}
		return nil
	}
	if len(rule.Spec.VIPAddresses) != 1 {
		return errors.New("shared service requires exactly one VIP")
	}
	address := addresses[canonicalVIP(rule.Spec.VIPAddresses[0])]
	if err := validAddressInventory(address); err != nil {
		return err
	}
	want := address.Spec.Group
	if address.Spec.VPCRef != rule.Spec.VPCRef || want.UID != group.UID || want.Generation != group.Generation ||
		want.Revision != group.Revision ||
		!reflect.DeepEqual(want.Listeners, group.Listeners) {
		return errors.New("service does not match the authoritative address revision")
	}
	for _, listener := range want.Listeners {
		if listener.Name == group.ListenerName && listener.Protocol == rule.Spec.Protocol &&
			listener.Port == rule.Spec.Port &&
			reflect.DeepEqual(listener.PortRange, rule.Spec.PortRange) {
			return nil
		}
	}
	return errors.New("service socket is not declared in address inventory")
}

func (r *NetworkGatewayReconciler) gateAddressRules(
	addresses addressInventory,
	desired *gateway.EngineState,
	outcomes []ruleOutcome,
	leaseSupport bool,
) {
	for i := range outcomes {
		o := &outcomes[i]
		if err := addressRuleError(o.rule, addresses); err != nil ||
			o.rule.Spec.AddressGroup != nil && (!o.rule.DeletionTimestamp.IsZero() || !leaseSupport) {
			if err == nil {
				err = errors.New("listener is withdrawing or router lease support is unavailable")
			}
			delete(desired.Rules, o.rule.Namespace+"/"+o.rule.Name)
			o.buildErr, o.unaccepted, o.draining = err, false, false
		}
	}
}

func addressAdvertisementName(address, node string) string {
	sum := sha256.Sum256([]byte(address + "/" + node))
	return fmt.Sprintf("nlb-address-%x", sum[:16])
}

func (r *NetworkGatewayReconciler) reconcileAddressAdvertisement(
	ctx context.Context,
	address *bgpv1alpha1.NetworkServiceAddress,
	router string,
	serve bool,
) (bool, error) {
	key := types.NamespacedName{Namespace: address.Namespace, Name: addressAdvertisementName(address.Name, r.NodeName)}
	adv := &bgpv1alpha1.BGPAdvertisement{}
	err := r.Get(ctx, key, adv)
	if !serve || router == "" || !address.DeletionTimestamp.IsZero() {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if err := r.Delete(ctx, adv, client.Preconditions{UID: &adv.UID}); err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}
		return false, nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}
	if pending, err := r.withdrawLegacyAddressAdvertisements(ctx, address); err != nil || pending {
		return false, err
	}
	previous := adv.DeepCopy()
	previousInstalled := err == nil && previous.DeletionTimestamp.IsZero() && advertisementInstalled(previous) &&
		previous.Spec.ExpiresAt != nil && previous.Spec.ExpiresAt.After(time.Now())
	if err == nil && !previous.DeletionTimestamp.IsZero() {
		return false, nil
	}
	adv = &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, adv, func() error {
		adv.Labels = map[string]string{
			serviceAddressLabel: address.Name,
			gatewayNodeLabel:    gatewayNodeLabelValue(r.NodeName),
		}
		deadline := adv.Spec.ExpiresAt
		if deadline == nil || time.Until(deadline.Time) < sharedAddressLeaseDuration-sharedAddressRenewInterval {
			renewed := metav1.NewTime(time.Now().Add(sharedAddressLeaseDuration))
			deadline = &renewed
		}
		adv.Spec = bgpv1alpha1.BGPAdvertisementSpec{ExpiresAt: deadline, RouterRef: bgpv1alpha1.RouterRef{Name: router},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(address.Spec.VIPAddress + "/128")}}
		return controllerutil.SetOwnerReference(address, adv, r.Scheme)
	})
	previousRoute := previous.Spec.DeepCopy()
	previousRoute.ExpiresAt = nil
	currentRoute := adv.Spec.DeepCopy()
	currentRoute.ExpiresAt = nil
	unchangedLeaseRenewal := previousInstalled && reflect.DeepEqual(previousRoute, currentRoute)
	return err == nil && (advertisementInstalled(adv) || unchangedLeaseRenewal), err
}

func (r *NetworkGatewayReconciler) publishAddressOutcomes(
	ctx context.Context,
	namespace string,
	addresses addressInventory,
	outcomes []ruleOutcome,
	status gateway.EngineStatus,
	router string,
) (map[string]bool, error) {
	announced := map[string]bool{}
	failed := map[string]bool{}
	for _, s := range status.Rules {
		if !s.Applied || s.Error != "" {
			failed[s.Key] = true
		}
	}
	var errs []error
	all := &bgpv1alpha1.NetworkServiceAddressList{}
	if err := r.List(ctx, all, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	for i := range all.Items {
		address := &all.Items[i]
		vip := canonicalVIP(address.Spec.VIPAddress)
		serve := false
		for _, o := range outcomes {
			if o.rule.Spec.AddressGroup == nil || o.rule.Spec.AddressGroup.UID != address.Spec.Group.UID ||
				o.buildErr != nil || o.unaccepted || o.draining || !o.rule.DeletionTimestamp.IsZero() {
				continue
			}
			if !failed[o.desired.Key] && len(o.desired.Backends) > 0 {
				serve = true
			}
		}
		// Any failed apply/removal can leave an obsolete match on this address.
		if !status.Healthy || validAddressInventory(address) != nil || addresses[vip] == nil {
			serve = false
		}
		installed, err := r.reconcileAddressAdvertisement(ctx, address, router, serve)
		if err != nil {
			errs = append(errs, err)
		}
		announced[vip] = installed
		if err := r.reportAddressNode(ctx, address, serve, installed, status.Healthy); err != nil {
			errs = append(errs, err)
		}
		if !address.DeletionTimestamp.IsZero() && status.Healthy {
			if err := r.finalizeAddress(ctx, address); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return announced, errors.Join(errs...)
}

func (r *NetworkGatewayReconciler) reportAddressNode(
	ctx context.Context,
	address *bgpv1alpha1.NetworkServiceAddress,
	programmed, advertised, converged bool,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &bgpv1alpha1.NetworkServiceAddress{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(address), current); err != nil {
			return client.IgnoreNotFound(err)
		}
		if current.UID != address.UID || current.Generation != address.Generation {
			return errors.New("address revision changed during programming")
		}
		changed := false
		for _, item := range []struct {
			kind  string
			value bool
		}{{programmedConditionType(r.NodeName), programmed}, {advertisedConditionType(r.NodeName), advertised}} {
			condition := metav1.Condition{
				Type:               item.kind,
				Status:             metav1.ConditionFalse,
				Reason:             "NotServed",
				Message:            "Address is not served on this gateway",
				ObservedGeneration: current.Generation,
			}
			if item.value {
				condition.Status, condition.Reason = metav1.ConditionTrue, "Served"
				condition.Message = "Address serves at least one listener on this gateway"
			}
			if !converged {
				condition.Status, condition.Reason = metav1.ConditionUnknown, "CleanupUnconfirmed"
				condition.Message = "Address forwarding cleanup is not confirmed"
			}
			changed = meta.SetStatusCondition(&current.Status.Conditions, condition) || changed
		}
		current.Status.ObservedGeneration = current.Generation
		if changed {
			return r.Status().Update(ctx, current)
		}
		return nil
	})
}

func (r *NetworkGatewayReconciler) finalizeAddress(
	ctx context.Context,
	address *bgpv1alpha1.NetworkServiceAddress,
) error {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	current := &bgpv1alpha1.NetworkServiceAddress{}
	if err := reader.Get(ctx, client.ObjectKeyFromObject(address), current); err != nil {
		return client.IgnoreNotFound(err)
	}
	if current.UID != address.UID || current.DeletionTimestamp.IsZero() {
		return nil
	}
	gateways := &bgpv1alpha1.NetworkGatewayList{}
	if err := reader.List(ctx, gateways, client.InNamespace(address.Namespace)); err != nil {
		return err
	}
	nodes := map[string]bool{}
	for _, gw := range gateways.Items {
		nodes[gw.Spec.TargetRef.Name] = true
	}
	for _, condition := range current.Status.Conditions {
		if node, ok := gatewayNodeConditionNode(condition.Type); ok {
			nodes[node] = true
		}
	}
	if len(nodes) == 0 {
		return nil
	}
	for node := range nodes {
		for _, kind := range []string{programmedConditionType(node), advertisedConditionType(node)} {
			condition := meta.FindStatusCondition(current.Status.Conditions, kind)
			if condition == nil || condition.ObservedGeneration != current.Generation ||
				condition.Status != metav1.ConditionFalse {
				return nil
			}
		}
	}
	ads := &bgpv1alpha1.BGPAdvertisementList{}
	selector := client.MatchingLabels{serviceAddressLabel: address.Name}
	if err := reader.List(ctx, ads, client.InNamespace(address.Namespace), selector); err != nil {
		return err
	}
	if len(ads.Items) != 0 {
		return nil
	}
	services := &bgpv1alpha1.NetworkServiceList{}
	if err := reader.List(ctx, services); err != nil {
		return err
	}
	for _, service := range services.Items {
		if service.Spec.AddressGroup != nil && service.Spec.AddressGroup.UID == address.Spec.Group.UID {
			return nil
		}
	}
	base := current.DeepCopy()
	controllerutil.RemoveFinalizer(current, serviceAddressFinalizer)
	return r.Patch(ctx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

func groupedRuleWithdrawn(rule *bgpv1alpha1.NetworkService, nodes []string) bool {
	for _, c := range rule.Status.Conditions {
		if node, ok := gatewayNodeConditionNode(c.Type); ok && !slices.Contains(nodes, node) {
			nodes = append(nodes, node)
		}
	}
	if len(nodes) == 0 {
		return false
	}
	for _, node := range nodes {
		for _, kind := range []string{programmedConditionType(node), advertisedConditionType(node)} {
			condition := meta.FindStatusCondition(rule.Status.Conditions, kind)
			if condition == nil || condition.ObservedGeneration != rule.Generation ||
				condition.Status != metav1.ConditionFalse ||
				time.Since(condition.LastTransitionTime.Time) < time.Second {
				return false
			}
		}
	}
	return true
}

func (r *NetworkGatewayReconciler) servingCapabilities(leaseSupport bool) []string {
	if r.Disabled || !leaseSupport {
		return nil
	}
	engine, ok := r.Engine.(interface {
		SupportsOwnedVIPs() bool
		SupportsPortRanges() bool
	})
	if !ok || !engine.SupportsOwnedVIPs() {
		return nil
	}
	caps := []string{bgpv1alpha1.CapabilitySharedAddressListeners}
	if engine.SupportsPortRanges() {
		caps = append(caps, bgpv1alpha1.CapabilityUDPPortRanges)
	}
	return caps
}

func canonicalVIP(value string) string {
	if vip, err := netip.ParseAddr(value); err == nil {
		return vip.String()
	}
	return value
}

// primeGroupedServing invalidates a previous withdrawal acknowledgment before
// an address can start forwarding again at the same object generation. The
// acknowledgment lives in the API, so deletion remains safe across restarts.
func (r *NetworkGatewayReconciler) primeGroupedServing(
	ctx context.Context,
	addresses addressInventory,
	desired gateway.EngineState,
	outcomes []ruleOutcome,
) error {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	for _, o := range outcomes {
		if o.rule.Spec.AddressGroup == nil {
			continue
		}
		if _, active := desired.Rules[o.rule.Namespace+"/"+o.rule.Name]; !active {
			continue
		}
		current := &bgpv1alpha1.NetworkService{}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(o.rule), current); err != nil {
			return err
		}
		if current.UID != o.rule.UID || current.Generation != o.rule.Generation || !current.DeletionTimestamp.IsZero() {
			return errors.New("listener changed before forwarding activation")
		}
		condition := meta.FindStatusCondition(current.Status.Conditions, programmedConditionType(r.NodeName))
		if condition == nil || condition.Status == metav1.ConditionFalse ||
			condition.ObservedGeneration != current.Generation {
			unknown := metav1.Condition{
				Type:    programmedConditionType(r.NodeName),
				Status:  metav1.ConditionUnknown,
				Reason:  "Programming",
				Message: "Listener forwarding activation is in progress",
			}
			adv := unknown
			adv.Type = advertisedConditionType(r.NodeName)
			if err := r.setRuleConditions(ctx, current, unknown, adv, nil, nil); err != nil {
				return err
			}
		}
		address := addresses[canonicalVIP(o.rule.Spec.VIPAddresses[0])]
		if address == nil {
			return errors.New("address inventory disappeared before activation")
		}
		fresh := &bgpv1alpha1.NetworkServiceAddress{}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(address), fresh); err != nil {
			return err
		}
		if fresh.UID != address.UID || fresh.Generation != address.Generation || !fresh.DeletionTimestamp.IsZero() {
			return errors.New("address changed before forwarding activation")
		}
		condition = meta.FindStatusCondition(fresh.Status.Conditions, programmedConditionType(r.NodeName))
		if condition == nil || condition.Status == metav1.ConditionFalse ||
			condition.ObservedGeneration != fresh.Generation {
			if err := r.reportAddressNode(ctx, fresh, false, false, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *NetworkGatewayReconciler) routerLeaseSupport(ctx context.Context, namespace, name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	router := &bgpv1alpha1.BGPRouter{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, router); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	observed := router.Status.LastSuccessfulReconcileTime
	return router.DeletionTimestamp.IsZero() && router.Status.ObservedGeneration == router.Generation &&
		router.Status.SupportsAdvertisementLeases && observed != nil &&
		time.Since(observed.Time) >= 0 && time.Since(observed.Time) <= time.Minute, nil
}

func (r *NetworkGatewayReconciler) withdrawLegacyAddressAdvertisements(ctx context.Context,
	address *bgpv1alpha1.NetworkServiceAddress) (bool, error) {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	legacy := &bgpv1alpha1.BGPAdvertisementList{}
	selector := client.MatchingLabels{gatewayNodeLabel: gatewayNodeLabelValue(r.NodeName)}
	if err := reader.List(ctx, legacy, client.InNamespace(address.Namespace), selector); err != nil {
		return false, err
	}
	pending := false
	for i := range legacy.Items {
		old := &legacy.Items[i]
		if old.Labels[networkRuleLabel] == "" {
			continue
		}
		for _, value := range old.Spec.Prefixes {
			prefix, err := netip.ParsePrefix(string(value))
			if err == nil && prefix.Bits() == 128 && prefix.Addr().String() == canonicalVIP(address.Spec.VIPAddress) {
				pending = true
				if err := r.Delete(ctx, old, client.Preconditions{UID: &old.UID}); client.IgnoreNotFound(err) != nil {
					return false, err
				}
				break
			}
		}
	}
	return pending, nil
}
