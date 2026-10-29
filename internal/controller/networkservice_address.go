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

const reasonAddressWithdrawn = "Withdrawn"

const serviceAddressFinalizer = "galactic.datum.net/address-withdrawal"
const serviceAddressLabel = "galactic.datum.net/service-address"
const serviceAddressNamespaceLabel = "galactic.datum.net/service-address-namespace"
const serviceAddressUIDLabel = "galactic.datum.net/service-address-uid"
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
	list, err := r.servedAddressInventories(ctx, r.Client, namespace)
	if err != nil {
		return nil, err
	}
	addresses := addressInventory{}
	var owned []netip.Addr
	retiredUIDs := map[string]bool{}
	for i := range list.Items {
		address := &list.Items[i]
		if address.Spec.Retired {
			retiredUIDs[address.Spec.Group.UID] = true
		}
		allowed, err := r.addressInScope(ctx, r.Client, address, namespace)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		vip, err := netip.ParseAddr(address.Spec.VIPAddress)
		if err != nil || !vip.Is6() || vip.Is4In6() {
			return nil, fmt.Errorf("invalid shared VIP %q", address.Spec.VIPAddress)
		}
		if addressRetirementAcknowledged(address) {
			retiredUIDs[address.Spec.Group.UID] = true
			continue
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
		if rule.Spec.AddressGroup == nil || retiredUIDs[rule.Spec.AddressGroup.UID] {
			continue
		}
		for _, value := range rule.Spec.VIPAddresses {
			authority := &bgpv1alpha1.NetworkServiceAddress{ObjectMeta: metav1.ObjectMeta{Namespace: rule.Namespace},
				Spec: bgpv1alpha1.NetworkServiceAddressSpec{VPCRef: rule.Spec.VPCRef, VIPAddress: value}}
			allowed, err := r.addressInScope(ctx, r.Client, authority, namespace)
			if err != nil {
				return nil, err
			}
			if !allowed {
				continue
			}
			if vip, err := netip.ParseAddr(value); err == nil {
				owned = append(owned, vip)
			}
		}
	}
	if err := r.prepareOwnedAddresses(ctx, addresses, owned); err != nil {
		return nil, err
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
	if address == nil || address.Spec.Retired || !address.DeletionTimestamp.IsZero() {
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
	gatewayNamespaces ...string,
) (bool, error) {
	objNS := address.Namespace
	if len(gatewayNamespaces) > 0 {
		objNS = gatewayNamespaces[0]
	}
	key := types.NamespacedName{
		Namespace: objNS,
		Name:      addressKeyAdvertisementName(client.ObjectKeyFromObject(address), objNS, r.NodeName),
	}
	adv := &bgpv1alpha1.BGPAdvertisement{}
	err := r.Get(ctx, key, adv)
	if !serve || router == "" || address.Spec.Retired || !address.DeletionTimestamp.IsZero() {
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
	if pending, err := r.withdrawLegacyAddressAdvertisements(ctx, address, objNS); err != nil || pending {
		return false, err
	}
	previous := adv.DeepCopy()
	previousInstalled := err == nil && previous.DeletionTimestamp.IsZero() && advertisementInstalled(previous) &&
		previous.Spec.ExpiresAt != nil && previous.Spec.ExpiresAt.After(time.Now())
	if err == nil && !previous.DeletionTimestamp.IsZero() {
		return false, nil
	}
	if err == nil && previous.Spec.RouterRef.Name != router {
		return false, client.IgnoreNotFound(r.Delete(ctx, previous, client.Preconditions{UID: &previous.UID}))
	}
	adv = &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, adv, func() error {
		adv.Labels = map[string]string{
			serviceAddressLabel:          gatewayNodeLabelValue(address.Name),
			serviceAddressNamespaceLabel: address.Namespace,
			serviceAddressUIDLabel:       string(address.UID),
			gatewayNodeLabel:             gatewayNodeLabelValue(r.NodeName),
		}
		if adv.Annotations == nil {
			adv.Annotations = map[string]string{}
		}
		adv.Annotations[serviceAddressLabel] = address.Name
		deadline := adv.Spec.ExpiresAt
		if deadline == nil || time.Until(deadline.Time) < sharedAddressLeaseDuration-sharedAddressRenewInterval {
			renewed := metav1.NewTime(time.Now().Add(sharedAddressLeaseDuration))
			deadline = &renewed
		}
		adv.Spec = bgpv1alpha1.BGPAdvertisementSpec{ExpiresAt: deadline, RouterRef: bgpv1alpha1.RouterRef{Name: router},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(address.Spec.VIPAddress + "/128")}}
		if address.Namespace == adv.Namespace {
			return controllerutil.SetOwnerReference(address, adv, r.Scheme)
		}
		return nil
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
	all, err := r.servedAddressInventories(ctx, r.Client, namespace)
	if err != nil {
		return nil, err
	}
	for i := range all.Items {
		address := &all.Items[i]
		if addressRetirementAcknowledged(address) {
			continue
		}
		allowed, scopeErr := r.addressInScope(ctx, r.Client, address, namespace)
		if scopeErr != nil {
			errs = append(errs, scopeErr)
			continue
		}
		vip := canonicalVIP(address.Spec.VIPAddress)
		snapshot, known := addresses[vip]
		if allowed && (!known || snapshot != nil && !sameAddressRevision(snapshot, address)) {
			errs = append(errs, errors.New("address revision changed after programming"))
			_, err := r.reconcileAddressAdvertisement(ctx, address, router, false, namespace)
			errs = append(errs, err)
			continue
		}
		serve := addressHasServingOutcome(address, outcomes, failed)
		// Any failed apply/removal can leave an obsolete match on this address.
		converged := status.VIPConverged(netip.MustParseAddr(vip))
		if !allowed || !converged || validAddressInventory(address) != nil || addresses[vip] == nil {
			serve = false
		}
		installed, err := r.reconcileAddressAdvertisement(ctx, address, router, serve, namespace)
		if err != nil {
			errs = append(errs, err)
		}
		if allowed {
			announced[vip] = installed
		}
		if err := r.reportAddressNode(ctx, address, serve, installed, converged); err != nil {
			errs = append(errs, err)
		}
		if (address.Spec.Retired || !address.DeletionTimestamp.IsZero()) && converged {
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
		changed := meta.RemoveStatusCondition(&current.Status.Conditions, stoppedGatewayConditionType(r.NodeName))
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
	if current.UID != address.UID || (!current.Spec.Retired && current.DeletionTimestamp.IsZero()) {
		return nil
	}
	gateways, err := r.addressGateways(ctx, reader, address.Namespace)
	if err != nil {
		return err
	}
	nodes := map[string]bool{}
	currentNodes := map[string]bool{}
	for _, gw := range gateways {
		nodes[gw.Spec.TargetRef.Name] = true
		currentNodes[gw.Spec.TargetRef.Name] = true
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
		if !currentNodes[node] &&
			meta.IsStatusConditionTrue(current.Status.Conditions, stoppedGatewayConditionType(node)) {
			continue
		}
		for _, kind := range []string{programmedConditionType(node), advertisedConditionType(node)} {
			condition := meta.FindStatusCondition(current.Status.Conditions, kind)
			if condition == nil || condition.ObservedGeneration != current.Generation ||
				condition.Status != metav1.ConditionFalse {
				return nil
			}
		}
	}
	ads := &bgpv1alpha1.BGPAdvertisementList{}
	selector := client.MatchingLabels{serviceAddressLabel: gatewayNodeLabelValue(address.Name)}
	if err := reader.List(ctx, ads, selector); err != nil {
		return err
	}
	for _, ad := range ads.Items {
		if addressKeyFromAdvertisement(&ad) == client.ObjectKeyFromObject(address) {
			return nil
		}
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
	bindings := &bgpv1alpha1.ServiceVIPBindingList{}
	if err := reader.List(ctx, bindings); err != nil {
		return err
	}
	for _, binding := range bindings.Items {
		if binding.Spec.SourceRef != nil && binding.Spec.SourceRef.AllocationUID == current.Spec.Group.UID {
			return nil
		}
	}
	if current.Spec.Retired {
		meta.SetStatusCondition(&current.Status.Conditions, metav1.Condition{
			Type: bgpv1alpha1.ConditionTypeAddressRetired, Status: metav1.ConditionTrue,
			Reason: reasonAddressWithdrawn, Message: "The allocation has been permanently retired and forwarding is withdrawn",
			ObservedGeneration: current.Generation,
		})
		current.Status.ObservedGeneration = current.Generation
		return r.Status().Update(ctx, current)
	}
	base := current.DeepCopy()
	controllerutil.RemoveFinalizer(current, serviceAddressFinalizer)
	return r.Patch(ctx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

func groupedRuleWithdrawn(rule *bgpv1alpha1.NetworkService, nodes []string) bool {
	currentNodes := slices.Clone(nodes)
	for _, c := range rule.Status.Conditions {
		if node, ok := gatewayNodeConditionNode(c.Type); ok && !slices.Contains(nodes, node) {
			nodes = append(nodes, node)
		}
	}
	if len(nodes) == 0 {
		return false
	}
	for _, node := range nodes {
		if !slices.Contains(currentNodes, node) &&
			meta.IsStatusConditionTrue(rule.Status.Conditions, stoppedGatewayConditionType(node)) {
			continue
		}
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
	caps := []string{bgpv1alpha1.CapabilitySharedAddressListeners, bgpv1alpha1.CapabilityTerminalAddressRetirement}
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
		if !sameAddressRevision(fresh, address) || fresh.Spec.Retired || !fresh.DeletionTimestamp.IsZero() {
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
	address *bgpv1alpha1.NetworkServiceAddress, namespace string) (bool, error) {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	legacy := &bgpv1alpha1.BGPAdvertisementList{}
	selector := client.MatchingLabels{gatewayNodeLabel: gatewayNodeLabelValue(r.NodeName)}
	if err := reader.List(ctx, legacy, client.InNamespace(namespace), selector); err != nil {
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

func addressRetirementAcknowledged(address *bgpv1alpha1.NetworkServiceAddress) bool {
	condition := meta.FindStatusCondition(address.Status.Conditions, bgpv1alpha1.ConditionTypeAddressRetired)
	return address.Spec.Retired && condition != nil && condition.Status == metav1.ConditionTrue &&
		condition.ObservedGeneration == address.Generation
}

func sameAddressRevision(a, b *bgpv1alpha1.NetworkServiceAddress) bool {
	return a.UID == b.UID && a.Generation == b.Generation && reflect.DeepEqual(a.Spec, b.Spec) &&
		a.DeletionTimestamp.Equal(b.DeletionTimestamp)
}

func (r *NetworkGatewayReconciler) currentAddressInventory(
	ctx context.Context,
	namespace string,
) (addressInventory, error) {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	list, err := r.servedAddressInventories(ctx, reader, namespace)
	if err != nil {
		return nil, err
	}
	current := addressInventory{}
	for i := range list.Items {
		address := &list.Items[i]
		allowed, err := r.addressInScope(ctx, reader, address, namespace)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		if addressRetirementAcknowledged(address) {
			continue
		}
		vip := canonicalVIP(address.Spec.VIPAddress)
		if _, duplicate := current[vip]; duplicate {
			current[vip] = nil
		} else {
			current[vip] = address
		}
	}
	return current, nil
}

func retiredRuleAllocation(
	ctx context.Context,
	reader client.Reader,
	rule *bgpv1alpha1.NetworkService,
	namespace string,
) (bool, error) {
	if rule.Spec.AddressGroup == nil {
		return false, nil
	}
	addresses := &bgpv1alpha1.NetworkServiceAddressList{}
	if err := reader.List(ctx, addresses, client.InNamespace(namespace)); err != nil {
		return false, err
	}
	for _, address := range addresses.Items {
		if address.Spec.Group.UID == rule.Spec.AddressGroup.UID && address.Spec.Retired {
			return true, nil
		}
	}
	return false, nil
}

func (r *ServiceVIPBindingReconciler) bindingSourceAllowed(
	ctx context.Context,
	binding *bgpv1alpha1.ServiceVIPBinding,
) (bool, error) {
	source := binding.Spec.SourceRef
	if source == nil {
		return true, nil
	}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	rule := &bgpv1alpha1.NetworkService{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: source.Namespace, Name: source.Name}, rule); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if rule.UID != source.UID || rule.Generation != source.Generation || rule.Spec.AddressGroup == nil ||
		rule.Spec.AddressGroup.UID != source.AllocationUID ||
		!rule.DeletionTimestamp.IsZero() {
		return false, nil
	}
	addresses := &bgpv1alpha1.NetworkServiceAddressList{}
	if err := reader.List(ctx, addresses, client.InNamespace(source.Namespace)); err != nil {
		return false, err
	}
	for i := range addresses.Items {
		address := &addresses.Items[i]
		if address.Spec.Group.UID == source.AllocationUID {
			if address.Spec.Retired || !address.DeletionTimestamp.IsZero() {
				return false, nil
			}
			return addressRuleError(rule, addressInventory{canonicalVIP(address.Spec.VIPAddress): address}) == nil, nil
		}
	}
	return false, nil
}

func stoppedGatewayConditionType(node string) string { return node + "/Stopped" }

func stoppedGatewayConditions(conditions *[]metav1.Condition, node string, generation int64) {
	for _, kind := range []string{programmedConditionType(node), advertisedConditionType(node)} {
		meta.SetStatusCondition(
			conditions,
			metav1.Condition{Type: kind, Status: metav1.ConditionFalse, ObservedGeneration: generation,
				Reason: "DataplaneStopped", Message: "Gateway forwarding stopped and its advertisements are absent"},
		)
	}
	meta.SetStatusCondition(
		conditions,
		metav1.Condition{
			Type:               stoppedGatewayConditionType(node),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: generation,
			Reason:             "DataplaneStopped",
			Message:            "Gateway forwarding stopped and its advertisements are absent",
		},
	)
}

func (r *NetworkGatewayReconciler) acknowledgeStoppedGateway(ctx context.Context, namespace string) (bool, error) {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	ads := &bgpv1alpha1.BGPAdvertisementList{}
	selector := client.MatchingLabels{gatewayNodeLabel: gatewayNodeLabelValue(r.NodeName)}
	if err := reader.List(ctx, ads, client.InNamespace(namespace), selector); err != nil {
		return true, err
	}
	if len(ads.Items) > 0 {
		return true, nil
	}
	addresses, err := r.servedAddressInventories(ctx, reader, namespace)
	if err != nil {
		return true, err
	}
	for i := range addresses.Items {
		address := &addresses.Items[i]
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			current := &bgpv1alpha1.NetworkServiceAddress{}
			if err := reader.Get(ctx, client.ObjectKeyFromObject(address), current); err != nil {
				return client.IgnoreNotFound(err)
			}
			if current.UID != address.UID {
				return errors.New("address identity changed during gateway retirement")
			}
			stoppedGatewayConditions(&current.Status.Conditions, r.NodeName, current.Generation)
			return r.Status().Update(ctx, current)
		}); err != nil {
			return true, err
		}
	}
	rules := &bgpv1alpha1.NetworkServiceList{}
	if err := reader.List(ctx, rules); err != nil {
		return true, err
	}
	for i := range rules.Items {
		rule := &rules.Items[i]
		if rule.Spec.AddressGroup == nil {
			continue
		}
		known := false
		for _, address := range addresses.Items {
			if address.Spec.Group.UID == rule.Spec.AddressGroup.UID {
				known = true
				break
			}
		}
		if !known {
			continue
		}
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			current := &bgpv1alpha1.NetworkService{}
			if err := reader.Get(ctx, client.ObjectKeyFromObject(rule), current); err != nil {
				return client.IgnoreNotFound(err)
			}
			if current.UID != rule.UID {
				return errors.New("service identity changed during gateway retirement")
			}
			stoppedGatewayConditions(&current.Status.Conditions, r.NodeName, current.Generation)
			return r.Status().Update(ctx, current)
		}); err != nil {
			return true, err
		}
	}
	return false, nil
}

func (r *NetworkGatewayReconciler) servedAddressInventories(
	ctx context.Context,
	reader client.Reader,
	gatewayNamespace string,
) (*bgpv1alpha1.NetworkServiceAddressList, error) {
	addresses := &bgpv1alpha1.NetworkServiceAddressList{}
	if err := reader.List(ctx, addresses); err != nil {
		return nil, err
	}
	served := &bgpv1alpha1.NetworkServiceAddressList{}
	if !r.Scope.trustsGateway(gatewayNamespace) {
		return served, nil
	}
	for _, address := range addresses.Items {
		allowed, err := r.addressInScope(ctx, reader, &address, gatewayNamespace)
		if err != nil {
			return nil, err
		}
		// Historical receipts remain visible for teardown after scope changes.
		if allowed || address.Spec.Retired || hasAddressNodeHistory(&address, r.NodeName) {
			served.Items = append(served.Items, address)
		}
	}
	return served, nil
}

func addressKeyAdvertisementName(key types.NamespacedName, namespace, node string) string {
	identity, _ := ruleNameKey(key, namespace)
	return addressAdvertisementName(identity, node)
}

func addressKeyFromAdvertisement(ad *bgpv1alpha1.BGPAdvertisement) types.NamespacedName {
	namespace := ad.Labels[serviceAddressNamespaceLabel]
	if namespace == "" {
		namespace = ad.Namespace
	}
	name := ad.Annotations[serviceAddressLabel]
	if name == "" {
		name = ad.Labels[serviceAddressLabel]
	}
	return types.NamespacedName{Namespace: namespace, Name: name}
}

// addressInScope applies the same namespace, pool and VPC checks as service admission.
func (r *NetworkGatewayReconciler) addressInScope(
	ctx context.Context, reader client.Reader, address *bgpv1alpha1.NetworkServiceAddress, namespace string,
) (bool, error) {
	if !r.Scope.trustsGateway(namespace) {
		return false, nil
	}
	if address.Namespace == namespace {
		return true, nil
	}
	if !r.Scope.ProjectServices {
		return false, nil
	}
	rule := &bgpv1alpha1.NetworkService{ObjectMeta: metav1.ObjectMeta{Namespace: address.Namespace},
		Spec: bgpv1alpha1.NetworkServiceSpec{
			VPCRef:       address.Spec.VPCRef,
			VIPAddresses: []string{address.Spec.VIPAddress},
		}}
	if allowed, _ := r.Scope.vipsInPool(rule); !allowed {
		return false, nil
	}
	owned, _, err := ruleOwnsVPC(ctx, reader, rule)
	if err != nil || !owned {
		return false, err
	}
	return projectAddressUnclaimed(ctx, reader, namespace, address.Spec.VIPAddress)
}

// projectAddressUnclaimed gives gateway-namespace services and anchors priority
// over project anchors, including an anchor that has no listener services yet.
func projectAddressUnclaimed(ctx context.Context, reader client.Reader, namespace, vip string) (bool, error) {
	rules := &bgpv1alpha1.NetworkServiceList{}
	if err := reader.List(ctx, rules, client.InNamespace(namespace)); err != nil {
		return false, err
	}
	for _, rule := range rules.Items {
		for _, value := range rule.Spec.VIPAddresses {
			if canonicalVIP(value) == canonicalVIP(vip) {
				return false, nil
			}
		}
	}
	addresses := &bgpv1alpha1.NetworkServiceAddressList{}
	if err := reader.List(ctx, addresses, client.InNamespace(namespace)); err != nil {
		return false, err
	}
	for i := range addresses.Items {
		address := &addresses.Items[i]
		if !addressRetirementAcknowledged(address) && canonicalVIP(address.Spec.VIPAddress) == canonicalVIP(vip) {
			return false, nil
		}
	}
	return true, nil
}

func hasAddressNodeHistory(address *bgpv1alpha1.NetworkServiceAddress, node string) bool {
	for _, condition := range address.Status.Conditions {
		if observed, ok := gatewayNodeConditionNode(condition.Type); ok && observed == node {
			return true
		}
	}
	return meta.FindStatusCondition(address.Status.Conditions, stoppedGatewayConditionType(node)) != nil
}

// appendUnservedGroupedOutcomes keeps withdrawal receipts current for listeners
// excluded by a scope change, without adding them to desired forwarding state.
func appendUnservedGroupedOutcomes(outcomes []ruleOutcome, served, all []bgpv1alpha1.NetworkService) []ruleOutcome {
	included := make(map[types.NamespacedName]bool, len(served))
	for i := range served {
		included[client.ObjectKeyFromObject(&served[i])] = true
	}
	for i := range all {
		rule := &all[i]
		if rule.Spec.AddressGroup == nil || included[client.ObjectKeyFromObject(rule)] {
			continue
		}
		outcomes = append(outcomes, ruleOutcome{rule: rule, buildErr: errors.New("project services are disabled")})
	}
	return outcomes
}

func addressHasServingOutcome(
	address *bgpv1alpha1.NetworkServiceAddress,
	outcomes []ruleOutcome,
	failed map[string]bool,
) bool {
	for _, outcome := range outcomes {
		if outcome.rule.Spec.AddressGroup == nil || outcome.rule.Spec.AddressGroup.UID != address.Spec.Group.UID ||
			outcome.buildErr != nil || outcome.unaccepted || outcome.draining || !outcome.rule.DeletionTimestamp.IsZero() {
			continue
		}
		if !failed[outcome.desired.Key] && len(outcome.desired.Backends) > 0 {
			return true
		}
	}
	return false
}

func (r *NetworkGatewayReconciler) addressGateways(
	ctx context.Context,
	reader client.Reader,
	namespace string,
) ([]bgpv1alpha1.NetworkGateway, error) {
	if r.Scope.GatewayNamespace != "" {
		namespace = r.Scope.GatewayNamespace
	}
	return (ServiceScope{}).servingGateways(ctx, reader, namespace)
}

func (r *NetworkGatewayReconciler) prepareOwnedAddresses(
	ctx context.Context,
	snapshot addressInventory,
	owned []netip.Addr,
) error {
	engine, ok := r.Engine.(ownedVIPEngine)
	if !ok {
		if len(owned) == 0 {
			return nil
		}
		return errors.New("gateway lacks shared-address isolation")
	}
	r.desiredOwnedAddresses = slices.Clone(owned)
	retained := slices.Clone(r.ownedAddresses)
	if discovery, ok := r.Engine.(interface{ OwnedVIPs() ([]netip.Addr, error) }); ok {
		pinned, err := discovery.OwnedVIPs()
		if err != nil {
			return err
		}
		for _, addr := range pinned {
			if !slices.Contains(retained, addr) {
				retained = append(retained, addr)
			}
		}
	}
	for _, addr := range owned {
		if !slices.Contains(retained, addr) {
			retained = append(retained, addr)
		}
	}
	// Record all attempted guards even on partial failure; no cleanup receipt
	// may forget a row the datapath might already have installed.
	r.ownedAddresses = retained
	if err := engine.SetOwnedVIPs(ctx, retained); err != nil {
		return err
	}
	var changed []netip.Addr
	for _, addr := range retained {
		current, confirmed := snapshot[addr.String()], r.confirmedAddresses[addr.String()]
		if current == nil || confirmed == nil || !sameAddressRevision(current, confirmed) {
			changed = append(changed, addr)
		}
	}
	if len(changed) > 0 {
		return engine.SetBlockedVIPs(ctx, changed)
	}
	return nil
}

func (r *NetworkGatewayReconciler) blockChangedAddressRules(ctx context.Context, desired gateway.EngineState) error {
	blocker, ok := r.Engine.(ownedVIPEngine)
	if !ok {
		return nil
	}
	changed := r.ownedAddresses
	if engine, ok := r.Engine.(interface {
		ChangedVIPs(gateway.EngineState) []netip.Addr
	}); ok {
		changed = nil
		for _, addr := range engine.ChangedVIPs(desired) {
			if slices.Contains(r.ownedAddresses, addr) {
				changed = append(changed, addr)
			}
		}
	}
	if len(changed) == 0 {
		return nil
	}
	return blocker.SetBlockedVIPs(ctx, changed)
}

func ruleVIPsConverged(rule *bgpv1alpha1.NetworkService, status gateway.EngineStatus) bool {
	for _, value := range rule.Spec.VIPAddresses {
		addr, err := netip.ParseAddr(value)
		if err != nil || !status.VIPConverged(addr) {
			return false
		}
	}
	return true
}

func markVIPFailure(status *gateway.EngineStatus, addr netip.Addr, err error) {
	status.Healthy = false
	status.Rules = append(status.Rules, gateway.RuleStatus{VIPAddresses: []netip.Addr{addr}, Error: err.Error()})
}

func (r *NetworkGatewayReconciler) finishOwnedAddresses(
	ctx context.Context,
	namespace string,
	snapshot addressInventory,
	status *gateway.EngineStatus,
) error {
	current, err := r.currentAddressInventory(ctx, namespace)
	if err != nil {
		return err
	}
	blocker, ok := r.Engine.(ownedVIPEngine)
	if !ok {
		return nil
	}
	var changed []netip.Addr
	for vip, before := range snapshot {
		after, exists := current[vip]
		if !exists || (after == nil) != (before == nil) || after != nil && !sameAddressRevision(before, after) {
			changed = append(changed, netip.MustParseAddr(vip))
		}
	}
	for vip := range current {
		if _, exists := snapshot[vip]; !exists {
			changed = append(changed, netip.MustParseAddr(vip))
		}
	}
	for _, addr := range changed {
		if !slices.Contains(r.ownedAddresses, addr) {
			r.ownedAddresses = append(r.ownedAddresses, addr)
		}
		markVIPFailure(status, addr, errors.New("address revision changed before forwarding activation"))
	}
	if len(changed) > 0 {
		if err := blocker.SetOwnedVIPs(ctx, r.ownedAddresses); err != nil {
			return err
		}
		if err := blocker.SetBlockedVIPs(ctx, changed); err != nil {
			return err
		}
	}
	renewer, ok := r.Engine.(interface {
		RenewVIPs(context.Context, []netip.Addr) error
	})
	if !ok && len(r.ownedAddresses) > 0 {
		return errors.New("gateway lacks selective address renewal")
	}
	if r.confirmedAddresses == nil {
		r.confirmedAddresses = addressInventory{}
	}
	retained := make([]netip.Addr, 0, len(r.ownedAddresses))
	for _, addr := range r.ownedAddresses {
		if !status.VIPConverged(addr) || slices.Contains(r.desiredOwnedAddresses, addr) {
			retained = append(retained, addr)
		}
		address := snapshot[addr.String()]
		if !status.VIPConverged(addr) || validAddressInventory(address) != nil {
			continue
		}
		if err := renewer.RenewVIPs(ctx, []netip.Addr{addr}); err != nil {
			markVIPFailure(status, addr, err)
			delete(r.confirmedAddresses, addr.String())
			continue
		}
		r.confirmedAddresses[addr.String()] = address.DeepCopy()
	}
	if err := blocker.SetOwnedVIPs(ctx, retained); err != nil {
		return err
	}
	r.ownedAddresses = retained
	for vip := range r.confirmedAddresses {
		if !slices.Contains(retained, netip.MustParseAddr(vip)) {
			delete(r.confirmedAddresses, vip)
		}
	}
	return nil
}
