// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// A NetworkService lives either in a gateway namespace, one holding
// NetworkGateways, or in a tenant namespace, one holding none. A gateway
// serves every service in its own namespace and every service in a tenant
// namespace. The objects generated for a service, its BGPAdvertisements and
// ServiceVIPBindings, always live in the gateway namespace, beside the
// BGPRouters they hang off, so galactic-router finds them where it already
// looks. A cluster runs one gateway namespace, the one galactic-router's
// BGP objects live in.
//
// A service in a tenant namespace is trusted for nothing the platform
// verified: it is accepted only when a VPC in its own namespace carries its
// vpcRef, its backends come only from VPCAttachments in its own namespace, and
// it loses every VIP address, protocol and port another service already
// serves.

// networkRuleNamespaceLabel is set, beside networkRuleLabel, on every object
// generated for a service in a tenant namespace, to that namespace. An object
// generated for a service in its own namespace carries no such label.
const networkRuleNamespaceLabel = "galactic.datum.net/network-rule-namespace"

// reasonVIPClaimed is the Accepted reason, and each gateway node's Programmed
// reason, for a tenant rule that claims a VIP address, protocol and port
// another rule already serves.
const reasonVIPClaimed = "VIPClaimed"

// errVIPClaimed is the build error of a tenant rule that loses a VIP to
// another rule (tenantVIPConflicts).
var errVIPClaimed = errors.New("VIP already served")

// ruleIsTenant reports whether rule's generated objects live in objNS, a
// namespace other than its own. An empty objNS means its own namespace.
func ruleIsTenant(rule *bgpv1alpha1.NetworkService, objNS string) bool {
	return objNS != "" && rule.Namespace != objNS
}

// generatedNamespace returns the namespace objects generated for rule live
// in: objNS, or rule's own namespace when objNS is empty.
func generatedNamespace(rule *bgpv1alpha1.NetworkService, objNS string) string {
	if objNS == "" {
		return rule.Namespace
	}
	return objNS
}

// ruleLabels returns the labels naming rule on an object generated for it in
// objNS.
func ruleLabels(rule *bgpv1alpha1.NetworkService, objNS string) map[string]string {
	l := map[string]string{networkRuleLabel: rule.Name}
	if ruleIsTenant(rule, objNS) {
		l[networkRuleNamespaceLabel] = rule.Namespace
	}
	return l
}

// setRuleLabels sets the labels naming rule on obj, an object generated for
// it in objNS, and removes a namespace label it should not carry.
func setRuleLabels(obj metav1.Object, rule *bgpv1alpha1.NetworkService, objNS string) {
	l := obj.GetLabels()
	if l == nil {
		l = map[string]string{}
	}
	delete(l, networkRuleNamespaceLabel)
	for k, v := range ruleLabels(rule, objNS) {
		l[k] = v
	}
	obj.SetLabels(l)
}

// ruleSelector selects the objects generated for rule in objNS.
// A service's own namespace's objects are those without
// networkRuleNamespaceLabel, so a tenant service of the same name never
// matches.
func ruleSelector(rule *bgpv1alpha1.NetworkService, objNS string) client.ListOption {
	return ruleKeySelector(client.ObjectKeyFromObject(rule), generatedNamespace(rule, objNS), nil)
}

// ruleKeySelector is ruleSelector for a service known only by its key, such
// as one already deleted.
func ruleKeySelector(key types.NamespacedName, objNS string, extra map[string]string) client.ListOption {
	set := labels.Set{networkRuleLabel: key.Name}
	for k, v := range extra {
		set[k] = v
	}
	sel := labels.SelectorFromSet(set)
	var req *labels.Requirement
	var err error
	if objNS == "" || key.Namespace == objNS {
		req, err = labels.NewRequirement(networkRuleNamespaceLabel, selection.DoesNotExist, nil)
	} else {
		req, err = labels.NewRequirement(networkRuleNamespaceLabel, selection.Equals, []string{key.Namespace})
	}
	if err == nil {
		sel = sel.Add(*req)
	}
	return &client.ListOptions{Namespace: objNS, LabelSelector: sel}
}

// ruleKeyFromLabels returns the key of the service obj was generated for,
// from its labels, and false when it names none.
func ruleKeyFromLabels(obj client.Object) (types.NamespacedName, bool) {
	l := obj.GetLabels()
	name := l[networkRuleLabel]
	if name == "" {
		return types.NamespacedName{}, false
	}
	ns := obj.GetNamespace()
	if tenant := l[networkRuleNamespaceLabel]; tenant != "" {
		ns = tenant
	}
	return types.NamespacedName{Namespace: ns, Name: name}, true
}

// generatedFor reports whether obj's labels name rule.
func generatedFor(obj client.Object, rule *bgpv1alpha1.NetworkService) bool {
	key, ok := ruleKeyFromLabels(obj)
	return ok && key == client.ObjectKeyFromObject(rule)
}

// ruleNameKey returns the string generated object names are derived from for
// a service known by key whose objects live in objNS: its name in its own
// namespace, as before services could live elsewhere, and "namespace/name"
// for a tenant service, which no service name can be.
func ruleNameKey(key types.NamespacedName, objNS string) (hashKey, prefix string) {
	if objNS == "" || key.Namespace == objNS {
		return key.Name, key.Name
	}
	return key.Namespace + "/" + key.Name, key.Namespace + "-" + key.Name
}

// setRuleOwner sets an owner reference to rule on obj when both share a
// namespace. An owner reference cannot cross namespaces, so a tenant
// service's objects are deleted by its finalizer and the sweeps instead.
func setRuleOwner(rule *bgpv1alpha1.NetworkService, obj metav1.Object, scheme *runtime.Scheme) error {
	if rule.Namespace != obj.GetNamespace() {
		return nil
	}
	return controllerutil.SetOwnerReference(rule, obj, scheme)
}

// servingGateways returns the NetworkGateways that serve a service in
// namespace: those in namespace, or, for a tenant namespace holding none,
// every NetworkGateway in the cluster.
func servingGateways(ctx context.Context, c client.Reader, namespace string) ([]bgpv1alpha1.NetworkGateway, error) {
	list := &bgpv1alpha1.NetworkGatewayList{}
	if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list NetworkGateways in %s: %w", namespace, err)
	}
	if len(list.Items) > 0 {
		return list.Items, nil
	}
	if err := c.List(ctx, list); err != nil {
		return nil, fmt.Errorf("list NetworkGateways: %w", err)
	}
	return list.Items, nil
}

// servingGatewayNodeNames returns the target node of every NetworkGateway
// that serves a service in namespace (servingGateways).
func servingGatewayNodeNames(ctx context.Context, c client.Reader, namespace string) ([]string, error) {
	gws, err := servingGateways(ctx, c, namespace)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(gws))
	for _, gw := range gws {
		names = append(names, gw.Spec.TargetRef.Name)
	}
	return names, nil
}

// nodeServingGateway returns the NetworkGateway targeting nodeName among
// those serving a service in namespace, or nil when nodeName serves none.
func nodeServingGateway(
	ctx context.Context, c client.Reader, namespace, nodeName string,
) (*bgpv1alpha1.NetworkGateway, error) {
	gws, err := servingGateways(ctx, c, namespace)
	if err != nil {
		return nil, err
	}
	for i := range gws {
		if gws[i].Spec.TargetRef.Name == nodeName {
			return &gws[i], nil
		}
	}
	return nil, nil
}

// listServedNetworkServices returns every NetworkService a gateway in
// gwNamespace serves, those in gwNamespace and those in every namespace
// holding no NetworkGateway, and every NetworkService in the cluster.
func listServedNetworkServices(
	ctx context.Context, c client.Reader, gwNamespace string,
) (served, all []bgpv1alpha1.NetworkService, err error) {
	rules := &bgpv1alpha1.NetworkServiceList{}
	if err := c.List(ctx, rules); err != nil {
		return nil, nil, fmt.Errorf("list NetworkServices: %w", err)
	}
	gws := &bgpv1alpha1.NetworkGatewayList{}
	if err := c.List(ctx, gws); err != nil {
		return nil, nil, fmt.Errorf("list NetworkGateways: %w", err)
	}
	gatewayNamespaces := map[string]bool{gwNamespace: true}
	for i := range gws.Items {
		gatewayNamespaces[gws.Items[i].Namespace] = true
	}
	for i := range rules.Items {
		ns := rules.Items[i].Namespace
		if ns == gwNamespace || !gatewayNamespaces[ns] {
			served = append(served, rules.Items[i])
		}
	}
	return served, rules.Items, nil
}

// ruleOwnsVPC reports whether a VPC in rule's namespace carries rule's
// vpcRef as its identifier, and says why not when none does.
func ruleOwnsVPC(ctx context.Context, c client.Reader, rule *bgpv1alpha1.NetworkService) (bool, string, error) {
	vpcs := &cloudv1alpha1.VPCList{}
	if err := c.List(ctx, vpcs, client.InNamespace(rule.Namespace)); err != nil {
		return false, "", fmt.Errorf("list VPCs in %s: %w", rule.Namespace, err)
	}
	for i := range vpcs.Items {
		if vpcs.Items[i].Status.VPC == rule.Spec.VPCRef && vpcs.Items[i].DeletionTimestamp.IsZero() {
			return true, "", nil
		}
	}
	return false, fmt.Sprintf("no VPC in namespace %s has identifier %q", rule.Namespace, rule.Spec.VPCRef), nil
}

// vipListener is one address, protocol and port a service serves.
type vipListener struct {
	addr     netip.Addr
	protocol bgpv1alpha1.NetworkServiceProtocol
	port     int32
	end      int32
}

// tenantVIPConflicts returns, for each service in a tenant namespace (one
// other than objNS) that claims a VIP address, protocol and port another
// service already serves, the service it loses to. A service in objNS never
// loses: the platform allocated its VIPs. Among tenant services the oldest
// claim wins (ruleOlder). Services being deleted keep their claims until gone.
func tenantVIPConflicts(
	rules []bgpv1alpha1.NetworkService, objNS string,
) map[types.NamespacedName]types.NamespacedName {
	ordered := make([]*bgpv1alpha1.NetworkService, 0, len(rules))
	for i := range rules {
		ordered = append(ordered, &rules[i])
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		ti, tj := ruleIsTenant(ordered[i], objNS), ruleIsTenant(ordered[j], objNS)
		if ti != tj {
			return !ti
		}
		return ruleOlder(ordered[i], ordered[j])
	})
	owners := map[vipListener]types.NamespacedName{}
	lost := map[types.NamespacedName]types.NamespacedName{}
	for _, rule := range ordered {
		key := client.ObjectKeyFromObject(rule)
		tenant := ruleIsTenant(rule, objNS)
		var claims []vipListener
		for _, v := range rule.Spec.VIPAddresses {
			addr, err := netip.ParseAddr(v)
			if err != nil {
				continue
			}
			l := vipListener{
				addr:     addr.Unmap(),
				protocol: rule.Spec.Protocol,
				port:     rule.Spec.Port,
				end:      rule.Spec.Port,
			}
			if rule.Spec.PortRange != nil {
				l.port, l.end = rule.Spec.PortRange.Start, rule.Spec.PortRange.End
			}
			var conflict *types.NamespacedName
			for claimed, owner := range owners {
				if claimed.addr == l.addr && claimed.protocol == l.protocol && l.port <= claimed.end &&
					claimed.port <= l.end &&
					(tenant || rule.Spec.AddressGroup != nil) &&
					owner != key {
					if conflict == nil || owner.String() < conflict.String() {
						copy := owner
						conflict = &copy
					}
				}
			}
			if conflict != nil {
				lost[key] = *conflict
				claims = nil
				break
			}
			claims = append(claims, l)
		}
		for _, l := range claims {
			if _, taken := owners[l]; !taken {
				owners[l] = key
			}
		}
	}
	return lost
}
