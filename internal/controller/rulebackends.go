// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ruleBackend is one backend a NetworkRule's BackendSelector picks: one IPv6
// interface address of one selected VPCAttachment, on the rule's BackendPort.
//
// galactic-gateway load-balances to it and galactic-router on node writes its
// ServiceVIPBinding, and both derive it from the same objects through
// selectRuleBackends and ruleBackendOwners, so the gateway never sends a flow
// to a node that has no binding planned for it.
type ruleBackend struct {
	attachment types.NamespacedName
	node       string
	addr       netip.Addr
	port       uint16
	egressKind bgpv1alpha1.ServiceVIPBindingEgressKind
}

// String returns the backend as "address:port", the form status messages use.
func (b ruleBackend) String() string {
	return netip.AddrPortFrom(b.addr, b.port).String()
}

// listVPCAttachments lists the VPCAttachments opts select, cluster-wide.
// Attachments live in tenant namespaces while NetworkRules live in
// galactic-system, so the list is never namespaced; selectRuleBackends scopes
// it to one rule's VPC.
//
// The list skips the cache's deep copy: the returned attachments share their
// maps and slices with the informer's store, so callers must treat them as
// read-only. selectRuleBackends and everything it calls only read them, and
// nothing they return points back into an attachment.
func listVPCAttachments(
	ctx context.Context, c client.Client, opts ...client.ListOption,
) ([]*cloudv1alpha1.VPCAttachment, error) {
	list := &cloudv1alpha1.VPCAttachmentList{}
	if err := c.List(ctx, list, append(opts, client.UnsafeDisableDeepCopy)...); err != nil {
		return nil, fmt.Errorf("list VPCAttachments: %w", err)
	}
	out := make([]*cloudv1alpha1.VPCAttachment, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, &list.Items[i])
	}
	return out, nil
}

// vpcAttachmentBackendChanged passes VPCAttachment events that can change some
// rule's backend set: every create, delete and generic event, and an update
// only when a field ruleCandidateBackends reads changed. Status writes that touch
// only conditions, observedGeneration, the container ID and the like are
// dropped, so an attachment controller refreshing its conditions does not
// trigger a pass on every gateway and router.
//
// The fields compared here are exactly those ruleCandidateBackends,
// attachmentIPv6Addresses and attachmentEgressKind read: labels (the
// selector), status.vpc, status.node, spec.interface.addresses and
// spec.interface.mode. Namespace and name are immutable. Keep this list in
// sync with those functions whenever one of them reads another field.
func vpcAttachmentBackendChanged() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldAtt, okOld := e.ObjectOld.(*cloudv1alpha1.VPCAttachment)
			newAtt, okNew := e.ObjectNew.(*cloudv1alpha1.VPCAttachment)
			if !okOld || !okNew {
				return true
			}
			return !maps.Equal(oldAtt.Labels, newAtt.Labels) ||
				oldAtt.Status.VPC != newAtt.Status.VPC ||
				oldAtt.Status.Node != newAtt.Status.Node ||
				oldAtt.Spec.Interface.Mode != newAtt.Spec.Interface.Mode ||
				!slices.Equal(oldAtt.Spec.Interface.Addresses, newAtt.Spec.Interface.Addresses)
		},
	}
}

// ruleSelection is what selectRuleBackends picks for one NetworkRule.
type ruleSelection struct {
	// backends are the rule's backends, sorted by address.
	backends []ruleBackend

	// pending lists the selected attachments that are not backends yet, as
	// "namespace/name: reason", sorted.
	pending []string

	// claimed are the backends the rule's selector picks that an older rule
	// serves (backendOwners), sorted by address.
	claimed []claimedBackend
}

// claimedBackend is a backend one rule selects but another rule owns.
type claimedBackend struct {
	ruleBackend
	owner types.NamespacedName
}

// String returns the backend and its owner, the form status messages use.
func (c claimedBackend) String() string {
	return fmt.Sprintf("%s: backend %s is served by NetworkRule %s", c.attachment, c.ruleBackend, c.owner)
}

// listVPCAttachmentsInVPC lists the VPCAttachments whose observed VPC is vpc,
// through the VPCAttachmentByVPC field index. selectRuleBackends drops every
// other attachment anyway, so for a rule in vpc this returns the same backends
// as the full list without visiting other tenants' attachments.
func listVPCAttachmentsInVPC(ctx context.Context, c client.Client, vpc string) ([]*cloudv1alpha1.VPCAttachment, error) {
	return listVPCAttachments(ctx, c, client.MatchingFields{VPCAttachmentByVPC: vpc})
}

// groupAttachmentsByVPC groups attachments by their observed VPC, for a caller
// that selects backends for many rules from one list. An attachment with no
// observed VPC is in no rule's VPC, so it is left out.
func groupAttachmentsByVPC(attachments []*cloudv1alpha1.VPCAttachment) map[string][]*cloudv1alpha1.VPCAttachment {
	byVPC := make(map[string][]*cloudv1alpha1.VPCAttachment)
	for _, a := range attachments {
		if a.Status.VPC != "" {
			byVPC[a.Status.VPC] = append(byVPC[a.Status.VPC], a)
		}
	}
	return byVPC
}

// selectRuleBackends returns the backends rule's BackendSelector picks from
// attachments, less those owners assigns to another rule.
//
// Only an attachment whose observed VPC equals rule.Spec.VPCRef is a
// candidate, whatever its labels, so a selector cannot reach another tenant's
// VPC. A selected attachment with no observed node, or no IPv6 interface
// address, is pending rather than a backend: the DSR datapath carries only
// IPv6 backends. An attachment with several IPv6 addresses contributes each of
// them. A backend owned by another rule is claimed rather than a backend: its
// node can translate its replies back to only one rule's VIP.
//
// An invalid selector is a spec error and fails the rule.
func selectRuleBackends(
	rule *bgpv1alpha1.NetworkRule, attachments []*cloudv1alpha1.VPCAttachment, owners backendOwners,
) (ruleSelection, error) {
	candidates, pending, err := ruleCandidateBackends(rule, attachments)
	if err != nil {
		return ruleSelection{}, err
	}
	sel := ruleSelection{pending: pending}
	self := client.ObjectKeyFromObject(rule)
	for _, b := range candidates {
		if owner, ok := owners[backendClaimFor(rule, b)]; ok && owner != self {
			sel.claimed = append(sel.claimed, claimedBackend{ruleBackend: b, owner: owner})
			continue
		}
		sel.backends = append(sel.backends, b)
	}
	return sel, nil
}

// ruleCandidateBackends returns every backend rule's BackendSelector picks
// from attachments, whatever other rules select, sorted by address, and the
// selected attachments that are not backends yet, as "namespace/name: reason".
// See selectRuleBackends for which attachments qualify.
func ruleCandidateBackends(
	rule *bgpv1alpha1.NetworkRule, attachments []*cloudv1alpha1.VPCAttachment,
) (backends []ruleBackend, pending []string, err error) {
	selector, err := ruleBackendSelector(rule)
	if err != nil {
		return nil, nil, err
	}
	//nolint:gosec // BackendPort is CRD-validated to [1,65535] (Minimum/Maximum markers on NetworkRuleSpec.BackendPort)
	port := uint16(rule.Spec.BackendPort)

	for _, attachment := range attachments {
		if attachment.Status.VPC != rule.Spec.VPCRef || !selector.Matches(labels.Set(attachment.Labels)) {
			continue
		}
		key := types.NamespacedName{Namespace: attachment.Namespace, Name: attachment.Name}
		if attachment.Status.Node == "" {
			pending = append(pending, key.String()+": status.node not set by datum-cloud/cloud")
			continue
		}
		addrs := attachmentIPv6Addresses(attachment)
		if len(addrs) == 0 {
			pending = append(pending, key.String()+": no IPv6 address")
			continue
		}
		kind := attachmentEgressKind(attachment.Spec.Interface.Mode)
		for _, addr := range addrs {
			backends = append(backends, ruleBackend{
				attachment: key,
				node:       attachment.Status.Node,
				addr:       addr,
				port:       port,
				egressKind: kind,
			})
		}
	}

	// The list order is the cache's, so sort for a stable Maglev input and a
	// stable status message. Two attachments claiming one address keep their
	// relative order by name.
	sort.SliceStable(backends, func(i, j int) bool {
		if c := backends[i].addr.Compare(backends[j].addr); c != 0 {
			return c < 0
		}
		return backends[i].attachment.String() < backends[j].attachment.String()
	})
	backends, rejected := dropConflictingBackends(backends)
	pending = append(pending, rejected...)
	sort.Strings(pending)
	return backends, pending, nil
}

// backendClaim identifies the egress vip_xlat_table row a backend's node
// writes for a rule: the reply from a backend address and port, over one
// protocol, in one VPC. The row rewrites the reply's source to one VIP, so
// only one rule can use a given claim.
type backendClaim struct {
	vpc      string
	addr     netip.Addr
	port     uint16
	protocol bgpv1alpha1.NetworkRuleProtocol
}

// backendClaimFor returns the claim backend b of rule makes.
func backendClaimFor(rule *bgpv1alpha1.NetworkRule, b ruleBackend) backendClaim {
	return backendClaim{vpc: rule.Spec.VPCRef, addr: b.addr, port: b.port, protocol: rule.Spec.Protocol}
}

// backendOwners maps each backend claim to the rule that owns it.
type backendOwners map[backendClaim]types.NamespacedName

// ruleBackendOwners assigns every backend claim the rules make to the oldest
// rule making it, by creation time and then namespace/name, so the gateway
// and every backend node pick the same owner from the same objects.
//
// A rule makes claims only if its backend nodes would write bindings for it:
// it has exactly one IPv6 VIP and a valid selector. A rule being deleted keeps
// its claims, since its bindings, and their rows, last until it is gone.
func ruleBackendOwners(
	rules []bgpv1alpha1.NetworkRule, attachments []*cloudv1alpha1.VPCAttachment,
) backendOwners {
	ordered := make([]*bgpv1alpha1.NetworkRule, 0, len(rules))
	for i := range rules {
		ordered = append(ordered, &rules[i])
	}
	sort.Slice(ordered, func(i, j int) bool { return ruleOlder(ordered[i], ordered[j]) })

	owners := make(backendOwners)
	for _, rule := range ordered {
		if _, ok, err := ruleTranslatedVIP(rule); err != nil || !ok {
			continue
		}
		backends, _, err := ruleCandidateBackends(rule, attachments)
		if err != nil {
			continue
		}
		for _, b := range backends {
			claim := backendClaimFor(rule, b)
			if _, taken := owners[claim]; !taken {
				owners[claim] = client.ObjectKeyFromObject(rule)
			}
		}
	}
	return owners
}

// ruleOlder reports whether a was created before b, breaking a tie on
// creation time, which has one-second resolution, by namespace and name.
func ruleOlder(a, b *bgpv1alpha1.NetworkRule) bool {
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	return a.Name < b.Name
}

// dropConflictingBackends removes, from backends in their sorted order, each
// backend that cannot get its own vip_xlat_table rows, and returns why as
// "namespace/name: reason".
//
//   - An address a backend earlier in the order already claims: two
//     attachments reporting one address would put two Maglev entries, maybe
//     on two nodes, behind one real backend.
//   - A slot (srv6.BackendSlot) an earlier backend on the same node already
//     uses: the node keys its ingress row on the slot, so the later backend's
//     binding could only report Conflict while the gateway kept sending it
//     flows.
//
// The order is the same on every node, so the gateway and every backend node
// drop the same backend.
func dropConflictingBackends(backends []ruleBackend) (kept []ruleBackend, rejected []string) {
	type nodeSlot struct {
		node string
		slot uint16
	}
	byAddr := make(map[netip.Addr]ruleBackend, len(backends))
	bySlot := make(map[nodeSlot]ruleBackend, len(backends))
	for _, b := range backends {
		if first, ok := byAddr[b.addr]; ok {
			rejected = append(rejected, fmt.Sprintf("%s: address %s is also claimed by %s",
				b.attachment, b.addr, first.attachment))
			continue
		}
		key := nodeSlot{node: b.node, slot: srv6.BackendSlot(b.addr, b.port)}
		if first, ok := bySlot[key]; ok {
			rejected = append(rejected, fmt.Sprintf("%s: backend %s shares slot %#04x on node %s with %s",
				b.attachment, b, key.slot, b.node, first))
			continue
		}
		byAddr[b.addr] = b
		bySlot[key] = b
		kept = append(kept, b)
	}
	return kept, rejected
}

// ruleTranslatedVIP returns the one IPv6 VIP of rule that backend nodes
// translate, or false if it has none. A rule may carry at most one: a backend
// node rewrites a reply's source from the backend's address and port back to
// a single VIP, so a backend cannot answer for a second IPv6 VIP and that
// VIP's flows would be lost. For the same reason a backend serves only one
// rule on a given backendPort (ruleBackendOwners). IPv4 VIPs are not
// translated (#705).
func ruleTranslatedVIP(rule *bgpv1alpha1.NetworkRule) (netip.Addr, bool, error) {
	var found []netip.Addr
	for _, v := range rule.Spec.VIPAddresses {
		vip, err := netip.ParseAddr(v)
		if err != nil {
			return netip.Addr{}, false, fmt.Errorf("invalid VIP address %q: %w", v, err)
		}
		if vip.Is6() && !vip.Is4In6() {
			found = append(found, vip)
		}
	}
	switch len(found) {
	case 0:
		return netip.Addr{}, false, nil
	case 1:
		return found[0], true, nil
	default:
		return netip.Addr{}, false, fmt.Errorf(
			"rule has %d IPv6 VIPs, but a backend node rewrites replies from one backend address, "+
				"backendPort and protocol to only one VIP; serve each further IPv6 VIP from its own rule "+
				"whose backends listen on a different backendPort",
			len(found))
	}
}

// ruleBackendSelector converts rule's BackendSelector to a labels.Selector.
// The CRD rejects an empty selector; this rejects one anyway, since an empty
// selector would otherwise match every attachment in the VPC.
func ruleBackendSelector(rule *bgpv1alpha1.NetworkRule) (labels.Selector, error) {
	sel := rule.Spec.BackendSelector
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
		return nil, errors.New("backendSelector is empty")
	}
	selector, err := metav1.LabelSelectorAsSelector(&sel)
	if err != nil {
		return nil, fmt.Errorf("invalid backendSelector: %w", err)
	}
	return selector, nil
}

// attachmentIPv6Addresses returns attachment's IPv6 interface addresses, with
// their prefix lengths dropped. An entry that does not parse is skipped: the
// Cloud API validates them, and one bad entry should not hide the others.
func attachmentIPv6Addresses(attachment *cloudv1alpha1.VPCAttachment) []netip.Addr {
	var out []netip.Addr
	for _, a := range attachment.Spec.Interface.Addresses {
		addr, err := parseInterfaceAddress(string(a))
		if err != nil || !addr.Is6() || addr.Is4In6() {
			continue
		}
		out = append(out, addr)
	}
	return out
}

// parseInterfaceAddress parses an interface address in CIDR notation, as the
// Cloud API stores it, or a bare address.
func parseInterfaceAddress(s string) (netip.Addr, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Addr(), nil
	}
	return netip.ParseAddr(s)
}

// attachmentEgressKind maps an attachment's interface mode to the binding
// mechanism its node uses: a container's interface is a veth in its netns, and
// a VM's is a tap handed to the hypervisor. An empty mode is the Cloud API's
// default, Netns.
func attachmentEgressKind(mode cloudv1alpha1.VPCAttachmentInterfaceMode) bgpv1alpha1.ServiceVIPBindingEgressKind {
	switch mode {
	case cloudv1alpha1.VPCAttachmentInterfaceModeHypervisor, cloudv1alpha1.VPCAttachmentInterfaceModeHypervisorDeclared:
		return bgpv1alpha1.ServiceVIPBindingEgressKindTap
	default:
		return bgpv1alpha1.ServiceVIPBindingEgressKindVeth
	}
}
