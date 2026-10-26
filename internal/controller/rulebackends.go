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

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

// ruleBackend is one backend a NetworkService's BackendSelector picks: one IPv6
// interface address of one selected VPCAttachment, on the rule's BackendPort.
// Workloads are IPv6 only, so it serves the rule's VIPs of both families: its
// node translates an IPv4 VIP's flows to and from IPv6.
//
// galactic-gateway load-balances to it and galactic-router on node writes its
// ServiceVIPBinding, and both derive it from the same objects through
// selectRuleBackends and ruleBackendOwners, so the gateway never sends a flow
// to a node that has no binding planned for it.
type ruleBackend struct {
	attachment types.NamespacedName
	// uid is the attachment's UID, which a published health decision must
	// name to apply to this backend.
	uid        types.UID
	node       string
	addr       netip.Addr
	port       uint16
	egressKind bgpv1alpha1.ServiceVIPBindingEgressKind
}

// String returns the backend as "address:port", the form status messages use.
func (b ruleBackend) String() string {
	return netip.AddrPortFrom(b.addr, b.port).String()
}

// addrFamily is the address family of a rule's VIP.
type addrFamily int

const (
	familyIPv6 addrFamily = iota
	familyIPv4
)

// String returns "IPv6" or "IPv4".
func (f addrFamily) String() string {
	if f == familyIPv4 {
		return "IPv4"
	}
	return "IPv6"
}

// has reports whether addr is of family f. An IPv4-mapped IPv6 address counts
// as IPv4, the family it carries.
func (f addrFamily) has(addr netip.Addr) bool {
	if f == familyIPv4 {
		return addr.Unmap().Is4()
	}
	return addr.Is6() && !addr.Is4In6()
}

// listVPCAttachments lists the VPCAttachments opts select, cluster-wide.
// Attachments live in tenant namespaces while a NetworkService may live in a
// gateway namespace, so the list is never namespaced; selectRuleBackends scopes
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

// ruleSelection is what selectRuleBackends picks for one NetworkService.
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
	return fmt.Sprintf("%s: backend %s is served by NetworkService %s", c.attachment, c.ruleBackend, c.owner)
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

// selectRuleBackends returns the backends that rule's BackendSelector picks
// from attachments for its VIP of family, less those whose claim for that
// family owners assigns to another rule.
//
// Only an attachment whose observed VPC equals rule.Spec.VPCRef is a
// candidate, whatever its labels, so a selector cannot reach another tenant's
// VPC. A selected attachment with no observed node, or no IPv6 interface
// address, is pending rather than a backend: workloads are IPv6 only, and an
// IPv4 VIP reaches its backends through translation to IPv6. An attachment
// with several IPv6 addresses contributes each of them. A backend owned by
// another rule is claimed rather than a backend: its node can translate its
// replies back to only one rule's VIP of each family.
//
// A service in a tenant namespace, one other than objNS (ruleIsTenant), picks
// only attachments in its own namespace, so its selector cannot reach another
// project's workloads even when it names their VPC.
//
// An invalid selector is a spec error and fails the rule.
func selectRuleBackends(
	rule *bgpv1alpha1.NetworkService, attachments []*cloudv1alpha1.VPCAttachment, owners backendOwners,
	family addrFamily, objNS string,
) (ruleSelection, error) {
	candidates, pending, err := ruleCandidateBackends(rule, attachments, objNS)
	if err != nil {
		return ruleSelection{}, err
	}
	sel := ruleSelection{pending: pending}
	self := client.ObjectKeyFromObject(rule)
	for _, b := range candidates {
		if owner, ok := owners[backendClaimFor(rule, b, family)]; ok && owner != self {
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
	rule *bgpv1alpha1.NetworkService, attachments []*cloudv1alpha1.VPCAttachment, objNS string,
) (backends []ruleBackend, pending []string, err error) {
	_, port, err := rulePorts(rule)
	if err != nil {
		return nil, nil, err
	}
	selector, err := ruleBackendSelector(rule)
	if err != nil {
		return nil, nil, err
	}

	for _, attachment := range attachments {
		if attachment.Status.VPC != rule.Spec.VPCRef || !selector.Matches(labels.Set(attachment.Labels)) {
			continue
		}
		if ruleIsTenant(rule, objNS) && attachment.Namespace != rule.Namespace {
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
				uid:        attachment.UID,
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

// errUnservedProtocol is rulePorts' error for a rule whose protocol the
// datapath does not serve.
var errUnservedProtocol = errors.New("the gateway datapath serves tcp and udp only")

// rulePorts returns rule's ingress port and backend port. It refuses any
// protocol but tcp and udp, wrapping errUnservedProtocol, and a port outside
// 1-65535, so no reader of the ports ever serves a rule on port 0.
func rulePorts(rule *bgpv1alpha1.NetworkService) (port, backendPort uint16, err error) {
	switch rule.Spec.Protocol {
	case bgpv1alpha1.NetworkServiceProtocolTCP, bgpv1alpha1.NetworkServiceProtocolUDP:
	default:
		return 0, 0, fmt.Errorf("protocol %q is not served: %w", rule.Spec.Protocol, errUnservedProtocol)
	}
	if rule.Spec.Port < 1 || rule.Spec.Port > 65535 {
		return 0, 0, fmt.Errorf("port %d is outside 1-65535", rule.Spec.Port)
	}
	if rule.Spec.BackendPort < 1 || rule.Spec.BackendPort > 65535 {
		return 0, 0, fmt.Errorf("backendPort %d is outside 1-65535", rule.Spec.BackendPort)
	}
	return uint16(rule.Spec.Port), uint16(rule.Spec.BackendPort), nil
}

// backendClaim identifies the egress vip_xlat_table row a backend's node
// writes for a rule's VIP of one family: the reply from a backend address and
// port, over one protocol, in one VPC. The row rewrites the reply's source to
// one VIP, so only one rule can use a given claim. The VIP's family is part of
// the claim: a reply to an IPv4 client, sent to 64:ff9b::/96, takes the IPv4
// VIP's egress-translated row and any other reply the IPv6 VIP's egress row,
// so one backend socket can answer for one VIP of each family, from one rule
// or two.
type backendClaim struct {
	vpc       string
	addr      netip.Addr
	port      uint16
	protocol  bgpv1alpha1.NetworkServiceProtocol
	vipFamily addrFamily
}

// backendClaimFor returns the claim backend b of rule makes.
func backendClaimFor(rule *bgpv1alpha1.NetworkService, b ruleBackend, vipFamily addrFamily) backendClaim {
	return backendClaim{
		vpc: rule.Spec.VPCRef, addr: b.addr, port: b.port, protocol: rule.Spec.Protocol, vipFamily: vipFamily,
	}
}

// backendOwners maps each backend claim to the rule that owns it.
type backendOwners map[backendClaim]types.NamespacedName

// ruleBackendOwners assigns every backend claim the rules make to the oldest
// rule making it, by creation time and then namespace/name, so the gateway
// and every backend node pick the same owner from the same objects.
//
// A rule makes claims for a family only if its backend nodes would write
// bindings for it: it has exactly one VIP of that family, at most one IPv6
// VIP, and a valid selector (ruleTranslatedVIPs). A rule being deleted keeps
// its claims, since its bindings, and their rows, last until it is gone.
func ruleBackendOwners(
	rules []bgpv1alpha1.NetworkService, attachments []*cloudv1alpha1.VPCAttachment, objNS string,
) backendOwners {
	ordered := make([]*bgpv1alpha1.NetworkService, 0, len(rules))
	for i := range rules {
		ordered = append(ordered, &rules[i])
	}
	sort.Slice(ordered, func(i, j int) bool { return ruleOlder(ordered[i], ordered[j]) })

	owners := make(backendOwners)
	for _, rule := range ordered {
		vips, err := ruleTranslatedVIPs(rule)
		if err != nil {
			continue
		}
		backends, _, err := ruleCandidateBackends(rule, attachments, objNS)
		if err != nil {
			continue
		}
		for _, tv := range vips.valid() {
			for _, b := range backends {
				claim := backendClaimFor(rule, b, tv.family)
				if _, taken := owners[claim]; !taken {
					owners[claim] = client.ObjectKeyFromObject(rule)
				}
			}
		}
	}
	return owners
}

// ruleOlder reports whether a was created before b, breaking a tie on
// creation time, which has one-second resolution, by namespace and name.
func ruleOlder(a, b *bgpv1alpha1.NetworkService) bool {
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

// translatedVIP is one VIP of a rule that backend nodes translate, and its
// family.
type translatedVIP struct {
	family addrFamily
	addr   netip.Addr
}

// ruleVIPs is a rule's VIPs as backend nodes translate them: at most one per
// family.
type ruleVIPs struct {
	// v6 and v4 are the rule's IPv6 and IPv4 VIP, the zero Addr when it has
	// none. v4 is also zero when v4Err is set. v4 is in plain form, whether
	// the spec writes it plainly or IPv4-mapped.
	v6, v4 netip.Addr

	// v4Err is set when the rule has more than one IPv4 VIP, so none of them
	// is translated.
	v4Err error
}

// valid returns the translated VIPs, IPv6 first.
func (v ruleVIPs) valid() []translatedVIP {
	var out []translatedVIP
	if v.v6.IsValid() {
		out = append(out, translatedVIP{family: familyIPv6, addr: v.v6})
	}
	if v.v4.IsValid() {
		out = append(out, translatedVIP{family: familyIPv4, addr: v.v4})
	}
	return out
}

// ruleTranslatedVIPs returns the VIPs of rule that backend nodes translate, at
// most one per family. A backend node rewrites a reply's source from the
// backend's address and port back to a single VIP of the family its client
// uses, so a backend cannot answer for a second VIP of one family and that
// VIP's flows would be lost. For the same reason a backend serves only one rule on a given
// backendPort (ruleBackendOwners).
//
// A second IPv6 VIP fails the whole rule, returned as the error. A second IPv4
// VIP fails only the IPv4 family, reported in v4Err, so the rule's IPv6 VIP
// keeps its bindings. An address that does not parse is an error.
func ruleTranslatedVIPs(rule *bgpv1alpha1.NetworkService) (ruleVIPs, error) {
	var v6, v4 []netip.Addr
	for _, v := range rule.Spec.VIPAddresses {
		vip, err := netip.ParseAddr(v)
		if err != nil {
			return ruleVIPs{}, fmt.Errorf("invalid VIP address %q: %w", v, err)
		}
		if familyIPv4.has(vip) {
			v4 = append(v4, vip.Unmap())
		} else {
			v6 = append(v6, vip)
		}
	}
	var out ruleVIPs
	switch len(v6) {
	case 0:
	case 1:
		out.v6 = v6[0]
	default:
		return ruleVIPs{}, errTooManyVIPs(familyIPv6, len(v6))
	}
	switch len(v4) {
	case 0:
	case 1:
		out.v4 = v4[0]
	default:
		out.v4Err = errTooManyVIPs(familyIPv4, len(v4))
	}
	return out, nil
}

// errTooManyVIPs is ruleTranslatedVIPs' error for a rule with n VIPs of
// family.
func errTooManyVIPs(family addrFamily, n int) error {
	return fmt.Errorf(
		"rule has %d %s VIPs, but a backend node rewrites replies from one backend address, "+
			"backendPort and protocol to only one VIP; serve each further %s VIP from its own rule "+
			"whose backends listen on a different backendPort",
		n, family, family)
}

// ruleBackendSelector converts rule's BackendSelector to a labels.Selector.
// The CRD rejects an empty selector; this rejects one anyway, since an empty
// selector would otherwise match every attachment in the VPC.
func ruleBackendSelector(rule *bgpv1alpha1.NetworkService) (labels.Selector, error) {
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
		if err != nil || !familyIPv6.has(addr) {
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
