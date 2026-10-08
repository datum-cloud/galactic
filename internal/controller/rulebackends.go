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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ruleBackend is one backend a NetworkRule's BackendSelector picks: one IPv6
// interface address of one selected VPCAttachment, on the rule's BackendPort.
//
// galactic-gateway load-balances to it and galactic-router on node writes its
// ServiceVIPBinding, and both derive it from the same objects through
// selectRuleBackends, so the gateway never sends a flow to a node that has no
// binding planned for it.
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

// listVPCAttachments lists every VPCAttachment in the cluster. Attachments live
// in tenant namespaces while NetworkRules live in galactic-system, so the list
// is cluster-wide; selectRuleBackends scopes it to one rule's VPC.
func listVPCAttachments(ctx context.Context, c client.Client) ([]*cloudv1alpha1.VPCAttachment, error) {
	list := &cloudv1alpha1.VPCAttachmentList{}
	if err := c.List(ctx, list); err != nil {
		return nil, fmt.Errorf("list VPCAttachments: %w", err)
	}
	out := make([]*cloudv1alpha1.VPCAttachment, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, &list.Items[i])
	}
	return out, nil
}

// selectRuleBackends returns the backends rule's BackendSelector picks from
// attachments, sorted by address, and the selected attachments that are not
// backends yet, as "namespace/name: reason".
//
// Only an attachment whose observed VPC equals rule.Spec.VPCRef is a
// candidate, whatever its labels, so a selector cannot reach another tenant's
// VPC. A selected attachment with no observed node, or no IPv6 interface
// address, is pending rather than a backend: the DSR datapath carries only
// IPv6 backends. An attachment with several IPv6 addresses contributes each of
// them.
//
// An invalid selector is a spec error and fails the rule.
func selectRuleBackends(
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
			pending = append(pending, key.String()+": no node")
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
// VIP's flows would be lost. IPv4 VIPs are not translated (#705).
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
			"rule has %d IPv6 VIPs but a backend can answer for only one; split it into one rule per IPv6 VIP",
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
