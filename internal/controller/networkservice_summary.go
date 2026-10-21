// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// conditionTypeBackendsReady is the rule-wide condition summarizing whether
// every backend can be reached and answer on the rule's VIPs.
const conditionTypeBackendsReady = "BackendsReady"

// Summary condition reasons. A summary that is not True takes the reason every
// failing node agrees on, so a tenant sees InvalidRule or BackendsClaimed
// rather than a generic one; these are the reasons used otherwise.
const (
	// reasonPending is the summary reason while no node has reported for the
	// rule's current generation.
	reasonPending = "Pending"

	// reasonNoGatewayNodes is the summary reason while no NetworkGateway in the
	// rule's namespace reports on it.
	reasonNoGatewayNodes = "NoGatewayNodes"

	// reasonNotAdvertised is the Advertised summary reason when the nodes that
	// did not advertise the rule disagree on why.
	reasonNotAdvertised = "NotAdvertised"

	// reasonIPv4NotServed is the IPv4Served summary reason when the nodes that
	// do not serve the rule's IPv4 VIP disagree on why.
	reasonIPv4NotServed = "NotServed"

	// reasonBackendsReady is the BackendsReady reason, with status True, once
	// every backend node bound its backends and every gateway node resolved
	// them.
	reasonBackendsReady = "BackendsReady"

	// reasonBackendsNotReady is the BackendsReady reason when the nodes
	// reporting a backend problem disagree on what it is.
	reasonBackendsNotReady = "BackendsNotReady"

	// reasonReady is the Ready reason, with status True.
	reasonReady = "Ready"
)

// vipFamilies records which address families a rule's VIPs cover.
type vipFamilies struct {
	ipv4, ipv6 bool
}

// ruleVIPFamilies returns which address families rule's VIPs cover. An
// IPv4-mapped IPv6 address counts as IPv4, as it does for the datapath.
func ruleVIPFamilies(rule *bgpv1alpha1.NetworkService) vipFamilies {
	var f vipFamilies
	for _, v := range rule.Spec.VIPAddresses {
		addr, err := netip.ParseAddr(v)
		switch {
		case err != nil:
		case isIPv4VIP(addr):
			f.ipv4 = true
		default:
			f.ipv6 = true
		}
	}
	return f
}

// nodeReport is one node's failing condition, as a summary lists it.
type nodeReport struct {
	node, reason string
}

// summaryConditions returns the rule-wide Programmed, Advertised,
// BackendsReady and Ready conditions, plus IPv4Served when the rule has an
// IPv4 VIP, for a rule with conditions at generation, VIPs of families, and
// served by the gateway nodes in gatewayNodes. They summarize the per-node
// conditions every gateway and backend node writes, so a client such as the
// tenant-facing API can tell whether the rule serves without reading
// NetworkGateway or knowing which nodes exist.
//
// Every input is shared state, so every writer computes the same result.
// Only gateway nodes that report a Programmed condition count: a node that
// has not reported yet, or whose datapath is turned off, advertises none of
// the rule's VIPs, so no client is sent to it. It can still receive a reply a
// backend node sends through it, which Ready does not see. Programmed and
// Ready say how many registered nodes have not reported. A per-node
// condition from an older generation counts as not reported.
//
// Advertised covers the routes a node published. Whether the IPv4 VIP is
// served is IPv4Served's alone, and Ready reads it only for a rule with no
// IPv6 VIP: IPv4 VIPs are off on most gateways, and a rule whose IPv6 VIP
// serves must not read as down because its IPv4 VIP does not.
func summaryConditions(
	conditions []metav1.Condition, generation int64, families vipFamilies, gatewayNodes []string,
) []metav1.Condition {
	current := func(condType string) *metav1.Condition {
		c := meta.FindStatusCondition(conditions, condType)
		if c == nil || c.ObservedGeneration != generation {
			return nil
		}
		return c
	}

	nodes := sortedUnique(gatewayNodes)

	var reporting, programmed []string
	var notProgrammed []nodeReport
	for _, n := range nodes {
		c := current(programmedConditionType(n))
		if c == nil {
			continue
		}
		reporting = append(reporting, n)
		if c.Status == metav1.ConditionTrue {
			programmed = append(programmed, n)
		} else {
			notProgrammed = append(notProgrammed, nodeReport{n, c.Reason})
		}
	}
	unreported := ""
	if silent := len(nodes) - len(reporting); silent > 0 {
		unreported = fmt.Sprintf("; %d of %d registered gateway nodes have not reported", silent, len(nodes))
	}

	programmedCond := metav1.Condition{Type: bgpv1alpha1.ConditionTypeProgrammed}
	switch {
	case len(nodes) == 0:
		programmedCond.Status, programmedCond.Reason = metav1.ConditionFalse, reasonNoGatewayNodes
		programmedCond.Message = "no NetworkGateway nodes are registered in this namespace"
	case len(reporting) == 0:
		programmedCond.Status, programmedCond.Reason = metav1.ConditionFalse, reasonPending
		programmedCond.Message = "no gateway node has loaded this generation yet"
	case len(notProgrammed) == 0:
		programmedCond.Status, programmedCond.Reason = metav1.ConditionTrue, reasonProgrammed
		programmedCond.Message = fmt.Sprintf("loaded on %d of %d reporting gateway nodes%s",
			len(programmed), len(reporting), unreported)
	default:
		programmedCond.Status = metav1.ConditionFalse
		programmedCond.Reason = commonReason(notProgrammed, reasonNotProgrammed)
		programmedCond.Message = fmt.Sprintf("loaded on %d of %d reporting gateway nodes%s; not loaded on %s",
			len(programmed), len(reporting), unreported, reportList(notProgrammed))
	}

	// Only a node that loaded the rule is expected to advertise it.
	var advertising int
	var notAdvertised []nodeReport
	for _, n := range programmed {
		switch c := current(advertisedConditionType(n)); {
		case c == nil:
			notAdvertised = append(notAdvertised, nodeReport{n, reasonPending})
		case c.Status != metav1.ConditionTrue:
			notAdvertised = append(notAdvertised, nodeReport{n, c.Reason})
		default:
			advertising++
		}
	}

	advertisedCond := metav1.Condition{Type: conditionTypeAdvertised}
	switch {
	case len(programmed) == 0:
		advertisedCond.Status, advertisedCond.Reason = metav1.ConditionFalse, reasonNotProgrammed
		advertisedCond.Message = "no gateway node has loaded the rule, so none advertises it"
	case len(notAdvertised) == 0:
		advertisedCond.Status, advertisedCond.Reason = metav1.ConditionTrue, reasonAdvertised
		advertisedCond.Message = fmt.Sprintf("advertised from %d of %d gateway nodes that loaded it",
			advertising, len(programmed))
	default:
		advertisedCond.Status = metav1.ConditionFalse
		advertisedCond.Reason = commonReason(notAdvertised, reasonNotAdvertised)
		advertisedCond.Message = fmt.Sprintf("advertised from %d of %d gateway nodes that loaded it; not from %s",
			advertising, len(programmed), reportList(notAdvertised))
	}

	backendsCond := backendsReadyCondition(conditions, generation, programmed)

	out := []metav1.Condition{programmedCond, advertisedCond, backendsCond}
	gate := []metav1.Condition{acceptedGate(current), programmedCond, advertisedCond, backendsCond}
	if families.ipv4 {
		ipv4Cond := ipv4ServedSummary(current, programmed)
		out = append(out, ipv4Cond)
		if !families.ipv6 {
			gate = append(gate, ipv4Cond)
		}
	}

	readyCond := metav1.Condition{
		Type: bgpv1alpha1.ConditionTypeReady, Status: metav1.ConditionTrue,
		Reason: reasonReady, Message: "the rule is loaded, advertised and its backends are ready" + unreported,
	}
	for _, c := range gate {
		if c.Status != metav1.ConditionTrue {
			readyCond.Status, readyCond.Reason = metav1.ConditionFalse, c.Reason
			readyCond.Message = c.Type + ": " + c.Message
			break
		}
	}
	out = append(out, readyCond)

	for i := range out {
		out[i].ObservedGeneration = generation
	}
	return out
}

// acceptedGate returns the rule's Accepted condition for Ready to gate on, or
// a False Pending one when it is missing or from an older generation, so a
// spec edit is never reported Ready before it is accepted.
func acceptedGate(current func(string) *metav1.Condition) metav1.Condition {
	if c := current(bgpv1alpha1.ConditionTypeAccepted); c != nil {
		return *c
	}
	return metav1.Condition{
		Type: bgpv1alpha1.ConditionTypeAccepted, Status: metav1.ConditionFalse,
		Reason: reasonPending, Message: "not accepted for this generation yet",
	}
}

// ipv4ServedSummary returns the rule-wide IPv4Served condition: True once
// every gateway node in programmed serves the rule's IPv4 VIP, and otherwise
// False with the reason those that do not share.
func ipv4ServedSummary(current func(string) *metav1.Condition, programmed []string) metav1.Condition {
	cond := metav1.Condition{Type: conditionTypeIPv4Served}
	var serving int
	var notServed []nodeReport
	for _, n := range programmed {
		switch c := current(ipv4ServedConditionType(n)); {
		case c == nil:
			notServed = append(notServed, nodeReport{n, reasonPending})
		case c.Status != metav1.ConditionTrue:
			notServed = append(notServed, nodeReport{n, c.Reason})
		default:
			serving++
		}
	}
	switch {
	case len(programmed) == 0:
		cond.Status, cond.Reason = metav1.ConditionFalse, reasonNotProgrammed
		cond.Message = "no gateway node has loaded the rule, so none serves its IPv4 VIP"
	case len(notServed) == 0:
		cond.Status, cond.Reason = metav1.ConditionTrue, reasonIPv4Advertised
		cond.Message = fmt.Sprintf("IPv4 VIP served from %d of %d gateway nodes that loaded the rule",
			serving, len(programmed))
	default:
		cond.Status = metav1.ConditionFalse
		cond.Reason = commonReason(notServed, reasonIPv4NotServed)
		cond.Message = fmt.Sprintf("IPv4 VIP served from %d of %d gateway nodes that loaded the rule; not from %s",
			serving, len(programmed), reportList(notServed))
	}
	return cond
}

// backendsReadyCondition summarizes the backend side of a rule: every backend
// node's BackendsBound condition, and whether any gateway node in programmed
// left backends out because their uSID did not resolve.
//
// Two inputs are planned and not written yet: whether every cluster holding a
// backend has the rule, so replies have a path back (#706), and backend health
// (#704). Each adds failing reports here.
func backendsReadyCondition(conditions []metav1.Condition, generation int64, programmed []string) metav1.Condition {
	cond := metav1.Condition{Type: conditionTypeBackendsReady}

	var bound int
	var problems []nodeReport
	for _, c := range conditions {
		node, ok := strings.CutSuffix(c.Type, "/"+conditionTypeBackendsBound)
		if !ok {
			continue
		}
		switch {
		case c.ObservedGeneration != generation:
			problems = append(problems, nodeReport{node, reasonPending})
		case c.Status != metav1.ConditionTrue:
			problems = append(problems, nodeReport{node, c.Reason})
		default:
			bound++
		}
	}
	for _, n := range programmed {
		c := meta.FindStatusCondition(conditions, programmedConditionType(n))
		if c != nil && c.Reason == reasonBackendsUnresolved {
			problems = append(problems, nodeReport{n, reasonBackendsUnresolved})
		}
	}
	sort.Slice(problems, func(i, j int) bool {
		if problems[i].node != problems[j].node {
			return problems[i].node < problems[j].node
		}
		return problems[i].reason < problems[j].reason
	})

	switch {
	case len(problems) > 0:
		cond.Status = metav1.ConditionFalse
		cond.Reason = commonReason(problems, reasonBackendsNotReady)
		cond.Message = "backends not ready on " + reportList(problems)
	case bound == 0:
		cond.Status, cond.Reason = metav1.ConditionFalse, reasonPending
		cond.Message = "no backend node has bound the rule's backends yet"
	default:
		cond.Status, cond.Reason = metav1.ConditionTrue, reasonBackendsReady
		cond.Message = fmt.Sprintf("backends bound on %d nodes", bound)
	}
	return cond
}

// sortedUnique returns names sorted with duplicates removed, so two
// NetworkGateways targeting one node count it once.
func sortedUnique(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	n := 0
	for i, name := range out {
		if i == 0 || name != out[n-1] {
			out[n] = name
			n++
		}
	}
	return out[:n]
}

// commonReason returns the reason every report shares, or fallback when they
// differ.
func commonReason(reports []nodeReport, fallback string) string {
	for _, r := range reports[1:] {
		if r.reason != reports[0].reason {
			return fallback
		}
	}
	return reports[0].reason
}

// reportList renders reports as "node (reason)", capped by cappedList.
func reportList(reports []nodeReport) string {
	items := make([]string, len(reports))
	for i, r := range reports {
		items[i] = r.node + " (" + r.reason + ")"
	}
	return cappedList(items)
}

// applySummaryConditions sets rule's summary conditions (summaryConditions) on
// its status, removes a rule-wide IPv4Served the rule no longer needs, and
// reports whether anything changed.
func applySummaryConditions(rule *bgpv1alpha1.NetworkService, gatewayNodes []string) bool {
	families := ruleVIPFamilies(rule)
	conds := &rule.Status.Conditions
	changed := false
	for _, c := range summaryConditions(*conds, rule.Generation, families, gatewayNodes) {
		changed = meta.SetStatusCondition(conds, c) || changed
	}
	if !families.ipv4 {
		changed = meta.RemoveStatusCondition(conds, conditionTypeIPv4Served) || changed
	}
	return changed
}

// updateSummaryConditions recomputes key's summary conditions and writes them
// only when they changed. Every node writing the rule's status triggers this
// through the NetworkService watch, so an unconditional write would never
// settle. It reads through reader, uncached, so it computes from the write
// that triggered it rather than a cache that has not seen it yet. A rule being
// deleted is left alone, as is one deleted mid-pass.
func updateSummaryConditions(ctx context.Context, c client.Client, reader client.Reader, key client.ObjectKey) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &bgpv1alpha1.NetworkService{}
		if err := reader.Get(ctx, key, current); err != nil {
			return err
		}
		if !current.DeletionTimestamp.IsZero() {
			return nil
		}
		nodes, err := gatewayNodeNames(ctx, c, current.Namespace)
		if err != nil {
			return err
		}
		if !applySummaryConditions(current, nodes) {
			return nil
		}
		return c.Status().Update(ctx, current)
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
