// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cell

import (
	"fmt"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/trafficpolicy"
)

// maxNamedNodes bounds how many nodes a condition message names.
const maxNamedNodes = 5

// notEnforcingReasons are the Enforcing=False reasons for an installed
// binding, most severe first: a node that cannot protect the interface at
// all outranks one deliberately off, which outranks one auditing, which
// outranks one whose mode is not known.
var notEnforcingReasons = []galacticv1alpha1.EnforcementMode{
	galacticv1alpha1.ModeUnsupported,
	galacticv1alpha1.ModeOff,
	galacticv1alpha1.ModeAudit,
	galacticv1alpha1.ModeUnknown,
}

// notInstalledReasons are the Installed=False reasons, most severe first.
var notInstalledReasons = []string{
	galacticv1alpha1.ReasonFailed,
	galacticv1alpha1.ReasonStale,
	galacticv1alpha1.ReasonPending,
}

// Readiness derives the binding's Installed and Enforcing conditions, as of
// now, from the status.nodes entry of node, the node the interface is on. An
// entry another node left behind, such as one lost while the interface moved
// away, is ignored rather than holding the binding Stale. An Applied entry
// alone never makes a binding Enforcing: the node must also report Enforce,
// at the binding's current generation, within trafficpolicy.StaleAfter. It
// keeps no state, so a restarted controller derives the same conditions.
//
// next is how long until the node's heartbeat goes stale, the soonest moment
// the conditions can change without a status write; zero means none can.
func Readiness(b *galacticv1alpha1.TrafficPolicyBinding, node string, now time.Time) (
	installed, enforcing metav1.Condition, next time.Duration,
) {
	installed = metav1.Condition{Type: galacticv1alpha1.BindingInstalled, ObservedGeneration: b.Generation}
	enforcing = metav1.Condition{Type: galacticv1alpha1.BindingEnforcing, ObservedGeneration: b.Generation}
	falseBoth := func(reason, msg string) {
		installed.Status, installed.Reason, installed.Message = metav1.ConditionFalse, reason, msg
		enforcing.Status, enforcing.Reason, enforcing.Message = metav1.ConditionFalse, reason, msg
	}

	if node == "" {
		falseBoth(galacticv1alpha1.ReasonNoNodes, "the interface is not on a node")
		return installed, enforcing, 0
	}
	var current []galacticv1alpha1.NodeBindingStatus
	for _, n := range b.Status.Nodes {
		if n.Node == node {
			current = append(current, n)
		}
	}
	if len(current) == 0 {
		falseBoth(galacticv1alpha1.ReasonPending, "no report yet from "+node+", the node the interface is on")
		return installed, enforcing, 0
	}

	notInstalled := map[string][]string{}
	notEnforcing := map[galacticv1alpha1.EnforcementMode][]string{}
	for _, n := range current {
		if n.HeartbeatTime == nil || now.Sub(n.HeartbeatTime.Time) >= trafficpolicy.StaleAfter {
			notInstalled[galacticv1alpha1.ReasonStale] = append(notInstalled[galacticv1alpha1.ReasonStale], n.Node)
			continue
		}
		if until := n.HeartbeatTime.Add(trafficpolicy.StaleAfter).Sub(now); next == 0 || until < next {
			next = until
		}
		if reason := installState(n, b.Generation); reason != "" {
			notInstalled[reason] = append(notInstalled[reason], n.Node)
			continue
		}
		if n.Mode != galacticv1alpha1.ModeEnforce {
			mode := n.Mode
			if !slices.Contains(notEnforcingReasons, mode) {
				mode = galacticv1alpha1.ModeUnknown // absent: a node that predates the field
			}
			notEnforcing[mode] = append(notEnforcing[mode], n.Node)
		}
	}

	for _, reason := range notInstalledReasons {
		if nodes, ok := notInstalled[reason]; ok {
			falseBoth(reason, installMessage(reason, nodes))
			return installed, enforcing, next
		}
	}
	installed.Status, installed.Reason = metav1.ConditionTrue, galacticv1alpha1.ReasonInstalled
	installed.Message = node + " has installed the desired policy in both directions"

	for _, mode := range notEnforcingReasons {
		if nodes, ok := notEnforcing[mode]; ok {
			enforcing.Status, enforcing.Reason = metav1.ConditionFalse, string(mode)
			enforcing.Message = fmt.Sprintf("installed but not enforced: mode is %s on %s", mode, nodeList(nodes))
			return installed, enforcing, next
		}
	}
	enforcing.Status, enforcing.Reason = metav1.ConditionTrue, galacticv1alpha1.ReasonEnforcing
	enforcing.Message = node + " enforces the desired policy in both directions"
	return installed, enforcing, next
}

// installState is why a current node has not installed the binding's
// desired policy, or "" when both directions are Applied at generation.
func installState(n galacticv1alpha1.NodeBindingStatus, generation int64) string {
	reason := ""
	for _, a := range []*galacticv1alpha1.AppliedPolicy{n.Ingress, n.Egress} {
		switch {
		case a == nil:
			reason = galacticv1alpha1.ReasonPending
		case a.State == galacticv1alpha1.StateFailed:
			return galacticv1alpha1.ReasonFailed
		case a.State != galacticv1alpha1.StateApplied, a.ObservedGeneration != generation:
			reason = galacticv1alpha1.ReasonPending
		}
	}
	return reason
}

func installMessage(reason string, nodes []string) string {
	switch reason {
	case galacticv1alpha1.ReasonFailed:
		return "installation failed on " + nodeList(nodes)
	case galacticv1alpha1.ReasonStale:
		return fmt.Sprintf("no report within %s from %s", trafficpolicy.StaleAfter, nodeList(nodes))
	default:
		return "the desired policy is not installed yet on " + nodeList(nodes)
	}
}

func nodeList(nodes []string) string {
	slices.Sort(nodes)
	if len(nodes) > maxNamedNodes {
		return fmt.Sprintf("%s and %d more", strings.Join(nodes[:maxNamedNodes], ", "), len(nodes)-maxNamedNodes)
	}
	return strings.Join(nodes, ", ")
}
