// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package diag

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// Attachment lifecycle states, as AttachmentState reports them: the first
// stage an attachment has not passed, or Active once it has passed them all.
const (
	StateAdmission   = "Admission"
	StateAllocation  = "Allocation"
	StateProgramming = "Programming"
	StateReady       = "Ready"
	StateActive      = "Active"
	StateDraining    = "Draining"
	StateReleasing   = "Releasing"
)

// Route states, as RouteState reports them.
const (
	RouteUnclaimed = "Unclaimed"
	RoutePending   = "Pending"
	RouteAccepted  = "Accepted"
	RoutePublished = "Published"
	RouteRevoked   = "Revoked"
	RouteReleased  = "Released"
)

// Reasons AttachmentState and RouteState report where no condition gives one.
const (
	// ReasonPending: the stage's condition is not set yet.
	ReasonPending = "Pending"
	// ReasonNotReady: the provider has not reported Ready. Its own reason is
	// provider-written and never used as a label.
	ReasonNotReady = "NotReady"
)

// Label names shared by the state gauges and the failure counter.
const (
	labelProvider = "provider"
	labelReason   = "reason"
)

// ServiceTrafficPolicy is the EdgeService condition reporting whether its
// traffic policy resolves (internal/edge/attachment).
const ServiceTrafficPolicy = "TrafficPolicyResolved"

// AttachmentState returns the lifecycle state att is in and the condition
// reason holding it there. reason is empty for Active.
func AttachmentState(att *galacticv1alpha1.EdgeAttachment) (state, reason string) {
	conds := att.Status.Conditions
	if !att.DeletionTimestamp.IsZero() {
		return StateReleasing, reasonOf(conds, galacticv1alpha1.EdgeAttachmentReleased)
	}
	if c := meta.FindStatusCondition(conds, galacticv1alpha1.EdgeAttachmentDraining); c != nil &&
		c.Status == metav1.ConditionTrue {
		return StateDraining, Reason(c.Reason)
	}
	admitted := meta.FindStatusCondition(conds, galacticv1alpha1.EdgeAttachmentAdmitted)
	allocated := meta.FindStatusCondition(conds, galacticv1alpha1.EdgeAttachmentAllocated)
	switch {
	case admitted != nil && admitted.Status == metav1.ConditionFalse:
		return StateAdmission, Reason(admitted.Reason)
	case allocated != nil && allocated.Status == metav1.ConditionFalse:
		return StateAllocation, Reason(allocated.Reason)
	case admitted == nil || admitted.Status != metav1.ConditionTrue:
		return StateAdmission, ReasonPending
	case allocated == nil || allocated.Status != metav1.ConditionTrue:
		return StateAllocation, ReasonPending
	case !meta.IsStatusConditionTrue(conds, galacticv1alpha1.EdgeAttachmentProgrammed):
		return StateProgramming, reasonOf(conds, galacticv1alpha1.EdgeAttachmentProgrammed)
	case !meta.IsStatusConditionTrue(conds, galacticv1alpha1.EdgeAttachmentReady):
		return StateReady, ReasonNotReady
	}
	return StateActive, ""
}

// RouteState returns the state rt is in and the condition reason holding it
// there: Published or Accepted while a claim is accepted (with the Published
// condition's reason when not published), Released once its holder released
// it, Revoked once core revoked it, Pending while a claim waits or is
// refused, and Unclaimed before any claim.
func RouteState(rt *galacticv1alpha1.EdgeRoute) (state, reason string) {
	conds := rt.Status.Conditions
	acc, c := rt.Status.Accepted, rt.Spec.Claim
	switch {
	case acc != nil && c != nil && c.Released && c.Epoch == acc.Epoch:
		return RouteReleased, ""
	case acc != nil && meta.IsStatusConditionTrue(conds, galacticv1alpha1.EdgeRouteAccepted):
		if meta.IsStatusConditionTrue(conds, galacticv1alpha1.EdgeRoutePublished) {
			return RoutePublished, ""
		}
		return RouteAccepted, reasonOf(conds, galacticv1alpha1.EdgeRoutePublished)
	case acc != nil && (c == nil || c.Epoch <= acc.Epoch):
		return RouteRevoked, reasonOf(conds, galacticv1alpha1.EdgeRouteAccepted)
	case c == nil:
		return RouteUnclaimed, ""
	}
	return RoutePending, reasonOf(conds, galacticv1alpha1.EdgeRouteClaimed)
}

// reasonOf returns the reason of conds' condition t: empty when it is True,
// Pending when it is absent.
func reasonOf(conds []metav1.Condition, t string) string {
	c := meta.FindStatusCondition(conds, t)
	switch {
	case c == nil:
		return ReasonPending
	case c.Status == metav1.ConditionTrue:
		return ""
	}
	return Reason(c.Reason)
}

var (
	attachmentsDesc = prometheus.NewDesc("galactic_edge_foundation_attachments",
		"EdgeAttachments by provider, lifecycle state and the condition reason holding them there.",
		[]string{labelProvider, "state", labelReason}, nil)
	routesDesc = prometheus.NewDesc("galactic_edge_foundation_routes",
		"EdgeRoutes by provider, state and the condition reason holding them there.",
		[]string{labelProvider, "state", labelReason}, nil)
	servicesDesc = prometheus.NewDesc("galactic_edge_foundation_services",
		"EdgeServices by provider and whether their traffic policy resolves (TrafficPolicyResolved), with "+
			"its reason when it does not.",
		[]string{labelProvider, "policy", labelReason}, nil)
	collectErrorsDesc = prometheus.NewDesc("galactic_edge_foundation_state_collect_errors",
		"Kinds the last scrape could not list and left out, rather than reporting zero.", nil, nil)
)

// collectTimeout bounds one scrape's reads.
const collectTimeout = 5 * time.Second

// StateCollector exports the foundation's state gauges from galactic-controller,
// read from its cache at scrape time, so a restart or leader change never
// leaves a stale series. Every replica exports them; aggregate with max.
type StateCollector struct {
	// Reader lists EdgeProviders, EdgeServices, EdgeAttachments and
	// EdgeRoutes, normally the manager's cached client.
	Reader client.Reader
}

// Describe implements prometheus.Collector.
func (s *StateCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{attachmentsDesc, routesDesc, servicesDesc, collectErrorsDesc} {
		ch <- d
	}
}

// key is one series' label values.
type key struct{ provider, state, reason string }

// Collect implements prometheus.Collector. A provider label is the name of an
// approved EdgeProvider, or "unknown": an object naming any other provider
// cannot add a series of its own.
func (s *StateCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()
	failed := 0
	approved := map[string]bool{}
	var providers galacticv1alpha1.EdgeProviderList
	if err := s.Reader.List(ctx, &providers); err != nil {
		failed++
	}
	for i := range providers.Items {
		if providers.Items[i].Status.Approved {
			approved[providers.Items[i].Name] = true
		}
	}
	provider := func(name string) string {
		if approved[name] {
			return name
		}
		return unknownProvider
	}
	emit := func(desc *prometheus.Desc, counts map[key]int) {
		for k, n := range counts {
			ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(n), k.provider, k.state, k.reason)
		}
	}

	var atts galacticv1alpha1.EdgeAttachmentList
	if err := s.Reader.List(ctx, &atts); err != nil {
		failed++
	} else {
		counts := map[key]int{}
		for i := range atts.Items {
			state, reason := AttachmentState(&atts.Items[i])
			counts[key{provider(atts.Items[i].Spec.ProviderRef.Name), state, reason}]++
		}
		emit(attachmentsDesc, counts)
	}

	var routes galacticv1alpha1.EdgeRouteList
	if err := s.Reader.List(ctx, &routes); err != nil {
		failed++
	} else {
		counts := map[key]int{}
		for i := range routes.Items {
			state, reason := RouteState(&routes.Items[i])
			counts[key{provider(routes.Items[i].Spec.ProviderRef.Name), state, reason}]++
		}
		emit(routesDesc, counts)
	}

	var services galacticv1alpha1.EdgeServiceList
	if err := s.Reader.List(ctx, &services); err != nil {
		failed++
	} else {
		counts := map[key]int{}
		for i := range services.Items {
			svc := &services.Items[i]
			policy, reason := "Resolved", ""
			if r := reasonOf(svc.Status.Conditions, ServiceTrafficPolicy); r != "" {
				policy, reason = "Unresolved", r
			}
			counts[key{provider(svc.Spec.ProviderRef.Name), policy, reason}]++
		}
		emit(servicesDesc, counts)
	}
	ch <- prometheus.MustNewConstMetric(collectErrorsDesc, prometheus.GaugeValue, float64(failed))
}
