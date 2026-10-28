// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package diag is the Galactic Edge foundation's diagnostics: the lifecycle
// stage an attachment or route stopped at, the Kubernetes Events and counters
// galactic-controller and galactic-edge emit when one fails, and the state
// gauges both export.
//
// Every Event carries the same correlation fields in its note, in a fixed
// order, so an operator can follow one attachment or route from admission to
// its forwarding gate across both processes. Metric labels are only stage,
// cause and reason enums and the names of approved EdgeProviders, never an
// attachment, pod, prefix or address, so the series count is bounded by the
// providers and reasons, not by the attachments. Neither carries a credential:
// the foundation's objects hold none, and nothing here reads a Secret or a
// token.
package diag

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// Stage is the lifecycle stage a failure happened in, an Event's action and
// the stage label of every metric.
type Stage string

// Lifecycle stages, in the order an attachment and its routes pass them.
const (
	// StageAdmission is core admitting the attachment, or ending an admitted
	// attachment's authority.
	StageAdmission Stage = "Admission"
	// StageAllocation is core allocating the attachment's address.
	StageAllocation Stage = "Allocation"
	// StageProgramming is the node agent programming the attachment's host
	// state.
	StageProgramming Stage = "Programming"
	// StagePolicy is resolving the traffic policy the service's attachments
	// enforce.
	StagePolicy Stage = "Policy"
	// StageRoute is core accepting, refusing or revoking a route's claim.
	StageRoute Stage = "Route"
	// StageOwnership is the node agent closing a route's forwarding gate.
	StageOwnership Stage = "Ownership"
	// StageCleanup is the node agent releasing host state.
	StageCleanup Stage = "Cleanup"
)

// Gate closure causes: why the node agent closed a forwarding gate.
const (
	// CauseExpired: no renewal extended the gate before its deadline.
	CauseExpired = "Expired"
	// CauseReleased: the holder released the claim.
	CauseReleased = "Released"
	// CauseRevoked: core revoked the accepted claim.
	CauseRevoked = "Revoked"
	// CauseInstanceGone: the holder's instance is gone, or of another boot
	// or node.
	CauseInstanceGone = "InstanceGone"
	// CauseAuthorityEnded: the grant, provider or attachment no longer
	// authorizes the route.
	CauseAuthorityEnded = "AuthorityEnded"
	// CauseGrantCeiling: the grant's validUntil, less the maximum skew,
	// passed.
	CauseGrantCeiling = "GrantCeiling"
	// CauseRouteGone: the route was deleted.
	CauseRouteGone = "RouteGone"
	// CauseHolderMoved: the route was accepted on another attachment or
	// node.
	CauseHolderMoved = "HolderMoved"
)

const (
	reasonOther          = "Other"
	unknownProvider      = "unknown"
	correlationSeparator = " | "
	// maxNote and maxReason are an Event's limits on its note and reason.
	maxNote   = 1024
	maxReason = 128
)

// reasonPattern is a condition reason's form (metav1.Condition). A reason that
// does not match is reported as Other, so a label value never carries free
// text.
var reasonPattern = regexp.MustCompile(`^[A-Za-z]([A-Za-z0-9_,:]{0,62}[A-Za-z0-9_])?$`)

// Reason returns reason as a metric label value: itself when it has a
// condition reason's form, otherwise Other.
func Reason(reason string) string {
	if reasonPattern.MatchString(reason) {
		return reason
	}
	return reasonOther
}

// Correlation names the objects one diagnostic is about. Empty fields are left
// out of an Event's note.
type Correlation struct {
	// Provider is the EdgeProvider's name.
	Provider string
	// Service is the EdgeService granting the attachment, as namespace/name.
	Service string
	// ServiceUID is the granting EdgeService's UID.
	ServiceUID string
	// ServiceGeneration is the EdgeService generation decided on; zero when
	// unknown.
	ServiceGeneration int64
	// Attachment is the EdgeAttachment, as namespace/name.
	Attachment string
	// AttachmentUID is the EdgeAttachment's UID.
	AttachmentUID string
	// PodUID is the provider pod's UID.
	PodUID string
	// Node is the node that programs the attachment or holds the gate.
	Node string
	// Route is the EdgeRoute, as namespace/name.
	Route string
	// Prefix is the route's prefix.
	Prefix string
	// Epoch is the route's claim epoch; zero when not about a route.
	Epoch int64
}

// String is the correlation as space-separated key=value pairs, in a fixed
// order, leaving out empty fields.
func (c Correlation) String() string {
	var pairs []string
	add := func(k, v string) {
		if v != "" {
			pairs = append(pairs, k+"="+v)
		}
	}
	add("provider", c.Provider)
	add("service", c.Service)
	add("serviceUID", c.ServiceUID)
	if c.ServiceGeneration != 0 {
		add("serviceGeneration", strconv.FormatInt(c.ServiceGeneration, 10))
	}
	add("attachment", c.Attachment)
	add("attachmentUID", c.AttachmentUID)
	add("podUID", c.PodUID)
	add("node", c.Node)
	add("route", c.Route)
	add("prefix", c.Prefix)
	if c.Epoch != 0 {
		add("epoch", strconv.FormatInt(c.Epoch, 10))
	}
	return strings.Join(pairs, " ")
}

// Note is an Event's note: the message, then the correlation after " | ".
// The message is shortened, never the correlation, to fit an Event's 1 KiB
// note limit.
func Note(message string, c Correlation) string {
	corr := c.String()
	room := maxNote - len(correlationSeparator) - len(corr)
	if len(message) > room {
		const ellipsis = "..."
		if room < len(ellipsis) {
			message = ""
		} else {
			message = message[:room-len(ellipsis)] + ellipsis
		}
	}
	if corr == "" {
		return message
	}
	return message + correlationSeparator + corr
}

// LabelRole is the constant label naming the role of the process emitting
// the failure counters: RoleCore or RoleNode.
const LabelRole = "edge_role"

// The process roles LabelRole names.
const (
	// RoleCore is galactic-controller's Edge controllers.
	RoleCore = "core"
	// RoleNode is the galactic-edge node agent.
	RoleNode = "node"
)

// Metrics are the foundation's failure counters.
type Metrics struct {
	failures     *prometheus.CounterVec
	gateClosures *prometheus.CounterVec
	cleanup      prometheus.Counter
}

// NewMetrics creates the counters on the instrumentation library's registry.
// role is the emitting process's role, RoleCore or RoleNode, and becomes the
// LabelRole constant label. The registry keeps role's series across calls, so
// each call starts them over.
func NewMetrics(role string) *Metrics {
	labels := prometheus.Labels{LabelRole: role}
	// A vector with no labels, so it can be reset like the others.
	cleanup := metrics.NewCounterVec(prometheus.CounterOpts{
		Name:        "galactic_edge_foundation_cleanup_failures_total",
		Help:        "Host state releases or gate sweeps that failed and are retried on the next pass.",
		ConstLabels: labels,
	}, nil)
	m := &Metrics{
		failures: metrics.NewCounterVec(prometheus.CounterOpts{
			Name: "galactic_edge_foundation_failures_total",
			Help: "Transitions of an attachment, route or service into a failed lifecycle stage, by stage and " +
				"condition reason. Counted once per transition, not per retry.",
			ConstLabels: labels,
		}, []string{"stage", labelReason}),
		gateClosures: metrics.NewCounterVec(prometheus.CounterOpts{
			Name:        "galactic_edge_foundation_gate_closures_total",
			Help:        "Forwarding gates the node agent closed while they were open, by cause.",
			ConstLabels: labels,
		}, []string{"cause"}),
	}
	m.failures.Reset()
	m.gateClosures.Reset()
	cleanup.Reset()
	m.cleanup = cleanup.WithLabelValues()
	return m
}

// Recorder emits the foundation's failure Events and counts them. A nil
// Recorder, or one without Events or Metrics, emits or counts nothing of
// what it lacks.
type Recorder struct {
	// Events records Events; nil records none.
	Events events.EventRecorder
	// Metrics counts failures; nil counts none.
	Metrics *Metrics
}

// Failure records obj entering a failed stage: a Warning Event whose reason
// is reason, action is stage and note is message with the correlation, and
// one count of galactic_edge_foundation_failures_total. Call it on the transition, not on
// every retry.
func (r *Recorder) Failure(obj runtime.Object, stage Stage, reason, message string, c Correlation) {
	if r == nil {
		return
	}
	if r.Metrics != nil {
		r.Metrics.failures.WithLabelValues(string(stage), Reason(reason)).Inc()
	}
	r.event(obj, corev1.EventTypeWarning, stage, reason, message, c)
}

// GateClosed records the node agent closing an open forwarding gate on a
// route: a Warning Event on the route with the cause as its reason, and one
// count of galactic_edge_foundation_gate_closures_total.
func (r *Recorder) GateClosed(obj runtime.Object, cause, message string, c Correlation) {
	if r == nil {
		return
	}
	if r.Metrics != nil {
		r.Metrics.gateClosures.WithLabelValues(cause).Inc()
	}
	r.event(obj, corev1.EventTypeWarning, StageOwnership, cause, message, c)
}

// CleanupFailed counts one failed release or sweep. It emits no Event: the
// object it belongs to may be gone, and the error is logged by the caller.
func (r *Recorder) CleanupFailed() {
	if r == nil || r.Metrics == nil {
		return
	}
	r.Metrics.cleanup.Inc()
}

func (r *Recorder) event(obj runtime.Object, eventType string, stage Stage, reason, message string, c Correlation) {
	if r.Events == nil || obj == nil {
		return
	}
	if len(reason) > maxReason {
		reason = reason[:maxReason]
	}
	r.Events.Eventf(obj, nil, eventType, reason, string(stage), "%s", Note(message, c))
}

// ForAttachment is the correlation of att: its provider, service, pod, node
// and itself. The service generation is left for the caller that read the
// service.
func ForAttachment(att *galacticv1alpha1.EdgeAttachment) Correlation {
	ref := att.Spec.ServiceRef
	return Correlation{
		Provider:      att.Spec.ProviderRef.Name,
		Service:       ref.Namespace + "/" + ref.Name,
		ServiceUID:    ref.UID,
		Attachment:    att.Namespace + "/" + att.Name,
		AttachmentUID: string(att.UID),
		PodUID:        att.Spec.PodUID,
		Node:          att.Status.NodeName,
	}
}

// ForRoute is the correlation of rt and its accepted holder, if any: its
// provider, attachment, node, prefix and epoch. A route with no accepted
// holder carries its pending claim's epoch.
func ForRoute(rt *galacticv1alpha1.EdgeRoute) Correlation {
	c := Correlation{
		Provider: rt.Spec.ProviderRef.Name,
		Route:    rt.Namespace + "/" + rt.Name,
		Prefix:   rt.Spec.Prefix,
	}
	if acc := rt.Status.Accepted; acc != nil {
		c.Attachment = rt.Namespace + "/" + acc.Attachment
		c.AttachmentUID = acc.AttachmentUID
		c.Node = acc.Node
		c.Epoch = acc.Epoch
	}
	if cl := rt.Spec.Claim; cl != nil && cl.Epoch > c.Epoch {
		c.Epoch = cl.Epoch
	}
	return c
}

// EnteredFailure reports whether setting conds' condition t False with
// reason is a transition into that failure rather than a retry of it: t is
// absent, not False, or False with another reason.
func EnteredFailure(conds []metav1.Condition, t, reason string) bool {
	c := meta.FindStatusCondition(conds, t)
	return c == nil || c.Status != metav1.ConditionFalse || c.Reason != reason
}
