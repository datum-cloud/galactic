// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/trafficpolicy"
)

// EffectiveMode is the node's enforcement mode from tp_state, which
// galactic-cni writes at startup. A kernel that failed the preflight
// protects nothing whatever the configured mode, and a state that could not
// be read is never assumed to be enforcing.
func EffectiveMode(st tpmap.State, err error) galacticv1alpha1.EnforcementMode {
	if err != nil {
		return galacticv1alpha1.ModeUnknown
	}
	switch st.Mode {
	case tpmap.ModeOff:
		return galacticv1alpha1.ModeOff
	case tpmap.ModeAudit, tpmap.ModeEnforce:
		if !st.Capable {
			return galacticv1alpha1.ModeUnsupported
		}
		if st.Mode == tpmap.ModeAudit {
			return galacticv1alpha1.ModeAudit
		}
		return galacticv1alpha1.ModeEnforce
	default:
		return galacticv1alpha1.ModeUnknown
	}
}

// modeNames are the galactic_cni_traffic_policy_mode label values, in the
// order the series are exported.
var modeNames = []struct {
	mode galacticv1alpha1.EnforcementMode
	name string
}{
	{galacticv1alpha1.ModeOff, "off"},
	{galacticv1alpha1.ModeAudit, "audit"},
	{galacticv1alpha1.ModeEnforce, "enforce"},
	{galacticv1alpha1.ModeUnsupported, "unsupported"},
	{galacticv1alpha1.ModeUnknown, "unknown"},
}

// nodeEntry builds this node's status entry from the directions' results and
// the node's mode. It keeps existing's heartbeat until it is
// trafficpolicy.HeartbeatInterval old, and reports whether the entry differs
// from existing, so an unchanged entry costs no write between heartbeats.
func nodeEntry(existing *galacticv1alpha1.NodeBindingStatus, node string, in, eg galacticv1alpha1.AppliedPolicy,
	mode galacticv1alpha1.EnforcementMode, now metav1.Time,
) (galacticv1alpha1.NodeBindingStatus, bool) {
	if existing != nil {
		keepTransitionTimes(&[2]*galacticv1alpha1.AppliedPolicy{&in, &eg}, *existing)
	}
	for _, a := range []*galacticv1alpha1.AppliedPolicy{&in, &eg} {
		if a.LastTransitionTime == nil {
			a.LastTransitionTime = &now
		}
	}
	heartbeat := now
	if existing != nil && existing.HeartbeatTime != nil &&
		now.Sub(existing.HeartbeatTime.Time) < trafficpolicy.HeartbeatInterval &&
		!existing.HeartbeatTime.After(now.Time) {
		heartbeat = *existing.HeartbeatTime
	}
	entry := galacticv1alpha1.NodeBindingStatus{
		Node: node, Ingress: &in, Egress: &eg, Mode: mode, HeartbeatTime: &heartbeat,
	}
	changed := existing == nil || !equality.Semantic.DeepEqual(*existing, entry)
	return entry, changed
}

// nowFunc is the clock nodeEntry's caller reads; tests replace it.
var nowFunc = func() metav1.Time { return metav1.NewTime(time.Now().Truncate(time.Second)) }
