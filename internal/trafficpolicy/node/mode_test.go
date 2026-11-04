// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
)

func TestEffectiveMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   tpmap.State
		err  error
		want galacticv1alpha1.EnforcementMode
	}{
		{"off", tpmap.State{Mode: tpmap.ModeOff, Capable: true}, nil, galacticv1alpha1.ModeOff},
		{"off on an incapable kernel", tpmap.State{Mode: tpmap.ModeOff}, nil, galacticv1alpha1.ModeOff},
		{"audit", tpmap.State{Mode: tpmap.ModeAudit, Capable: true}, nil, galacticv1alpha1.ModeAudit},
		{"enforce", tpmap.State{Mode: tpmap.ModeEnforce, Capable: true}, nil, galacticv1alpha1.ModeEnforce},
		{"audit on an incapable kernel", tpmap.State{Mode: tpmap.ModeAudit}, nil, galacticv1alpha1.ModeUnsupported},
		{"enforce on an incapable kernel", tpmap.State{Mode: tpmap.ModeEnforce}, nil, galacticv1alpha1.ModeUnsupported},
		{"unrecognised mode", tpmap.State{Mode: 9, Capable: true}, nil, galacticv1alpha1.ModeUnknown},
		{"unreadable state", tpmap.State{Mode: tpmap.ModeEnforce, Capable: true}, errors.New("lookup"),
			galacticv1alpha1.ModeUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EffectiveMode(tc.st, tc.err); got != tc.want {
				t.Fatalf("EffectiveMode = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestNodeEntry(t *testing.T) {
	t0 := metav1.NewTime(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	applied := galacticv1alpha1.AppliedPolicy{State: galacticv1alpha1.StateApplied, ObservedGeneration: 1}
	first, changed := nodeEntry(nil, "n1", applied, applied, galacticv1alpha1.ModeEnforce, t0)
	if !changed || first.HeartbeatTime == nil || !first.HeartbeatTime.Equal(&t0) ||
		first.Mode != galacticv1alpha1.ModeEnforce {
		t.Fatalf("first entry = %+v, changed %v", first, changed)
	}

	soon := metav1.NewTime(t0.Add(5 * time.Minute))
	if e, changed := nodeEntry(&first, "n1", applied, applied, galacticv1alpha1.ModeEnforce, soon); changed {
		t.Fatalf("unchanged entry before the heartbeat is due was rewritten: %+v", e)
	}

	if e, changed := nodeEntry(&first, "n1", applied, applied, galacticv1alpha1.ModeAudit, soon); !changed ||
		e.Mode != galacticv1alpha1.ModeAudit || !e.HeartbeatTime.Equal(&t0) {
		t.Fatalf("mode change: entry %+v, changed %v", e, changed)
	}

	due := metav1.NewTime(t0.Add(10 * time.Minute))
	e, changed := nodeEntry(&first, "n1", applied, applied, galacticv1alpha1.ModeEnforce, due)
	if !changed || !e.HeartbeatTime.Equal(&due) {
		t.Fatalf("due heartbeat: entry %+v, changed %v", e, changed)
	}
	if !e.Ingress.LastTransitionTime.Equal(first.Ingress.LastTransitionTime) {
		t.Fatal("a heartbeat moved an unchanged direction's lastTransitionTime")
	}

	future := first.DeepCopy()
	ahead := metav1.NewTime(t0.Add(time.Hour))
	future.HeartbeatTime = &ahead
	e, _ = nodeEntry(future, "n1", applied, applied, galacticv1alpha1.ModeEnforce, soon)
	if !e.HeartbeatTime.Equal(&soon) {
		t.Fatalf("a heartbeat in the future was kept: %v", e.HeartbeatTime)
	}
}

func TestCollectModeWithoutMaps(t *testing.T) {
	want := "\n# HELP galactic_cni_traffic_policy_mode The node's effective interface traffic policy mode: " +
		"1 for the current mode, 0 for the others. Only enforce drops what policy denies; unsupported is " +
		"audit or enforce on a kernel that failed the preflight, and unknown means the mode could not be read." + `
# TYPE galactic_cni_traffic_policy_mode gauge
galactic_cni_traffic_policy_mode{mode="audit"} 0
galactic_cni_traffic_policy_mode{mode="enforce"} 0
galactic_cni_traffic_policy_mode{mode="off"} 0
galactic_cni_traffic_policy_mode{mode="unknown"} 1
galactic_cni_traffic_policy_mode{mode="unsupported"} 0
`
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(&Reconciler{})
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "galactic_cni_traffic_policy_mode"); err != nil {
		t.Fatal(err)
	}
}
