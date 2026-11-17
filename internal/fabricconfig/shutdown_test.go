// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"go.datum.net/galactic/internal/rbaccheck"
)

const frrStopBudget = 20

var (
	preStopTimeout = regexp.MustCompile(`\btimeout\s+(\d+)\s`)
	preStopSleep   = regexp.MustCompile(`\bsleep\s+(\d+)\b`)
)

func TestFabricRouterGracePeriodCoversDrain(t *testing.T) {
	for name, components := range map[string][]string{
		"base":       nil,
		"activation": {activationComponent},
	} {
		t.Run(name, func(t *testing.T) {
			out := rbaccheck.Kustomize(t, []string{fabricRouterBase}, components)
			var daemonSets int
			for _, obj := range rbaccheck.Objects(t, out) {
				if obj.GetKind() != "DaemonSet" || obj.GetName() != "fabric-router" {
					continue
				}
				daemonSets++
				raw, found, err := unstructured.NestedFloat64(obj.Object, "spec", "template", "spec",
					"terminationGracePeriodSeconds")
				if err != nil || !found {
					t.Fatalf("terminationGracePeriodSeconds not set (found=%v, err=%v)", found, err)
				}
				grace := int64(raw)
				script := frrPreStop(t, obj)
				timeout := firstInt(t, preStopTimeout, script, "vtysh timeout")
				sleep := firstInt(t, preStopSleep, script, "drain sleep")
				if need := timeout + sleep + frrStopBudget; grace < need {
					t.Errorf("terminationGracePeriodSeconds %d < %d (vtysh timeout %d + drain %d + FRR stop %d)",
						grace, need, timeout, sleep, frrStopBudget)
				}
			}
			if daemonSets != 1 {
				t.Fatalf("%d fabric-router DaemonSets rendered", daemonSets)
			}
		})
	}
}

func frrPreStop(t *testing.T, obj *unstructured.Unstructured) string {
	t.Helper()
	containers, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
	for _, c := range containers {
		container, _ := c.(map[string]any)
		if name, _, _ := unstructured.NestedString(container, "name"); name != "frr" {
			continue
		}
		command, found, _ := unstructured.NestedStringSlice(container, "lifecycle", "preStop", "exec", "command")
		if !found || len(command) == 0 {
			t.Fatal("frr container has no preStop exec command")
		}
		return strings.Join(command, " ")
	}
	t.Fatal("no frr container rendered")
	return ""
}

func firstInt(t *testing.T, re *regexp.Regexp, script, what string) int64 {
	t.Helper()
	m := re.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("frr preStop has no %s matching %s:\n%s", what, re, script)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		t.Fatalf("parse %s %q: %v", what, m[1], err)
	}
	return n
}
