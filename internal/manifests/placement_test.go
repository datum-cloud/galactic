// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package manifests holds tests over the deployable manifests under config/.
package manifests

import (
	"os"
	"path/filepath"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

const (
	labelNode    = "galactic.datumapis.com/node"
	labelGateway = "galactic.datumapis.com/gateway"
	labelNAT     = "galactic.datumapis.com/nat"
	enabled      = "enabled"
	roleEdge     = "edge"
	controlPlane = "node-role.kubernetes.io/control-plane"
)

func loadDaemonSet(t *testing.T, rel ...string) appsv1.DaemonSet {
	t.Helper()
	path := filepath.Join(append([]string{"..", "..", "config"}, rel...)...)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var ds appsv1.DaemonSet
	if err := yaml.UnmarshalStrict(raw, &ds); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return ds
}

// matches reports whether a node with the given labels satisfies every
// required node-affinity term of the pod template, evaluating only the
// operators these manifests use.
func matches(t *testing.T, ds appsv1.DaemonSet, nodeLabels map[string]string) bool {
	t.Helper()
	aff := ds.Spec.Template.Spec.Affinity
	if aff == nil || aff.NodeAffinity == nil ||
		aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		t.Fatalf("%s has no required node affinity", ds.Name)
	}
	for _, term := range aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
		ok := true
		for _, expr := range term.MatchExpressions {
			val, has := nodeLabels[expr.Key]
			switch expr.Operator {
			case corev1.NodeSelectorOpIn:
				found := false
				for _, v := range expr.Values {
					if has && v == val {
						found = true
					}
				}
				ok = ok && found
			case corev1.NodeSelectorOpDoesNotExist:
				ok = ok && !has
			default:
				t.Fatalf("%s: unsupported operator %q on %s", ds.Name, expr.Operator, expr.Key)
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestGatewayAndNATPlacement(t *testing.T) {
	gateway := loadDaemonSet(t, "galactic-gateway", "base", "daemonset.yaml")
	nat := loadDaemonSet(t, "galactic-nat", "base", "daemonset.yaml")

	tests := []struct {
		name        string
		labels      map[string]string
		wantGateway bool
		wantNAT     bool
	}{
		{name: "unlabeled node runs neither (never automatic)", labels: map[string]string{}},
		{name: "compute node runs neither", labels: map[string]string{labelNode: "compute"}},
		{name: "edge node (galactic-vrf host) runs neither", labels: map[string]string{labelNode: roleEdge}},
		{name: "gateway only", labels: map[string]string{labelGateway: enabled}, wantGateway: true},
		{name: "nat only", labels: map[string]string{labelNAT: enabled}, wantNAT: true},
		{
			name:        "both labels run both",
			labels:      map[string]string{labelGateway: enabled, labelNAT: enabled},
			wantGateway: true, wantNAT: true,
		},
		{
			name:   "gateway label on an edge node is refused",
			labels: map[string]string{labelGateway: enabled, labelNode: roleEdge},
		},
		{
			name:   "nat label on an edge node is refused",
			labels: map[string]string{labelNAT: enabled, labelNode: roleEdge},
		},
		{
			name:   "both labels on a compute node are refused",
			labels: map[string]string{labelGateway: enabled, labelNAT: enabled, labelNode: "compute"},
		},
		{
			name:   "control-plane node is refused",
			labels: map[string]string{labelGateway: enabled, labelNAT: enabled, controlPlane: ""},
		},
		{name: "wrong label value is refused", labels: map[string]string{labelGateway: "true", labelNAT: "true"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matches(t, gateway, tc.labels); got != tc.wantGateway {
				t.Errorf("galactic-gateway placement = %v, want %v", got, tc.wantGateway)
			}
			if got := matches(t, nat, tc.labels); got != tc.wantNAT {
				t.Errorf("galactic-nat placement = %v, want %v", got, tc.wantNAT)
			}
		})
	}
}

func natXDPAttach(ds appsv1.DaemonSet) (string, bool) {
	for _, c := range ds.Spec.Template.Spec.Containers {
		for _, e := range c.Env {
			if e.Name == "GALACTIC_NAT_XDP_ATTACH" {
				return e.Value, true
			}
		}
	}
	return "", false
}

// TestNATChainedOverlay pins the base to the binary's default (attach its own
// program) so it works with no gateway, and leaves chaining to the overlay for
// nodes that also run galactic-gateway.
func TestNATChainedOverlay(t *testing.T) {
	base := loadDaemonSet(t, "galactic-nat", "base", "daemonset.yaml")
	if v, ok := natXDPAttach(base); ok {
		t.Errorf("base sets GALACTIC_NAT_XDP_ATTACH=%q; it must be left to the default so a node with no gateway works", v)
	}

	patch := loadDaemonSet(t, "galactic-nat", "overlays", "chained", "daemonset-patch.yaml")
	if v, ok := natXDPAttach(patch); !ok || v != "chain" {
		t.Errorf("chained overlay GALACTIC_NAT_XDP_ATTACH = %q (set=%v), want chain", v, ok)
	}
}
