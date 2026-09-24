// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"errors"
	"maps"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testNode      = "worker-1"
	testNamespace = "galactic-system"
	legacyKey     = legacyFRRConfKeyPrefix + testNode
	legacyConf    = "old"
)

func configMap(name string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Data:       data,
	}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name       string
		perNode    *corev1.ConfigMap
		legacy     *corev1.ConfigMap
		wantErr    error
		wantLegacy bool
		wantFiles  map[string]string
	}{
		{
			name:      "PerNode",
			perNode:   configMap(ConfigMapName(testNode), map[string]string{KeyFRRConf: "a"}),
			wantFiles: map[string]string{KeyFRRConf: "a"},
		},
		{
			name: "PerNodeWithOverrides",
			perNode: configMap(ConfigMapName(testNode), map[string]string{
				KeyFRRConf: "a", KeyDaemons: "d", KeyVtyshConf: "v",
			}),
			wantFiles: map[string]string{KeyFRRConf: "a", KeyDaemons: "d", KeyVtyshConf: "v"},
		},
		{
			name:      "PerNodeTakesPrecedence",
			perNode:   configMap(ConfigMapName(testNode), map[string]string{KeyFRRConf: "new"}),
			legacy:    configMap(DefaultLegacyConfigMap, map[string]string{legacyKey: legacyConf}),
			wantFiles: map[string]string{KeyFRRConf: "new"},
		},
		{
			name:    "PerNodeMissingFRRConf",
			perNode: configMap(ConfigMapName(testNode), map[string]string{KeyDaemons: "d"}),
			wantErr: ErrInvalid,
		},
		{
			name:    "PerNodeUnknownKey",
			perNode: configMap(ConfigMapName(testNode), map[string]string{KeyFRRConf: "a", "frr.config": "typo"}),
			wantErr: ErrInvalid,
		},
		{
			name:    "PerNodeDoesNotFallBackWhenInvalid",
			perNode: configMap(ConfigMapName(testNode), map[string]string{}),
			legacy:  configMap(DefaultLegacyConfigMap, map[string]string{legacyKey: legacyConf}),
			wantErr: ErrInvalid,
		},
		{
			name: "Legacy",
			legacy: configMap(DefaultLegacyConfigMap, map[string]string{
				legacyKey: legacyConf, "frr.conf.other": "x", KeyVtyshConf: "v",
			}),
			wantLegacy: true,
			wantFiles:  map[string]string{KeyFRRConf: legacyConf, KeyVtyshConf: "v"},
		},
		{
			name:    "LegacyWithoutNodeKey",
			legacy:  configMap(DefaultLegacyConfigMap, map[string]string{"frr.conf.other": "x"}),
			wantErr: ErrNotFound,
		},
		{
			name:    "NoConfigMaps",
			wantErr: ErrNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, err := Resolve(testNode, tt.perNode, tt.legacy)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Resolve() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if src.Legacy != tt.wantLegacy {
				t.Errorf("Resolve() Legacy = %v, want %v", src.Legacy, tt.wantLegacy)
			}
			if !maps.Equal(src.Files, tt.wantFiles) {
				t.Errorf("Resolve() Files = %v, want %v", src.Files, tt.wantFiles)
			}
		})
	}
}
