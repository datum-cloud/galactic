// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want []string
	}{
		{
			name: "unsupported env level on a Galactic image",
			yaml: `
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: galactic-router}
spec:
  template:
    spec:
      containers:
        - name: router
          image: ghcr.io/example/galactic-router:v1.2.3
          env:
            - {name: LOG_LEVEL, value: verbose}
            - {name: LOG_FORMAT, value: json}
`,
			want: []string{`DaemonSet galactic-router: container router: LOG_LEVEL "verbose"`},
		},
		{
			name: "unsupported env format",
			yaml: `
kind: Deployment
metadata: {name: c}
spec:
  template:
    spec:
      containers:
        - name: c
          image: registry.example:5000/galactic-controller@sha256:00
          env: [{name: LOG_FORMAT, value: console}]
`,
			want: []string{`container c: LOG_FORMAT "console"`},
		},
		{
			name: "flags in both forms, in a CronJob",
			yaml: `
kind: CronJob
metadata: {name: janitor}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          initContainers:
            - name: janitor
              image: fabric-api:latest
              args: [janitor, --log-level=loud, --log-format, xml]
`,
			want: []string{`--log-format "xml"`, `--log-level "loud"`},
		},
		{
			name: "supported values",
			yaml: `
containers:
  - name: n
    image: galactic-nat
    args: [--log-level=debug, --log-format=text]
    env: [{name: LOG_LEVEL, value: WARN}]
`,
		},
		{
			name: "other images keep their own log settings",
			yaml: `
containers:
  - name: frr
    image: ghcr.io/example/fabric-router:v1
    args: [--log-level=verbose]
    env: [{name: LOG_LEVEL, value: trace}]
`,
		},
		{
			name: "an empty variable is unset, an empty flag is not",
			yaml: `
containers:
  - name: n
    image: galactic-nat
    args: [--log-format=]
    env: [{name: LOG_LEVEL, value: ""}, {name: LOG_FORMAT, value: ""}]
`,
			want: []string{`--log-format ""`},
		},
		{
			name: "references are not resolved",
			yaml: `
containers:
  - name: n
    image: galactic-nat
    args: [--log-level=$(LEVEL)]
    env: [{name: LOG_LEVEL, valueFrom: {configMapKeyRef: {name: x, key: y}}}]
`,
		},
		{
			name: "image-less container in a kustomization's inline patch",
			yaml: `
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
patches:
  - target: {kind: DaemonSet, name: fabric-router}
    patch: |-
      apiVersion: apps/v1
      kind: DaemonSet
      metadata:
        name: fabric-router
      spec:
        template:
          spec:
            containers:
              - name: fabric-api
                args: [node, --log-level=chatty]
              - name: frr
                args: [--log-level=chatty]
`,
			want: []string{`inline patch: DaemonSet fabric-router: container fabric-api: --log-level "chatty"`},
		},
		{
			name: "fabric-config-agent in the fabric-router image, run directly or from a script",
			yaml: `
kind: DaemonSet
metadata: {name: fabric-router}
spec:
  template:
    spec:
      initContainers:
        - name: frr-init
          image: ghcr.io/example/fabric-router:v1
          command: [sh, -ec, "install -d /run/frr\nexec fabric-config-agent init\n"]
          env: [{name: LOG_LEVEL, value: noisy}]
      containers:
        - name: config-agent
          image: ghcr.io/example/fabric-router:v1
          command: [fabric-config-agent, watch, --log-format=xml]
        - name: frr
          image: ghcr.io/example/fabric-router:v1
          command: [/usr/lib/frr/docker-start]
          env: [{name: LOG_LEVEL, value: noisy}]
`,
			want: []string{
				`container config-agent: --log-format "xml"`,
				`container frr-init: LOG_LEVEL "noisy"`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := check(strings.NewReader(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings %q, want %d matching %q", len(got), got, len(tc.want), tc.want)
			}
			for i, w := range tc.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("finding %d = %q, want it to contain %q", i, got[i], w)
				}
			}
		})
	}
}

func TestIsGalactic(t *testing.T) {
	for _, tc := range []struct {
		name, image string
		want        bool
	}{
		{"x", "ghcr.io/example/galactic-gateway:v1", true},
		{"x", "localhost:5000/fabric-api", true},
		{"x", "galactic-vrf@sha256:00", true},
		{"x", "ghcr.io/example/galactic-cni:v1", true},
		{"x", "ghcr.io/example/galactic-usid:v1", false},
		{"x", "ghcr.io/example/galactic-router-extra:v1", false},
		{"galactic-edge", "", true},
		{"frr", "", false},
	} {
		if got := isGalactic(tc.name, tc.image); got != tc.want {
			t.Errorf("isGalactic(%q, %q) = %v, want %v", tc.name, tc.image, got, tc.want)
		}
	}
}

func TestRunsGalactic(t *testing.T) {
	for _, tc := range []struct {
		command []any
		want    bool
	}{
		{[]any{"fabric-config-agent", "watch"}, true},
		{[]any{"/usr/local/bin/galactic-cni", "run"}, true},
		{[]any{"sh", "-ec", "set -x\nexec fabric-config-agent init"}, true},
		{[]any{"/usr/lib/frr/docker-start"}, false},
		{[]any{"galactic-usid", "decode"}, false},
		{nil, false},
	} {
		if got := runsGalactic(tc.command); got != tc.want {
			t.Errorf("runsGalactic(%q) = %v, want %v", tc.command, got, tc.want)
		}
	}
}
