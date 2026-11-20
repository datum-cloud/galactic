// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"slices"
	"strings"
	"testing"
)

const rendered = `apiVersion: apps/v1
kind: DaemonSet
metadata: {name: w, namespace: ns}
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: c
          securityContext:
            runAsUser: 0
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: {drop: [ALL], add: [NET_ADMIN]}
          volumeMounts:
            - {name: bpf, mountPath: /sys/fs/bpf}
            - {name: netns, mountPath: /var/run/netns, readOnly: true}
            - {name: cfg, mountPath: /etc/c}
      volumes:
        - {name: bpf, hostPath: {path: /sys/fs/bpf}}
        - {name: netns, hostPath: {path: /var/run/netns}}
        - {name: cfg, configMap: {name: c}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: w}
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list]
---
apiVersion: v1
kind: ConfigMap
metadata: {name: galactic-worker-allowlist-abc, namespace: ns}
data:
  allowlist.yaml: |
    serviceAccounts:
      - serviceAccount: ns/nat
        capabilities: [fabric.srv6, local.veth_pair]
`

func TestSummarize(t *testing.T) {
	s, err := Summarize(strings.NewReader(rendered))
	if err != nil {
		t.Fatal(err)
	}
	w := s.Workloads["DaemonSet/ns/w"]
	c := w.Containers["c"]
	if !w.HostNetwork || !w.HostPID || !c.DropsAll || c.AllowPrivilegeEscalation || c.RunAsUser != "0" ||
		c.RunAsGroup != fromImage || c.WritableRootFilesystem ||
		!slices.Equal(c.Capabilities, []string{"NET_ADMIN"}) ||
		!slices.Equal(c.HostPaths, []string{"/sys/fs/bpf:rw", "/var/run/netns"}) {
		t.Fatalf("workload %+v", w)
	}
	if !slices.Equal(s.Roles["ClusterRole/w"], []string{"core/pods:get", "core/pods:list"}) {
		t.Fatalf("roles %v", s.Roles)
	}
	if !slices.Equal(s.WorkerAllowlist["ns/nat"], []string{"fabric.srv6", "local.veth_pair"}) {
		t.Fatalf("allowlist %v", s.WorkerAllowlist)
	}
}

// TestCompareFailsBothWays checks that an unrecorded grant and a stale
// record each fail.
func TestCompareFailsBothWays(t *testing.T) {
	want, err := Summarize(strings.NewReader(rendered))
	if err != nil {
		t.Fatal(err)
	}
	if d := Compare(want, want); len(d) != 0 {
		t.Fatalf("identical summaries differ: %v", d)
	}
	more := strings.Replace(rendered, "add: [NET_ADMIN]", "add: [NET_ADMIN, SYS_ADMIN]", 1)
	got, err := Summarize(strings.NewReader(more))
	if err != nil {
		t.Fatal(err)
	}
	d := Compare(want, got)
	if len(d) != 1 || !strings.Contains(d[0], "granted but not recorded") || !strings.Contains(d[0], "SYS_ADMIN") {
		t.Fatalf("an extra capability: %v", d)
	}
	d = Compare(got, want)
	if len(d) != 1 || !strings.Contains(d[0], "recorded but not granted") {
		t.Fatalf("a stale record: %v", d)
	}
	for _, mutate := range []struct{ from, to, want string }{
		{"runAsUser: 0", "runAsUser: 1", "runAsUser 1"},
		{"readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false", "writable root filesystem"},
	} {
		got, err := Summarize(strings.NewReader(strings.Replace(rendered, mutate.from, mutate.to, 1)))
		if err != nil {
			t.Fatal(err)
		}
		if d := Compare(want, got); !slices.ContainsFunc(d, func(l string) bool { return strings.Contains(l, mutate.want) }) {
			t.Fatalf("%s: %v", mutate.to, d)
		}
	}
	if _, err := Summarize(strings.NewReader("kind: ReplicaSet\nmetadata: {name: r}\n")); err == nil {
		t.Fatal("an unsupported workload kind passed")
	}
}

func TestLeadingCommentsKept(t *testing.T) {
	got := leadingComments([]byte("# why\n# each grant\nworkloads: {}\n# not this\n"))
	if got != "# why\n# each grant\n" {
		t.Fatalf("leading comments %q", got)
	}
	if got := leadingComments([]byte("workloads: {}\n")); got != "" {
		t.Fatalf("no comments, got %q", got)
	}
}
