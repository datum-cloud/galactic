// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const explainPolicy = `apiVersion: galactic.datumapis.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: web
  namespace: tenant
spec:
  rules:
    - name: private-http
      action: Allow
      match:
        path: Private
        protocol: TCP
        destinationPorts:
          - start: 80
            end: 80
    - name: block-dns
      action: Deny
      match:
        protocol: UDP
        destinationPorts:
          - start: 53
            end: 53
`

const verdictDeny = "verdict           deny"

func runExplain(t *testing.T, args ...string) (string, error) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(file, []byte(explainPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newPolicyCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"explain", "--file", file}, args...))
	err := cmd.Execute()
	return out.String(), err
}

// tuple is explain's packet flags: path (empty for none), addresses, and
// any further flags.
func tuple(path, src, dst string, extra ...string) []string {
	args := []string{"--src", src, "--dst", dst}
	if path != "" {
		args = append(args, "--path", path)
	}
	return append(args, extra...)
}

func TestPolicyExplain(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want []string
	}{
		{"rule allows", tuple("Private", "10.0.0.1", "10.0.0.2", "--dport", "80"),
			[]string{"verdict           allow", "private-http (#0)"}},
		{"rule denies", tuple("Private", "fd00::1", "fd00::2", "--proto", "udp", "--dport", "53"),
			[]string{verdictDeny, "block-dns (#1)", "reason            rule"}},
		{"no rule matches", tuple("PublicNAT", "10.0.0.1", "10.0.0.2", "--dport", "80"),
			[]string{verdictDeny, "reason            no_match"}},
		{"unknown path at a path rule", tuple("", "10.0.0.1", "10.0.0.2", "--dport", "80"),
			[]string{verdictDeny, "reason            classification_error"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runExplain(t, tt.args...)
			if err != nil {
				t.Fatalf("explain: %v\n%s", err, out)
			}
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
		})
	}
}

func TestPolicyExplainRejectsBadInput(t *testing.T) {
	for _, args := range [][]string{
		tuple("", "10.0.0.1", "fd00::2"),
		tuple("Elsewhere", "10.0.0.1", "10.0.0.2"),
		tuple("", "10.0.0.1", "10.0.0.2", "--proto", "sctp"),
		tuple("", "nope", "10.0.0.2"),
	} {
		if _, err := runExplain(t, args...); err == nil {
			t.Errorf("explain %v succeeded", args)
		}
	}
}
