// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
)

// Allowlist maps each ServiceAccount, as "namespace/name", to the
// capabilities it may use. A ServiceAccount it does not list may use none.
type Allowlist struct {
	entries map[string][]string
}

// allowlistFile is the YAML form of an allowlist:
//
//	serviceAccounts:
//	- serviceAccount: galactic-system/galactic-nat
//	  capabilities: [local.veth_pair, fabric.srv6]
type allowlistFile struct {
	ServiceAccounts []struct {
		ServiceAccount string   `json:"serviceAccount"`
		Capabilities   []string `json:"capabilities"`
	} `json:"serviceAccounts"`
}

// LoadAllowlist reads an allowlist from a YAML file.
func LoadAllowlist(path string) (*Allowlist, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("auth: read allowlist: %w", err)
	}
	return ParseAllowlist(b)
}

// ParseAllowlist parses the YAML form of an allowlist. It refuses an unknown
// capability, a malformed or repeated ServiceAccount, and unknown fields.
func ParseAllowlist(b []byte) (*Allowlist, error) {
	var f allowlistFile
	if err := yaml.UnmarshalStrict(b, &f); err != nil {
		return nil, fmt.Errorf("auth: parse allowlist: %w", err)
	}
	a := &Allowlist{entries: map[string][]string{}}
	for _, e := range f.ServiceAccounts {
		ns, name, ok := strings.Cut(e.ServiceAccount, "/")
		if !ok || ns == "" || name == "" || strings.Contains(name, "/") {
			return nil, fmt.Errorf("auth: allowlist: %q is not namespace/name", e.ServiceAccount)
		}
		if _, dup := a.entries[e.ServiceAccount]; dup {
			return nil, fmt.Errorf("auth: allowlist: %s is listed twice", e.ServiceAccount)
		}
		for _, c := range e.Capabilities {
			if !slices.Contains(workerv1alpha1.Capabilities, c) {
				return nil, fmt.Errorf("auth: allowlist: %s: unknown capability %q", e.ServiceAccount, c)
			}
		}
		a.entries[e.ServiceAccount] = slices.Clone(e.Capabilities)
	}
	return a, nil
}

// NewAllowlist builds an allowlist from a map, for tests and embedding.
func NewAllowlist(entries map[string][]string) *Allowlist {
	a := &Allowlist{entries: map[string][]string{}}
	for k, v := range entries {
		a.entries[k] = slices.Clone(v)
	}
	return a
}

// Capabilities returns the capabilities serviceAccount may use, and whether
// it is listed at all.
func (a *Allowlist) Capabilities(serviceAccount string) ([]string, bool) {
	if a == nil {
		return nil, false
	}
	c, ok := a.entries[serviceAccount]
	return slices.Clone(c), ok
}
