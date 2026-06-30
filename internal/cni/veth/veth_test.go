// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package veth

import (
	"errors"
	"testing"
)

func TestIsLinkNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"os.IsNotExist", errors.New("no such device"), true},
		{"no such device", errors.New("link not found: no such device"), true},
		{"not found", errors.New("failed to find link: not found"), true},
		{"unrelated", errors.New("permission denied"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLinkNotFoundError(tt.err); got != tt.want {
				t.Errorf("isLinkNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsIptablesRuleNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"rule not found", errors.New("iptables: No chain/target/match by given name. (rule not found)"), true},
		{"no rule found", errors.New("rule not found in table filter"), true},
		{"unrelated", errors.New("permission denied"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isIptablesRuleNotFoundError(tt.err); got != tt.want {
				t.Errorf("isIptablesRuleNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}
