// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import "testing"

func TestParseTrafficPolicyConfig(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }

	cfg, err := ParseTrafficPolicyConfig(env(nil))
	if err != nil || cfg.Mode != TrafficPolicyOff || cfg.Mark != DefaultPolicyMark || !cfg.KernelCheck {
		t.Errorf("defaults = %+v, %v; want off, the default mark and the kernel check", cfg, err)
	}
	cfg, err = ParseTrafficPolicyConfig(env(map[string]string{
		EnvCNITrafficPolicy: "enforce", EnvCNIPolicyMark: "0x100", EnvCNITrafficPolicyKernelCheck: "false",
	}))
	if err != nil || cfg.Mode != TrafficPolicyEnforce || cfg.Mark != 0x100 || cfg.KernelCheck {
		t.Errorf("set = %+v, %v", cfg, err)
	}
	for _, kv := range []map[string]string{
		{EnvCNITrafficPolicy: "on"},
		{EnvCNIPolicyMark: "0x1ffffffff"},
		{EnvCNITrafficPolicyKernelCheck: "maybe"},
	} {
		if _, err := ParseTrafficPolicyConfig(env(kv)); err == nil {
			t.Errorf("%v: want an error", kv)
		}
	}
}
