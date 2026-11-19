// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestStatNamesMatchEnum keeps StatNames in step with enum hp_stat in
// handoff.c, which counters are read by.
func TestStatNamesMatchEnum(t *testing.T) {
	src, err := os.ReadFile("handoff.c")
	if err != nil {
		t.Fatal(err)
	}
	body := regexp.MustCompile(`(?s)enum hp_stat \{(.*?)\};`).FindSubmatch(src)
	if body == nil {
		t.Fatal("handoff.c has no enum hp_stat")
	}
	var names []string
	for _, m := range regexp.MustCompile(`HP_STAT_([A-Z0-9_]+)`).FindAllSubmatch(body[1], -1) {
		name := strings.ToLower(string(m[1]))
		if name == "count" {
			continue
		}
		names = append(names, name)
	}
	if strings.Join(names, ",") != strings.Join(StatNames, ",") {
		t.Fatalf("StatNames = %v, enum hp_stat = %v", StatNames, names)
	}
}
