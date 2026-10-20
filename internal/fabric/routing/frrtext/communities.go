// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package frrtext

import (
	"slices"
	"sort"
	"strconv"
	"strings"
)

// wellKnown is each well-known community FRR spells by name, with its value.
var wellKnown = map[string]uint64{
	"internet":          0,
	"graceful-shutdown": 0xFFFF0000,
	"accept-own":        0xFFFF0001,
	"llgr-stale":        0xFFFF0006,
	"no-llgr":           0xFFFF0007,
	"blackhole":         0xFFFF029A,
	"no-export":         0xFFFFFF01,
	"no-advertise":      0xFFFFFF02,
	"local-AS":          0xFFFFFF03,
}

// SortedStandard orders standard communities by value, as FRR displays a
// set community line.
func SortedStandard(values []string) []string {
	out := slices.Clone(values)
	sort.SliceStable(out, func(i, j int) bool { return standardValue(out[i]) < standardValue(out[j]) })
	return out
}

func standardValue(c string) uint64 {
	if v, ok := wellKnown[c]; ok {
		return v
	}
	asn, val, _ := strings.Cut(c, ":")
	a, _ := strconv.ParseUint(asn, 10, 16)
	b, _ := strconv.ParseUint(val, 10, 16)
	return a<<16 | b
}

// SortedLarge orders large communities by their three parts.
func SortedLarge(values []string) []string {
	out := slices.Clone(values)
	key := func(c string) [3]uint64 {
		var k [3]uint64
		for i, part := range strings.SplitN(c, ":", 3) {
			k[i], _ = strconv.ParseUint(part, 10, 32)
		}
		return k
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := key(out[i]), key(out[j])
		return slices.Compare(a[:], b[:]) < 0
	})
	return out
}
