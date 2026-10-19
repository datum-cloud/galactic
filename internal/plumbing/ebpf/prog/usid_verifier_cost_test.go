// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"errors"
	"regexp"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
)

// verifierCostBudget is the most instructions the verifier may process for
// either program. The kernel's own limit is 1,000,000, but crossing it is a
// cliff, not a slope: clamp_tcp_mss's option walk cost about 4,000 at 20 steps
// and over 1,000,000 at 40, which failed every load on every node. This budget
// leaves modest headroom above today's largest program: clang 18 reports about
// 17,800 instructions while newer compilers report about 13,600. It remains
// 35 times below the kernel limit, so a change that starts multiplying verifier
// states fails here, in a unit test, long before it reaches the cliff.
//
// Raising it is fine when a change genuinely needs the room. Measure first:
// this test logs each program's cost.
//
// Interface traffic policy raised it from 20,000 to 24,000. Each program that
// calls tp_capture and tp_decide verifies both global functions once, about
// 2,900 instructions whatever the rule count: usid_ingress went from 18,255 to
// about 21,100 and usid_egress from 9,701 to about 12,500 (clang 21).
//
// A newer kernel verifier raised it from 24,000 to 28,000. With the same
// source and clang 18, usid_ingress costs 21,840 on kernel 6.17 and 24,292 on
// kernel 7.0, which the GitHub runner images moved to.
const verifierCostBudget = 28000

var processedInsns = regexp.MustCompile(`processed (\d+) insns`)

// TestUsid_VerifierCostStaysFarBelowLimit loads both programs with verifier
// statistics on and fails if either one's processed-instruction count passes
// verifierCostBudget.
func TestUsid_VerifierCostStaysFarBelowLimit(t *testing.T) {
	requireRoot(t)
	spec, err := LoadUsid()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier rejected the datapath:\n%+v", ve)
		}
		t.Fatalf("load collection: %v", err)
	}
	defer coll.Close() //nolint:errcheck // test cleanup

	for _, name := range []string{"usid_ingress", "usid_egress"} {
		p := coll.Programs[name]
		if p == nil {
			t.Fatalf("program %q missing from the collection", name)
		}
		m := processedInsns.FindStringSubmatch(p.VerifierLog)
		if m == nil {
			t.Fatalf("%s: no processed-instruction count in the verifier log:\n%s", name, p.VerifierLog)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("%s: parse count %q: %v", name, m[1], err)
		}
		t.Logf("%s: verifier processed %d instructions (budget %d)", name, n, verifierCostBudget)
		if n > verifierCostBudget {
			t.Errorf("%s: verifier processed %d instructions, over the %d budget", name, n, verifierCostBudget)
		}
	}
}
