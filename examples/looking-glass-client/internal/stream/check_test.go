// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package stream

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
)

const fixtureID = "b74e19ee-926f-43dc-b03d-c29550a827ab"

// fixture returns the contract's published example stream: two selected
// routers (one observation, one NodeUnreachable) and one omitted for
// NoCertificatePod, ending PartialResults.
func fixture(t *testing.T) []*servicev1.DiagnosticEvent {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "api", "fabric", "service", "v1", "testdata", "stream.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var evs []*servicev1.DiagnosticEvent
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		ev := &servicev1.DiagnosticEvent{}
		if err := protojson.Unmarshal(sc.Bytes(), ev); err != nil {
			t.Fatal(err)
		}
		evs = append(evs, ev)
	}
	return evs
}

func check(evs []*servicev1.DiagnosticEvent, ok bool) Result {
	c := New(fixtureID)
	for _, ev := range evs {
		c.Observe(ev)
	}
	return c.Finish(ok)
}

func TestFixtureDelivered(t *testing.T) {
	r := check(fixture(t), true)
	if !r.Delivered || len(r.Violations) > 0 {
		t.Fatalf("fixture not delivered: %v", r.Violations)
	}
	if r.Reason != PartialResults || len(r.Outcomes) != 2 || len(r.Pending) != 0 ||
		r.OmittedReasons["router-c"] != "NoCertificatePod" || r.Complete.Expected != 3 {
		t.Errorf("result = %+v", r)
	}
	if r.Outcomes[1].Result != "failure" || r.Outcomes[1].Reason != "NodeUnreachable" {
		t.Errorf("second outcome = %+v", r.Outcomes[1])
	}
}

func TestViolations(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent
		ok     bool
		want   string
	}{
		{"missing complete", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent { return e[:3] }, true, ""},
		{
			"error after complete", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent { return e },
			false, "ended with an error",
		},
		{"sequence gap", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent {
			e[2].Sequence = 4
			return e
		}, true, "sequence 4, want 3"},
		{"foreign request", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent {
			e[1].RequestId = "other"
			return e
		}, true, `request_id "other"`},
		{"outcome first", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent {
			e[0], e[1] = e[1], e[0]
			e[0].Sequence, e[1].Sequence = 1, 2
			return e
		}, true, "outcome before snapshot"},
		{"duplicate outcome", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent {
			e[2].GetOutcome().Node, e[2].GetOutcome().PodUid = "router-a", "pod-a"
			return e
		}, true, "second outcome for router router-a"},
		{"omitted router outcome", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent {
			e[2].GetOutcome().Node = "router-c"
			return e
		}, true, "outcome for omitted router router-c"},
		{"pod swapped", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent {
			e[1].GetOutcome().PodUid = "pod-new"
			return e
		}, true, "snapshot froze pod-a"},
		{"counts disagree", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent {
			e[3].GetComplete().Successful = 2
			e[3].GetComplete().Failed = 0
			return e
		}, true, "delivered events imply"},
		{"wrong reason", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent {
			e[3].GetComplete().Reason = Succeeded
			return e
		}, true, "counts imply PartialResults"},
		{"other snapshot", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent {
			e[3].GetComplete().SnapshotId = "snap-2"
			return e
		}, true, `complete snapshot "snap-2"`},
		{"unknown variant", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent {
			e[2].Event = nil
			return e
		}, true, "unknown event variant"},
		{"event after complete", func(e []*servicev1.DiagnosticEvent) []*servicev1.DiagnosticEvent {
			extra := proto.Clone(e[2]).(*servicev1.DiagnosticEvent)
			extra.Sequence = 5
			return append(e, extra)
		}, true, "after complete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := check(tc.mutate(fixture(t)), tc.ok)
			if r.Delivered {
				t.Fatalf("delivered despite %s", tc.name)
			}
			if tc.want != "" && !slices.ContainsFunc(r.Violations, func(v string) bool { return strings.Contains(v, tc.want) }) {
				t.Errorf("violations %q do not mention %q", r.Violations, tc.want)
			}
		})
	}
}

func TestMissingCompleteLeavesPending(t *testing.T) {
	r := check(fixture(t)[:2], true)
	if r.Delivered || r.Complete != nil || !slices.Equal(r.Pending, []string{"router-b"}) {
		t.Errorf("result = %+v", r)
	}
}

func TestStopReasonOverridesCounts(t *testing.T) {
	evs := fixture(t)
	evs[3].GetComplete().Reason = Cancelled
	if r := check(evs, true); !r.Delivered {
		t.Errorf("a stop reason with consistent counts was refused: %v", r.Violations)
	}
}

func TestImpliedReasons(t *testing.T) {
	c := New("x")
	c.res.OmittedReasons = map[string]string{"r": NotRequested}
	for _, tc := range []struct {
		n    Counts
		want string
	}{
		{Counts{Expected: 1, Omitted: 1}, NoNodesAvailable},
		{Counts{Expected: 2, Failed: 1, Omitted: 1}, ExecutionFailed},
		{Counts{Expected: 2, Successful: 1, Omitted: 1}, Succeeded},
		{Counts{Expected: 3, Successful: 1, Failed: 1, Omitted: 1}, PartialResults},
		{Counts{Expected: 2, Successful: 1, Truncated: 1, Omitted: 1}, PartialResults},
	} {
		if got := c.impliedReason(tc.n); got != tc.want {
			t.Errorf("%+v: got %s, want %s", tc.n, got, tc.want)
		}
	}
	c.res.OmittedReasons["r"] = "NoSidecar"
	if got := c.impliedReason(Counts{Expected: 2, Successful: 1, Omitted: 1}); got != PartialResults {
		t.Errorf("an unavailable router's omission gave %s, want PartialResults", got)
	}
}
