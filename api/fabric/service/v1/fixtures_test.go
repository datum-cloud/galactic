// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// These tests decode the contract's wire examples as an outside consumer
// would: through the published packages and protobuf alone.
package servicev1_test

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
)

func decode(t *testing.T, data []byte, m proto.Message) {
	t.Helper()
	if err := protojson.Unmarshal(data, m); err != nil {
		t.Fatalf("decode %T: %v", m, err)
	}
	// The binary encoding round-trips the decoded message.
	wire, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	back := m.ProtoReflect().New().Interface()
	if err := proto.Unmarshal(wire, back); err != nil || !proto.Equal(m, back) {
		t.Fatalf("%T does not round-trip: %v", m, err)
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRequestFixture(t *testing.T) {
	var req servicev1.RunDiagnosticRequest
	decode(t, fixture(t, "request.json"), &req)
	if req.GetApiMajor() != 1 || req.GetQuery().GetType() != fabricv1.QueryType_QUERY_TYPE_PING ||
		!req.GetExpiresAt().IsValid() || len(req.GetRequiredFeatures()) != 2 {
		t.Errorf("request = %v", &req)
	}
}

func TestCapabilitiesFixture(t *testing.T) {
	var caps servicev1.GetCapabilitiesResponse
	decode(t, fixture(t, "capabilities.json"), &caps)
	if len(caps.GetOperations()) != 4 || caps.GetLimits().GetMaxSelectedRouters() != 32 ||
		caps.GetLimits().GetMaxRequestLifetime().AsDuration().Seconds() != 120 ||
		caps.GetLimits().GetAdmission().GetPacketDestinationPrefix().GetPerSecond() != 40 {
		t.Errorf("capabilities = %v", &caps)
	}
}

// TestStreamFixture decodes the mixed result stream and reconciles its
// terminal coverage with its snapshot, as a consumer must before claiming
// complete coverage.
func TestStreamFixture(t *testing.T) {
	var events []*servicev1.DiagnosticEvent
	lines := bufio.NewScanner(bytes.NewReader(fixture(t, "stream.jsonl")))
	for lines.Scan() {
		ev := &servicev1.DiagnosticEvent{}
		decode(t, lines.Bytes(), ev)
		events = append(events, ev)
	}
	if len(events) != 4 {
		t.Fatalf("%d events", len(events))
	}
	for i, ev := range events {
		if ev.GetSequence() != uint64(i+1) {
			t.Errorf("event %d has sequence %d", i, ev.GetSequence())
		}
	}
	snap, done := events[0].GetSnapshot(), events[3].GetComplete()
	if snap == nil || done == nil {
		t.Fatal("the stream does not open with a snapshot and close with complete")
	}
	selected := 0
	for _, r := range snap.GetRouters() {
		if r.GetSelected() {
			selected++
		}
	}
	loss := events[1].GetOutcome().GetObservation().GetPing()
	failure := events[2].GetOutcome().GetFailure()
	if loss.GetSent() != 3 || loss.GetReceived() != 0 || failure.GetReason() != "NodeUnreachable" {
		t.Errorf("outcomes = %v, %v", events[1], events[2])
	}
	if done.GetSnapshotId() != snap.GetSnapshotId() || done.GetExpected() != uint32(len(snap.GetRouters())) ||
		done.GetSuccessful()+done.GetFailed() != uint32(selected) ||
		done.GetExpected() != done.GetSuccessful()+done.GetFailed()+done.GetOmitted() ||
		done.GetReason() != "PartialResults" {
		t.Errorf("complete %v does not reconcile with the snapshot", done)
	}
}
