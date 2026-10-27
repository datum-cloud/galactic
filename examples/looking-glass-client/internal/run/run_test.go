// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/datum-cloud/galactic/examples/looking-glass-client/internal/stream"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
)

// eventStream is the server side of a RunDiagnostic stream.
type eventStream = grpc.ServerStreamingServer[servicev1.DiagnosticEvent]

// fake is a LookingGlassService that runs serve for every RunDiagnostic.
type fake struct {
	servicev1.UnimplementedLookingGlassServiceServer
	serve func(*servicev1.RunDiagnosticRequest, eventStream) error
}

func (f *fake) RunDiagnostic(req *servicev1.RunDiagnosticRequest, s eventStream) error {
	return f.serve(req, s)
}

func dial(t *testing.T, f *fake) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	servicev1.RegisterLookingGlassServiceServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func snapshot(id string) *servicev1.DiagnosticEvent {
	return &servicev1.DiagnosticEvent{RequestId: id, Sequence: 1, Event: &servicev1.DiagnosticEvent_Snapshot{
		Snapshot: &servicev1.Snapshot{SnapshotId: "s", Routers: []*servicev1.SnapshotRouter{
			{Node: "a", PodUid: "pa", Selected: true}, {Node: "b", PodUid: "pb", Selected: true},
		}},
	}}
}

func outcome(id string, seq uint64, node string) *servicev1.DiagnosticEvent {
	return &servicev1.DiagnosticEvent{RequestId: id, Sequence: seq, Event: &servicev1.DiagnosticEvent_Outcome{
		Outcome: &servicev1.RouterOutcome{Node: node, PodUid: "p" + node, CompletedAt: timestamppb.Now(),
			Result: &servicev1.RouterOutcome_Observation{Observation: &fabricv1.Observation{
				Node: node, SampleTime: timestamppb.Now(),
			}}},
	}}
}

func opts() Options {
	return Options{
		Cell: "c", Project: "p", Query: Query{Type: "BGPSummary", Family: "IPv6"}, ExpiresIn: Duration(5 * time.Second),
	}
}

func TestDelivered(t *testing.T) {
	cc := dial(t, &fake{serve: func(req *servicev1.RunDiagnosticRequest, s eventStream) error {
		if req.GetApiMajor() != 1 || req.GetQuery().GetType() != fabricv1.QueryType_QUERY_TYPE_BGP_SUMMARY ||
			req.GetQuery().GetAddressFamily() != fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6 || req.GetProjectId() != "p" {
			return status.Error(codes.InvalidArgument, "unexpected request")
		}
		id := req.GetRequestId()
		for _, ev := range []*servicev1.DiagnosticEvent{snapshot(id), outcome(id, 2, "b"), outcome(id, 3, "a"),
			{RequestId: id, Sequence: 4, Event: &servicev1.DiagnosticEvent_Complete{Complete: &servicev1.Complete{
				SnapshotId: "s", FinishedAt: timestamppb.Now(), Expected: 2, Successful: 2, Reason: stream.Succeeded,
			}}}} {
			if err := s.Send(ev); err != nil {
				return err
			}
		}
		return nil
	}})
	rec, err := Do(t.Context(), cc, opts(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status.Code != "OK" || !rec.Stream.Delivered || rec.Events != 4 || len(rec.Timing.OutcomeMS) != 2 ||
		rec.Timing.SnapshotMS < 0 || rec.Timing.CompleteMS < rec.Timing.SnapshotMS || rec.Timing.CancelMS != -1 {
		t.Errorf("record = %+v", rec)
	}
}

func TestTypedRefusal(t *testing.T) {
	cc := dial(t, &fake{serve: func(*servicev1.RunDiagnosticRequest, eventStream) error {
		st, _ := status.New(codes.ResourceExhausted, "throttled").WithDetails(
			&errdetails.ErrorInfo{Reason: "Throttled", Domain: "fabric-api.datumapis.com",
				Metadata: map[string]string{"scope": "project", "execution_started": "false"}},
			&errdetails.RetryInfo{RetryDelay: durationpb.New(1500 * time.Millisecond)})
		return st.Err()
	}})
	rec, err := Do(t.Context(), cc, opts(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := rec.Status
	if s.Code != "ResourceExhausted" || s.Reason != "Throttled" || s.Domain != "" || s.Metadata["scope"] != "project" ||
		s.RetryDelayMS != 1500 || rec.Stream.Delivered || rec.Events != 0 {
		t.Errorf("record = %+v", rec)
	}
}

// block sends the snapshot and one outcome, then holds the stream until
// the client goes away.
func block(req *servicev1.RunDiagnosticRequest, s eventStream) error {
	id := req.GetRequestId()
	if err := s.Send(snapshot(id)); err != nil {
		return err
	}
	if err := s.Send(outcome(id, 2, "a")); err != nil {
		return err
	}
	<-s.Context().Done()
	return s.Context().Err()
}

func TestCancelAfterEvents(t *testing.T) {
	cc := dial(t, &fake{serve: block})
	o := opts()
	o.CancelAfterEvents = 2
	rec, err := Do(t.Context(), cc, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status.Code != "Canceled" || rec.Stream.Delivered || rec.Timing.CancelMS < 0 ||
		rec.Timing.CancelToEndMS < 0 || rec.Timing.CancelToEndMS > 1000 || len(rec.Stream.Pending) != 1 {
		t.Errorf("record = %+v", rec)
	}
}

func TestStuckConsumerHoldsToDeadline(t *testing.T) {
	cc := dial(t, &fake{serve: block})
	o := opts()
	o.StopReadingAfter, o.Deadline = 1, Duration(300*time.Millisecond)
	rec, err := Do(t.Context(), cc, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status.Code != "DeadlineExceeded" || rec.Events != 1 || rec.Timing.EndMS < 300 {
		t.Errorf("record = %+v", rec)
	}
}

func TestRequestIDIsLowercaseUUID(t *testing.T) {
	id := NewRequestID()
	if len(id) != 36 || id[14] != '4' {
		t.Errorf("request ID %q", id)
	}
	for _, r := range id {
		if r >= 'A' && r <= 'Z' {
			t.Errorf("request ID %q is not lowercase", id)
		}
	}
}

func TestUnknownQueryType(t *testing.T) {
	if _, err := (Query{Type: "Whois"}).Proto(); err == nil {
		t.Error("an unknown query type was accepted")
	}
}
