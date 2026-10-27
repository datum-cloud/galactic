// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package run runs one RunDiagnostic attempt and records what a consumer
// observed: the status, the stream's grammar and coverage, and when each
// event arrived. A record never holds diagnostic payloads.
package run

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/datum-cloud/galactic/examples/looking-glass-client/internal/rpcerr"
	"github.com/datum-cloud/galactic/examples/looking-glass-client/internal/stream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
)

// Query is a diagnostic in the contract's terms.
type Query struct {
	// Type is RouteLookup, BGPSummary, Ping or Traceroute; any other name
	// is sent as the enum value it names, for negative tests.
	Type   string `json:"type"`
	Target string `json:"target,omitempty"`
	// Family is IPv4, IPv6 or empty to let the target imply it.
	Family string `json:"family,omitempty"`
}

var queryTypes = map[string]fabricv1.QueryType{
	"RouteLookup":    fabricv1.QueryType_QUERY_TYPE_ROUTE_LOOKUP,
	"BGPSummary":     fabricv1.QueryType_QUERY_TYPE_BGP_SUMMARY,
	"Ping":           fabricv1.QueryType_QUERY_TYPE_PING,
	"Traceroute":     fabricv1.QueryType_QUERY_TYPE_TRACEROUTE,
	"ASPath":         fabricv1.QueryType_QUERY_TYPE_AS_PATH,
	"Community":      fabricv1.QueryType_QUERY_TYPE_COMMUNITY,
	"LargeCommunity": fabricv1.QueryType_QUERY_TYPE_LARGE_COMMUNITY,
}

var families = map[string]fabricv1.AddressFamily{
	"":     fabricv1.AddressFamily_ADDRESS_FAMILY_UNSPECIFIED,
	"IPv4": fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4,
	"IPv6": fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6,
}

// Proto returns q as the published Query message. A Type of "enum:N"
// sends the raw enum value N.
func (q Query) Proto() (*fabricv1.Query, error) {
	t, ok := queryTypes[q.Type]
	if raw, isRaw := strings.CutPrefix(q.Type, "enum:"); isRaw {
		n, err := strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("query type %q: %w", q.Type, err)
		}
		t, ok = fabricv1.QueryType(n), true
	}
	if !ok {
		return nil, fmt.Errorf("unknown query type %q", q.Type)
	}
	f, ok := families[q.Family]
	if !ok {
		return nil, fmt.Errorf("unknown address family %q", q.Family)
	}
	return &fabricv1.Query{Type: t, Target: q.Target, AddressFamily: f}, nil
}

// Options describe one attempt and how the consumer behaves.
type Options struct {
	Cell      string   `json:"cell"`
	Project   string   `json:"project"`
	RequestID string   `json:"requestId,omitempty"`
	Query     Query    `json:"query"`
	Nodes     []string `json:"nodes,omitempty"`
	// APIMajor defaults to 1.
	APIMajor uint32 `json:"apiMajor,omitempty"`
	// ExpiresIn sets expires_at from now; it defaults to 30 s.
	ExpiresIn Duration `json:"expiresIn,omitempty"`
	// Deadline is the transport deadline; it defaults to ExpiresIn.
	Deadline         Duration          `json:"deadline,omitempty"`
	RequiredFeatures []string          `json:"requiredFeatures,omitempty"`
	Budgets          *fabricv1.Budgets `json:"-"`
	// ReadDelay sleeps before each read after the first event, as a slow
	// consumer would.
	ReadDelay Duration `json:"readDelay,omitempty"`
	// StopReadingAfter stops reading after that many events and holds the
	// stream open, unread, until the deadline: a stuck consumer.
	StopReadingAfter int `json:"stopReadingAfter,omitempty"`
	// CancelAfterEvents cancels the call once that many events arrived;
	// CancelAfter cancels it that long after the call started.
	CancelAfterEvents int      `json:"cancelAfterEvents,omitempty"`
	CancelAfter       Duration `json:"cancelAfter,omitempty"`
	// Metadata is sent as gRPC request metadata, e.g. to try forging the
	// gateway's internal forwarding headers.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Duration is a time.Duration that reads and writes as a Go duration
// string.
type Duration time.Duration

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	*d = Duration(v)
	return err
}

// Timing holds offsets in milliseconds from the call's start; -1 means the
// moment never came.
type Timing struct {
	FirstEventMS float64 `json:"firstEventMs"`
	SnapshotMS   float64 `json:"snapshotMs"`
	CompleteMS   float64 `json:"completeMs"`
	EndMS        float64 `json:"endMs"`
	// CancelMS is when the client cancelled, and CancelToEndMS how long the
	// stream took to end after it.
	CancelMS      float64 `json:"cancelMs"`
	CancelToEndMS float64 `json:"cancelToEndMs"`
	// OutcomeMS holds each delivered outcome's arrival, in stream order.
	OutcomeMS []float64 `json:"outcomeMs,omitempty"`
}

// Record is what the consumer observed of one attempt.
type Record struct {
	RequestID string        `json:"requestId"`
	Project   string        `json:"project"`
	Query     Query         `json:"query"`
	Nodes     []string      `json:"nodes,omitempty"`
	StartedAt time.Time     `json:"startedAt"`
	Status    rpcerr.Error  `json:"status"`
	Stream    stream.Result `json:"stream"`
	Events    int           `json:"events"`
	// Bytes is the serialized size of every event received, and
	// MaxEventBytes that of the largest.
	Bytes         int    `json:"bytes"`
	MaxEventBytes int    `json:"maxEventBytes"`
	Timing        Timing `json:"timing"`
}

// NewRequestID returns a random lowercase UUID.
func NewRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// Request builds the request o describes, expiring ExpiresIn after now.
func Request(o *Options, now time.Time) (*servicev1.RunDiagnosticRequest, error) {
	if o.RequestID == "" {
		o.RequestID = NewRequestID()
	}
	if o.ExpiresIn == 0 {
		o.ExpiresIn = Duration(30 * time.Second)
	}
	if o.APIMajor == 0 {
		o.APIMajor = 1
	}
	q, err := o.Query.Proto()
	if err != nil {
		return nil, err
	}
	return &servicev1.RunDiagnosticRequest{
		ApiMajor: o.APIMajor, Cell: o.Cell, ProjectId: o.Project, RequestId: o.RequestID,
		ExpiresAt: timestamppb.New(now.Add(time.Duration(o.ExpiresIn))),
		Query:     q, Nodes: o.Nodes, Budgets: o.Budgets, RequiredFeatures: o.RequiredFeatures,
	}, nil
}

// Do runs one attempt on cc. onEvent, if set, sees each event as it
// arrives; it is the only way to reach payloads.
func Do(
	ctx context.Context, cc grpc.ClientConnInterface, o Options, onEvent func(*servicev1.DiagnosticEvent),
) (Record, error) {
	start := time.Now()
	req, err := Request(&o, start)
	if err != nil {
		return Record{}, err
	}
	rec := Record{
		RequestID: o.RequestID, Project: o.Project, Query: o.Query, Nodes: o.Nodes, StartedAt: start.UTC(),
		Timing: Timing{FirstEventMS: -1, SnapshotMS: -1, CompleteMS: -1, CancelMS: -1, CancelToEndMS: -1},
	}
	deadline := time.Duration(o.Deadline)
	if deadline == 0 {
		deadline = time.Duration(o.ExpiresIn)
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	if len(o.Metadata) > 0 {
		ctx = metadata.AppendToOutgoingContext(ctx, mdPairs(o.Metadata)...)
	}
	var cancelledAt time.Time
	doCancel := func() {
		if cancelledAt.IsZero() {
			cancelledAt = time.Now()
			cancel()
		}
	}
	if o.CancelAfter > 0 {
		t := time.AfterFunc(time.Duration(o.CancelAfter), doCancel)
		defer t.Stop()
	}

	check := stream.New(o.RequestID)
	st, err := servicev1.NewLookingGlassServiceClient(cc).RunDiagnostic(ctx, req)
	for err == nil {
		if o.StopReadingAfter > 0 && rec.Events >= o.StopReadingAfter {
			<-ctx.Done()
			err = ctx.Err()
			break
		}
		if o.ReadDelay > 0 && rec.Events > 0 {
			time.Sleep(time.Duration(o.ReadDelay))
		}
		var ev *servicev1.DiagnosticEvent
		if ev, err = st.Recv(); err != nil {
			break
		}
		at := ms(time.Since(start))
		rec.Events++
		size := proto.Size(ev)
		rec.Bytes += size
		rec.MaxEventBytes = max(rec.MaxEventBytes, size)
		if rec.Timing.FirstEventMS < 0 {
			rec.Timing.FirstEventMS = at
		}
		switch ev.GetEvent().(type) {
		case *servicev1.DiagnosticEvent_Snapshot:
			rec.Timing.SnapshotMS = at
		case *servicev1.DiagnosticEvent_Outcome:
			rec.Timing.OutcomeMS = append(rec.Timing.OutcomeMS, at)
		case *servicev1.DiagnosticEvent_Complete:
			rec.Timing.CompleteMS = at
		}
		check.Observe(ev)
		if onEvent != nil {
			onEvent(ev)
		}
		if o.CancelAfterEvents > 0 && rec.Events == o.CancelAfterEvents {
			doCancel()
		}
	}
	end := time.Now()
	rec.Timing.EndMS = ms(end.Sub(start))
	if !cancelledAt.IsZero() {
		rec.Timing.CancelMS = ms(cancelledAt.Sub(start))
		rec.Timing.CancelToEndMS = ms(end.Sub(cancelledAt))
	}
	ok := errors.Is(err, io.EOF)
	if ok {
		err = nil
	}
	rec.Status = rpcerr.Decode(err)
	rec.Stream = check.Finish(ok)
	return rec, nil
}

func mdPairs(md map[string]string) []string {
	kv := make([]string, 0, 2*len(md))
	for k, v := range md {
		kv = append(kv, k, v)
	}
	return kv
}

// Summary is one line describing r for a person.
func Summary(r Record) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", r.RequestID, r.Status.Code)
	if r.Status.Reason != "" {
		fmt.Fprintf(&b, " %s", r.Status.Reason)
	}
	if r.Stream.Complete != nil {
		c := r.Stream.Complete
		fmt.Fprintf(&b, " %s expected=%d successful=%d failed=%d omitted=%d",
			r.Stream.Reason, c.Expected, c.Successful, c.Failed, c.Omitted)
	}
	fmt.Fprintf(&b, " delivered=%t", r.Stream.Delivered)
	if n := len(r.Stream.Violations); n > 0 {
		fmt.Fprintf(&b, " violations=%d", n)
	}
	return b.String()
}
