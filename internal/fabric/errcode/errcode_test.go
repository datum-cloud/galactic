// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package errcode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.datum.net/galactic/internal/fabric/frr"
	"go.datum.net/galactic/internal/fabric/probe"
	"go.datum.net/galactic/internal/fabric/query"
)

func TestFromErrorAndOf(t *testing.T) {
	_, qerr := query.Canonicalize(query.Query{Type: query.TypeRouteLookup, Target: "nope"})
	tests := []struct {
		err  error
		code Code
		grpc codes.Code
	}{
		{&frr.Error{Code: frr.CodeResponseTooLarge, Message: "cap"}, ResponseTooLarge, codes.ResourceExhausted},
		{fmt.Errorf("wrapped: %w", &frr.Error{Code: frr.CodeUnavailable}), FRRUnavailable, codes.Unavailable},
		{&probe.Error{Code: probe.CodeSourceUnavailable}, ProbeSourceUnavailable, codes.FailedPrecondition},
		{qerr, InvalidQuery, codes.InvalidArgument},
		{query.DestinationPolicy{}.Check(netipMust("10.0.0.1")), DestinationNotAllowed, codes.InvalidArgument},
		{context.DeadlineExceeded, Timeout, codes.DeadlineExceeded},
		{errors.New("boom"), Internal, codes.Internal},
	}
	for _, tt := range tests {
		got := FromError(tt.err)
		if Of(got) != tt.code || status.Code(got) != tt.grpc {
			t.Errorf("FromError(%v) = %v (%s, %s), want %s/%s", tt.err, got, Of(got), status.Code(got), tt.code, tt.grpc)
		}
	}
	if FromError(nil) != nil || Of(nil) != "" {
		t.Error("nil must stay nil")
	}
}

func TestInvalidQueryCarriesQueryCode(t *testing.T) {
	_, qerr := query.Canonicalize(query.Query{Type: query.TypeBGPSummary, Target: "x"})
	st, _ := status.FromError(FromError(qerr))
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			if info.GetMetadata()[MetadataQueryCode] != string(query.CodeTargetForbidden) {
				t.Errorf("metadata = %v", info.GetMetadata())
			}
			return
		}
	}
	t.Fatal("no ErrorInfo")
}

func TestOfWithoutErrorInfo(t *testing.T) {
	for c, want := range map[codes.Code]Code{
		codes.Unavailable:       NodeUnreachable,
		codes.DeadlineExceeded:  Timeout,
		codes.PermissionDenied:  Unauthorized,
		codes.ResourceExhausted: ResponseTooLarge,
		codes.Unknown:           Internal,
	} {
		if got := Of(status.Error(c, "x")); got != want {
			t.Errorf("Of(%s) = %s, want %s", c, got, want)
		}
	}
}

func TestMessageBounded(t *testing.T) {
	err := Status(Internal, strings.Repeat("x", 1000))
	if len(Message(err)) > query.MaxErrorMessageLength {
		t.Errorf("message length %d", len(Message(err)))
	}
}

func netipMust(s string) netip.Addr { return netip.MustParseAddr(s) }
