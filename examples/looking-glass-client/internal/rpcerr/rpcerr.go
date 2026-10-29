// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rpcerr decodes the typed errors of the Looking Glass service: a
// gRPC status whose google.rpc.ErrorInfo (domain fabric-api.datumapis.com)
// names the reason, with google.rpc.RetryInfo on a refusal that advises a
// delay.
package rpcerr

import (
	"context"
	"errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Domain is the ErrorInfo domain of every fabric-api error.
const Domain = "fabric-api.datumapis.com"

// Error is a decoded RPC outcome. The zero value with Code "OK" is success.
type Error struct {
	Code string `json:"code"`
	// Reason is the ErrorInfo reason; empty when the status carried none,
	// as for a transport failure.
	Reason string `json:"reason,omitempty"`
	// Domain is set when it is not Domain, which marks an error from
	// something other than the service.
	Domain   string            `json:"domain,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	// RetryDelayMS is RetryInfo's delay in milliseconds, or -1 when the
	// status carried no RetryInfo.
	RetryDelayMS int64 `json:"retryDelayMs"`
	// MessageBytes is the length of the status message, which the contract
	// caps at 256 bytes; the message itself is not recorded.
	MessageBytes int `json:"messageBytes,omitempty"`
}

// Decode returns err's status, ErrorInfo and RetryInfo. A nil err is OK.
func Decode(err error) Error {
	out := Error{Code: codes.OK.String(), RetryDelayMS: -1}
	if err == nil {
		return out
	}
	st, ok := status.FromError(err)
	if !ok {
		switch {
		case errors.Is(err, context.Canceled):
			st = status.New(codes.Canceled, err.Error())
		case errors.Is(err, context.DeadlineExceeded):
			st = status.New(codes.DeadlineExceeded, err.Error())
		default:
			st = status.New(codes.Unknown, err.Error())
		}
	}
	out.Code, out.MessageBytes = st.Code().String(), len(st.Message())
	for _, d := range st.Details() {
		switch d := d.(type) {
		case *errdetails.ErrorInfo:
			out.Reason, out.Metadata = d.GetReason(), d.GetMetadata()
			if d.GetDomain() != Domain {
				out.Domain = d.GetDomain()
			}
		case *errdetails.RetryInfo:
			out.RetryDelayMS = d.GetRetryDelay().AsDuration().Milliseconds()
		}
	}
	return out
}
