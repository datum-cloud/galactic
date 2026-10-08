// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package errcode defines fabric-api's typed error codes and carries them
// across gRPC as a google.rpc.ErrorInfo reason. The codes are part of the
// internal FabricQuery contract and, through NSO, of the public one.
package errcode

import (
	"context"
	"errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.datum.net/galactic/internal/fabric/frr"
	"go.datum.net/galactic/internal/fabric/probe"
	"go.datum.net/galactic/internal/fabric/query"
)

// Domain is the ErrorInfo domain of every fabric-api error.
const Domain = "fabric-api.datumapis.com"

// Code is a typed fabric-api error code.
type Code string

// Error codes. FRR, probe and validation codes reuse their packages' values.
const (
	FRRUnavailable         Code = Code(frr.CodeUnavailable)
	FRRVersionUnsupported  Code = Code(frr.CodeVersionUnsupported)
	CommandFailed          Code = Code(frr.CodeCommandFailed)
	ResponseTooLarge       Code = Code(frr.CodeResponseTooLarge)
	MalformedResponse      Code = Code(frr.CodeMalformed)
	Timeout                Code = Code(frr.CodeTimeout)
	ProbeSourceUnavailable Code = probe.CodeSourceUnavailable
	ProbeFailed            Code = probe.CodeSocket
	DestinationNotAllowed  Code = Code(query.CodeDestinationDeny)

	// InvalidQuery is any other validation failure; the ErrorInfo metadata
	// carries the query package's own code.
	InvalidQuery Code = "InvalidQuery"
	// QueryTypeUnavailable means the query type is not enabled here, or is
	// suspended by the expensive-query circuit breaker.
	QueryTypeUnavailable Code = "QueryTypeUnavailable"
	// NodeBusy means the node's execution or probe budget is full.
	NodeBusy Code = "NodeBusy"
	// DuplicateConflict means a request ID was reused with different
	// arguments.
	DuplicateConflict Code = "DuplicateConflict"
	// Expired means the request's absolute expiration has passed.
	Expired Code = "Expired"
	// WrongNode means the request named another node.
	WrongNode Code = "WrongNode"
	// Unauthorized means the caller's identity may not make this call.
	Unauthorized Code = "Unauthorized"
	// NodeUnreachable means the gateway could not reach the node.
	NodeUnreachable Code = "NodeUnreachable"
	// Internal is an unexpected failure.
	Internal Code = "Internal"
)

// grpcCodes maps each code to the gRPC status code it travels as.
var grpcCodes = map[Code]codes.Code{
	FRRUnavailable:         codes.Unavailable,
	FRRVersionUnsupported:  codes.FailedPrecondition,
	CommandFailed:          codes.FailedPrecondition,
	ResponseTooLarge:       codes.ResourceExhausted,
	MalformedResponse:      codes.Internal,
	Timeout:                codes.DeadlineExceeded,
	ProbeSourceUnavailable: codes.FailedPrecondition,
	ProbeFailed:            codes.Internal,
	DestinationNotAllowed:  codes.InvalidArgument,
	InvalidQuery:           codes.InvalidArgument,
	QueryTypeUnavailable:   codes.FailedPrecondition,
	NodeBusy:               codes.ResourceExhausted,
	DuplicateConflict:      codes.AlreadyExists,
	Expired:                codes.DeadlineExceeded,
	WrongNode:              codes.FailedPrecondition,
	Unauthorized:           codes.PermissionDenied,
	Internal:               codes.Internal,
}

// MetadataQueryCode is the ErrorInfo metadata key carrying the query
// package's own validation code on an InvalidQuery error.
const MetadataQueryCode = "queryCode"

// Status builds a gRPC error carrying code as its ErrorInfo reason.
func Status(code Code, msg string) error {
	return StatusWithMetadata(code, msg, nil)
}

// StatusWithMetadata is Status with ErrorInfo metadata.
func StatusWithMetadata(code Code, msg string, md map[string]string) error {
	gc, ok := grpcCodes[code]
	if !ok {
		gc = codes.Unknown
	}
	if len(msg) > query.MaxErrorMessageLength {
		msg = msg[:query.MaxErrorMessageLength]
	}
	st, err := status.New(gc, msg).WithDetails(&errdetails.ErrorInfo{Reason: string(code), Domain: Domain, Metadata: md})
	if err != nil {
		return status.Error(gc, msg)
	}
	return st.Err()
}

// FromError converts an error from the frr, probe or query packages into a
// gRPC status. Errors already carrying a status pass through.
func FromError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	if e, ok := errors.AsType[*frr.Error](err); ok {
		return Status(Code(e.Code), e.Error())
	}
	if e, ok := errors.AsType[*probe.Error](err); ok {
		return Status(Code(e.Code), e.Error())
	}
	if c := query.CodeOf(err); c != "" {
		if c == query.CodeDestinationDeny {
			return Status(DestinationNotAllowed, err.Error())
		}
		return StatusWithMetadata(InvalidQuery, err.Error(), map[string]string{MetadataQueryCode: string(c)})
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Status(Timeout, err.Error())
	}
	return Status(Internal, err.Error())
}

// Of returns the fabric-api code of a gRPC error: its ErrorInfo reason when
// one in Domain is present, else a code derived from the gRPC status code.
// It returns "" for nil.
func Of(err error) Code {
	if err == nil {
		return ""
	}
	st, ok := status.FromError(err)
	if !ok {
		if errors.Is(err, context.DeadlineExceeded) {
			return Timeout
		}
		return Internal
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == Domain {
			return Code(info.GetReason())
		}
	}
	switch st.Code() {
	case codes.Unavailable:
		return NodeUnreachable
	case codes.DeadlineExceeded, codes.Canceled:
		return Timeout
	case codes.Unauthenticated, codes.PermissionDenied:
		return Unauthorized
	case codes.ResourceExhausted:
		return ResponseTooLarge
	}
	return Internal
}

// Message returns a gRPC error's message, or err.Error() for any other error,
// bounded to MaxErrorMessageLength.
func Message(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if st, ok := status.FromError(err); ok {
		msg = st.Message()
	}
	if len(msg) > query.MaxErrorMessageLength {
		msg = msg[:query.MaxErrorMessageLength]
	}
	return msg
}
