// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package refusal builds the gRPC errors Worker returns: a status code and a
// google.rpc.ErrorInfo carrying a machine reason from the contract
// (docs/worker/contract.md, "Errors and retry").
package refusal

import (
	"errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
)

// New returns a gRPC error with code, reason and optional ErrorInfo metadata.
func New(code codes.Code, reason, msg string, md map[string]string) error {
	st := status.New(code, msg)
	if d, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason: reason, Domain: workerv1alpha1.ErrorDomain, Metadata: md,
	}); err == nil {
		st = d
	}
	return st.Err()
}

// Reason returns the machine reason of a Worker error, or "" when err
// carries none.
func Reason(err error) string {
	st, ok := status.FromError(err)
	if !ok {
		return ""
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == workerv1alpha1.ErrorDomain {
			return info.GetReason()
		}
	}
	return ""
}

// Is reports whether err is a Worker error with code and reason.
func Is(err error, code codes.Code, reason string) bool {
	if err == nil {
		return false
	}
	var se interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &se) {
		return false
	}
	return se.GRPCStatus().Code() == code && Reason(err) == reason
}
