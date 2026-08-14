// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cnitestutil holds test helpers shared by internal/cni's and
// internal/cnitap's own test suites — the same reasoning as internal/
// cnimaster, but for test-only scaffolding rather than production code:
// neither helper is specific to veth or tap, so a fix only has to happen
// once. Not a _test.go file, since Go doesn't let one package's _test.go
// import another package's _test.go — this is a regular importable package
// that happens to only ever be imported from test code.
package cnitestutil

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
)

// AssertCNIError verifies that err is a *types.Error with the expected Code
// and that its Msg contains wantMsg (substring match). Pass wantMsg == "" to
// skip the message check.
func AssertCNIError(t *testing.T, err error, wantCode uint, wantMsg string) {
	t.Helper()
	var cniErr *types.Error
	if !errors.As(err, &cniErr) {
		t.Fatalf("expected *types.Error, got %T: %v", err, err)
	}
	if cniErr.Code != wantCode {
		t.Fatalf("expected code %d, got %d (Msg: %q)", wantCode, cniErr.Code, cniErr.Msg)
	}
	if wantMsg != "" && !strings.Contains(cniErr.Msg, wantMsg) {
		t.Fatalf("expected Msg to contain %q, got %q", wantMsg, cniErr.Msg)
	}
}

// MustParseCIDR parses cidr and fails the test immediately if it's invalid.
func MustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	return ipnet
}
