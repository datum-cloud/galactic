// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cnitestutil holds the test helpers both master plugins' test suites
// share, the same reasoning as the shared production package but for test
// scaffolding: neither helper is specific to veth or tap, so a fix happens once.
//
// It is a regular importable package rather than a test file, since one
// package's test files cannot import another's.
package cnitestutil

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
)

// AssertCNIError verifies that err is a CNI error with the expected code and a
// message containing wantMsg. Pass an empty wantMsg to skip the message check.
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
