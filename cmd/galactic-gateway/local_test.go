// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/gateway/localhandoff"
)

type memTable map[netip.Addr]uint32

func (m memTable) Set(sid netip.Addr, tap uint32) error { m[sid] = tap; return nil }
func (m memTable) Delete(sid netip.Addr) error          { delete(m, sid); return nil }
func (m memTable) List() (map[netip.Addr]uint32, error) {
	out := map[netip.Addr]uint32{}
	for k, v := range m {
		out[k] = v
	}
	return out, nil
}

func noWorker(context.Context) (localhandoff.ClaimAPI, error) { return nil, errors.New("no worker") }

// TestPublicPathState (D44): a public target without the load balancer, or a
// missing public uplink while local backends are served, withdraws both
// families; an internal return target or an uplink with no local backends
// does not.
func TestPublicPathState(t *testing.T) {
	cov := newDatapathCoverage(nil)
	p := newPublicPath(cov, nil)
	p.uplink = func() (bool, error) { return false, nil }
	if s := p.State(); s != (controller.PublicPathState{}) {
		t.Errorf("covered, no local backends: %+v, want nothing withdrawn", s)
	}

	cov.set([]string{"eth9"}) // a return target only
	if s := p.State(); s != (controller.PublicPathState{}) {
		t.Errorf("internal target missing: %+v, want nothing withdrawn", s)
	}

	cov.setPublic([]string{"bond0-member"})
	cov.set([]string{"bond0-member"})
	s := p.State()
	if !strings.Contains(s.IPv6, "bond0-member") || s.IPv4 != s.IPv6 {
		t.Errorf("public member missing: %+v, want both families withdrawn naming the member", s)
	}
	cov.setPublic(nil)
	cov.set(nil)

	m := localhandoff.New("node-a", noWorker, memTable{}, nil)
	m.SetBackends([]localhandoff.Backend{{AttachmentUID: "a", VPC: "v", Slot: 1,
		USID: netip.MustParseAddr("2001:db8::1")}})
	p = newPublicPath(cov, m)
	p.uplink = func() (bool, error) { return false, nil }
	if s := p.State(); !strings.Contains(s.IPv6, "public_uplink_table") || s.IPv4 == "" {
		t.Errorf("no uplink with local backends: %+v, want both families withdrawn", s)
	}
	// With no Worker session WorkerUnavailable is reported first; either
	// way the backend is not ready.
	if a := m.Snapshot().Attachments[0]; a.Ready {
		t.Errorf("local backend = %+v, want not ready while the uplink is missing", a)
	}
	p.uplink = func() (bool, error) { return true, nil }
	if s := p.State(); s != (controller.PublicPathState{}) {
		t.Errorf("uplink present: %+v, want nothing withdrawn", s)
	}
}

// TestLocalHandoffOrNil keeps a nil manager from becoming a non-nil
// interface the reconciler would call.
func TestLocalHandoffOrNil(t *testing.T) {
	if localHandoffOrNil(nil) != nil {
		t.Error("nil manager became a non-nil LocalHandoff")
	}
}
