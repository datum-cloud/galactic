// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xmitdrops

import (
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"
)

type fakeReader struct {
	counts map[Key]uint64
	err    error
}

func (f fakeReader) Read() (map[Key]uint64, error) { return f.counts, f.err }

func TestReason(t *testing.T) {
	for _, tt := range []struct {
		stage Stage
		errno uint32
		want  string
	}{
		{StageRedirect, uint32(unix.EOPNOTSUPP), "redirect_eopnotsupp"},
		{StageXmit, uint32(unix.ENXIO), "xmit_enxio"},
		{StageXmit, 0, "xmit_dropped"},
		{StageRedirect, 4000, "redirect_errno_4000"},
		{Stage(7), uint32(unix.EINVAL), "stage_7_einval"},
	} {
		if got := Reason(tt.stage, tt.errno); got != tt.want {
			t.Errorf("Reason(%v, %d) = %q, want %q", tt.stage, tt.errno, got, tt.want)
		}
	}
}

func TestCollector(t *testing.T) {
	reader := fakeReader{counts: map[Key]uint64{
		{Ifindex: 3, Stage: StageRedirect, Errno: uint32(unix.EOPNOTSUPP)}: 5,
		{Ifindex: 3, Stage: StageXmit, Errno: 0}:                           2,
		{Ifindex: 9, Stage: StageRedirect, Errno: uint32(unix.EOPNOTSUPP)}: 1,
		// Two ifindexes resolving to the same name sum into one series.
		{Ifindex: 4, Stage: StageRedirect, Errno: uint32(unix.EOPNOTSUPP)}: 4,
	}}
	c := NewCollector("galactic_edge", reader)
	c.ifname = func(ifindex uint32) string {
		switch ifindex {
		case 3, 4:
			return "mgmt0"
		default:
			return "9"
		}
	}

	want := `
# HELP galactic_edge_redirect_xmit_drops_total ` + help + `
# TYPE galactic_edge_redirect_xmit_drops_total counter
galactic_edge_redirect_xmit_drops_total{interface="9",reason="redirect_eopnotsupp"} 1
galactic_edge_redirect_xmit_drops_total{interface="mgmt0",reason="redirect_eopnotsupp"} 9
galactic_edge_redirect_xmit_drops_total{interface="mgmt0",reason="xmit_dropped"} 2
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}

func TestCollectorReadError(t *testing.T) {
	c := NewCollector("galactic_edge", fakeReader{err: errors.New("map gone")})
	if n := testutil.CollectAndCount(c); n != 0 {
		t.Errorf("collected %d series after a read error, want 0", n)
	}
}
