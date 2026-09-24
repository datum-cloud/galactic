// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"go.datum.net/galactic/internal/plumbing/ebpf/srcfiltermap"
	"go.datum.net/galactic/internal/srcfilter"
)

func srcFilterStatus(t *testing.T, h *health.Server) grpc_health_v1.HealthCheckResponse_ServingStatus {
	t.Helper()
	resp, err := h.Check(context.Background(),
		&grpc_health_v1.HealthCheckRequest{Service: srcFilterHealthServiceName})
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	return resp.GetStatus()
}

func TestSourceFilterPassReportsHealth(t *testing.T) {
	filter, _ := srcfiltermap.NewFake()
	peer := netip.MustParsePrefix("2001:db8:0:2::/64")
	routes := []netlink.Route{{
		Dst:       &net.IPNet{IP: peer.Addr().AsSlice(), Mask: net.CIDRMask(64, 128)},
		LinkIndex: 1,
		Table:     unix.RT_TABLE_MAIN,
		Type:      unix.RTN_UNICAST,
	}}
	var routesErr error

	r, err := srcfilter.New(srcfilter.Options{
		Settings: srcfilter.Settings{
			Mode:           srcfilter.ModeAudit,
			DomainPrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
		},
		Target: srcfilter.USIDTarget{Filter: filter},
		Routes: func() ([]netlink.Route, error) { return routes, routesErr },
		Links: func() ([]netlink.Link, error) {
			return []netlink.Link{&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "uplink0"}}}, nil
		},
		Uplinks: func() ([]string, error) { return []string{"uplink0"}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	h := health.NewServer()
	ctx := context.Background()

	lastErr := sourceFilterPass(ctx, r, h, "")
	if lastErr != "" || srcFilterStatus(t, h) != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("after success: lastErr %q, status %v", lastErr, srcFilterStatus(t, h))
	}

	routesErr = errors.New("netlink dump interrupted")
	lastErr = sourceFilterPass(ctx, r, h, lastErr)
	if lastErr == "" || srcFilterStatus(t, h) != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("after failure: lastErr %q, status %v", lastErr, srcFilterStatus(t, h))
	}
	entries, err := filter.ListAllow()
	if err != nil || len(entries) != 1 {
		t.Fatalf("allow-list after failure = %v, %v; want the previous entry kept", entries, err)
	}

	routesErr = nil
	if lastErr = sourceFilterPass(ctx, r, h, lastErr); lastErr != "" {
		t.Fatalf("recovery pass failed: %s", lastErr)
	}
	if srcFilterStatus(t, h) != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatal("health did not recover")
	}
}

func TestStartSourceFilterWithoutDatapathIsNoOp(t *testing.T) {
	t.Setenv("GALACTIC_CNI_SRV6_SOURCE_FILTER", "enforce")
	h := health.NewServer()
	startSourceFilter(context.Background(), ebpfDatapathState{}, h)
	if _, err := h.Check(context.Background(),
		&grpc_health_v1.HealthCheckRequest{Service: srcFilterHealthServiceName}); err == nil {
		t.Error("health service registered with no datapath loaded")
	}
}
