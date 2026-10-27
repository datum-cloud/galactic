// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/connectip"
)

const notA96 = "/96"

func validConfig() *Config {
	return &Config{
		Provider: "masque-fixture", Authority: "masque.test:8443", Listen: ":8443",
		Services: []Service{
			{Namespace: "ns10", Name: "svc", UID: "s10", VPCUID: "v10", VPC: "10"},
			{Namespace: "ns20", Name: "svc", UID: "s20", VPCUID: "v20", VPC: "20"},
		},
		Connectors: []Connector{
			{ID: "c10", Credential: "t10", Service: "ns10/svc", Prefix: netip.MustParsePrefix("fd00:1::/96")},
			{ID: "c20", Credential: "t20", Service: "ns20/svc", Prefix: netip.MustParsePrefix("fd00:1::/96")},
		},
	}
}

func TestConfigValidate(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("identical /96s in different services: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no authority", func(c *Config) { c.Authority = "" }, "required"},
		{"service without VPC", func(c *Config) { c.Services[0].VPC = "" }, "required"},
		{"duplicate service", func(c *Config) { c.Services[1].Namespace = "ns10" }, "twice"},
		{"shared credential", func(c *Config) { c.Connectors[1].Credential = "t10" }, "not unique"},
		{"unknown service", func(c *Config) { c.Connectors[0].Service = "ns30/svc" }, "unknown service"},
		{"not a /96", func(c *Config) { c.Connectors[0].Prefix = netip.MustParsePrefix("fd00:1::/64") }, notA96},
		{"unmasked", func(c *Config) { c.Connectors[0].Prefix = netip.MustParsePrefix("fd00:1::1/96") }, notA96},
		{"IPv4-mapped", func(c *Config) { c.Connectors[0].Prefix = netip.MustParsePrefix("::ffff:0.0.0.0/96") }, notA96},
		{"same /96 twice in one service", func(c *Config) { c.Connectors[1].Service = "ns10/svc" }, "already used"},
		{"unmasked route", func(c *Config) {
			c.Connectors[0].Routes = []netip.Prefix{netip.MustParsePrefix("fd20::1/32")}
		}, "route"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// fixture returns a provider with both connectors' services served and the
// lease held until deadline on a clock that reads now.
func fixture(t *testing.T, now *time.Duration, deadline time.Duration) *Provider {
	t.Helper()
	p := &Provider{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Config: validConfig(),
		Clock: func() time.Duration { return *now }}
	p.services = map[string]*service{}
	for _, s := range p.Config.Services {
		p.services[s.Key()] = &service{cfg: s,
			attachment: &galacticv1alpha1.EdgeAttachment{ObjectMeta: metav1.ObjectMeta{Name: "ea-" + s.Namespace}}}
	}
	for _, c := range p.Config.Connectors {
		p.connectors = append(p.connectors, &connector{cfg: c, svc: p.services[c.Service], route: "er-" + c.ID,
			grants: map[*grant]struct{}{}})
	}
	p.setLease(&claim.Lease{Key: "ei-pod", Epoch: 1, Deadline: deadline})
	return p
}

// serve marks every service's backend open and every connector's route
// accepted at epoch 3.
func serve(p *Provider) {
	for _, s := range p.services {
		s.backend = &connectip.TUNBackend{}
	}
	for _, c := range p.connectors {
		c.active, c.epoch = true, 3
	}
}

func TestAdmit(t *testing.T) {
	now := time.Second
	p := fixture(t, &now, time.Minute)
	ctx := context.Background()

	if _, err := p.Admit(ctx, "unknown", "10"); !errors.Is(err, connectip.ErrUnauthenticated) {
		t.Errorf("unknown credential: %v, want ErrUnauthenticated", err)
	}
	if _, err := p.Admit(ctx, "t10", "20"); !errors.Is(err, connectip.ErrForbidden) {
		t.Errorf("VPC 10's credential for VPC 20: %v, want ErrForbidden", err)
	}
	if _, err := p.Admit(ctx, "t10", "10"); err == nil || errors.Is(err, connectip.ErrForbidden) ||
		errors.Is(err, connectip.ErrUnauthenticated) {
		t.Errorf("connector without an accepted route: %v, want an unavailable error", err)
	}

	serve(p)
	l, err := p.Admit(ctx, "t20", "20")
	if err != nil {
		t.Fatal(err)
	}
	want := connectip.SessionInfo{ID: 1, Principal: "c20", VPC: "20", Prefix: netip.MustParsePrefix("fd00:1::/96"),
		Connector: p.connectors[1].cfg.ID, Attachment: "ea-ns20", Claim: "er-c20", Epoch: 3}
	if got := l.Info(); got != want {
		t.Errorf("Info() = %+v, want %+v", got, want)
	}

	// Losing the route ends that connector's session and no other.
	other, err := p.Admit(ctx, "t10", "10")
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.deactivate(p.connectors[1], "test")
	p.mu.Unlock()
	select {
	case <-l.Done():
	default:
		t.Error("VPC 20's session survived its route")
	}
	select {
	case <-other.Done():
		t.Error("VPC 10's session ended with VPC 20's route")
	default:
	}
	if _, err := p.Admit(ctx, "t20", "20"); err == nil {
		t.Error("admitted a connector whose route is no longer accepted")
	}
	_ = other.Close()
	if len(p.connectors[0].grants) != 0 {
		t.Error("Close left the grant registered")
	}

	// Past the lease's deadline nothing is admitted.
	serve(p)
	now = 2 * time.Minute
	if _, err := p.Admit(ctx, "t10", "10"); err == nil {
		t.Error("admitted past the lease's deadline")
	}
}

type fakeSession struct{ writes, reads int }

func (s *fakeSession) WritePacket([]byte) error { s.writes++; return nil }
func (s *fakeSession) ReadPacket(context.Context, []byte) (int, error) {
	s.reads++
	return 40, nil
}
func (s *fakeSession) Close() error { return nil }

func TestGatedSessionStopsAtDeadline(t *testing.T) {
	now := time.Second
	p := fixture(t, &now, 10*time.Second)
	inner := &fakeSession{}
	s := &gatedSession{BackendSession: inner, allow: p.forwarding}
	buf := make([]byte, 64)
	if err := s.WritePacket(buf); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ReadPacket(context.Background(), buf); err != nil || n != 40 {
		t.Fatalf("ReadPacket = %d, %v", n, err)
	}
	now = 10 * time.Second
	if err := s.WritePacket(buf); !errors.Is(err, errExpired) {
		t.Errorf("write at the deadline: %v, want errExpired", err)
	}
	if _, err := s.ReadPacket(context.Background(), buf); !errors.Is(err, errExpired) {
		t.Errorf("read at the deadline: %v, want errExpired", err)
	}
	if inner.writes != 1 {
		t.Errorf("%d writes reached the device, want 1", inner.writes)
	}
}
