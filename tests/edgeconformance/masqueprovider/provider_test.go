// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/masque"
	"go.datum.net/galactic/internal/edge/masque/authority"
)

const (
	notA96   = "/96"
	svcName  = "svc"
	required = "required"
)

func validConfig() *Config {
	return &Config{
		Provider: "masque-fixture", Authority: "masque.test:8443", Listen: ":8443",
		Services: []Service{
			{Namespace: "ns10", Name: svcName, UID: "s10", VPCUID: "v10", VPCID: "000000v10", VPC: "10"},
			{Namespace: "ns20", Name: svcName, UID: "s20", VPCUID: "v20", VPCID: "000000v20", VPC: "20"},
		},
		Connectors: []Connector{
			{ID: "c10", Credential: "t10", Service: "ns10/svc", Prefix: netip.MustParsePrefix("fd00:1::/96")},
			{ID: "c20", Credential: "t20", Service: "ns20/svc", Prefix: netip.MustParsePrefix("fd00:1::/96")},
		},
	}
}

// tokenPath is a token file path in configurations under test.
const tokenPath = "token"

func TestConfigValidate(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("identical /96s in different services: %v", err)
	}
	ga := validConfig()
	ga.Services, ga.Connectors = nil, nil
	ga.GrantAuthority = &GrantAuthority{URL: "https://authority", CAFile: "ca", TokenFile: tokenPath}
	if err := ga.Validate(); err != nil {
		t.Fatalf("grant authority configuration: %v", err)
	}
	if _, ok := ga.Authorizer().(*authority.Client); !ok {
		t.Fatalf("Authorizer() = %T with a grant authority, want *authority.Client", ga.Authorizer())
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no authority", func(c *Config) { c.Authority = "" }, required},
		{"service without VPC", func(c *Config) { c.Services[0].VPC = "" }, required},
		{"service without VPC ID", func(c *Config) { c.Services[0].VPCID = "" }, required},
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
		{"grant authority beside static connectors", func(c *Config) {
			c.GrantAuthority = &GrantAuthority{URL: "https://authority", CAFile: "ca", TokenFile: tokenPath}
		}, "come from the grant authority"},
		{"grant authority over plain HTTP", func(c *Config) {
			c.Services, c.Connectors = nil, nil
			c.GrantAuthority = &GrantAuthority{URL: "http://authority", CAFile: "ca", TokenFile: tokenPath}
		}, "https://"},
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

func TestAuthorize(t *testing.T) {
	c := validConfig()
	g, err := c.Authorize(context.Background(), "t20", "20")
	if err != nil {
		t.Fatal(err)
	}
	if g.Connector != "c20" || g.VPC != "20" || g.VPCUID != "v20" || g.VPCID != "000000v20" ||
		g.Service != (masque.ServiceRef{Namespace: "ns20", Name: svcName, UID: "s20"}) ||
		g.Prefix != netip.MustParsePrefix("fd00:1::/96") || !g.NotAfter.After(time.Now()) {
		t.Fatalf("grant %+v does not match connector c20", g)
	}
	if _, err := c.Authorize(context.Background(), "nope", "10"); !errors.Is(err, connectip.ErrUnauthenticated) {
		t.Fatalf("unknown credential: %v", err)
	}
	if _, err := c.Authorize(context.Background(), "t10", "20"); !errors.Is(err, connectip.ErrForbidden) {
		t.Fatalf("credential for another VPC: %v", err)
	}
}
