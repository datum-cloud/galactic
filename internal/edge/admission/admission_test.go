// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package admission

import (
	"net/netip"
	"testing"
)

const (
	packetAccess = "PacketAccess"
	connectIP    = "connect-ip"
	contractV1   = "v1alpha1"
	unapproved   = "unapproved"
	prodVPC      = "prod"
)

var packetV1 = Capability{Name: packetAccess, Version: "v1"}

func registry() map[string]Provider {
	return map[string]Provider{
		connectIP: {
			Name: connectIP, Approved: true, ContractVersions: []string{contractV1},
			Capabilities: []Capability{packetV1},
			ConfigGroup:  "connect.galactic.datumapis.com", ConfigKind: "ConnectIPConfig",
		},
		unapproved: {
			Name: unapproved, ContractVersions: []string{contractV1}, Capabilities: []Capability{packetV1},
			ConfigGroup: "x.example.com", ConfigKind: "XConfig",
		},
	}
}

var grants = []Grant{{
	VPC: prodVPC, Capabilities: []string{packetAccess},
	Prefixes: []netip.Prefix{netip.MustParsePrefix("fd00:5::/48")},
}}

func request() Request {
	return Request{
		Provider: connectIP, ContractVersion: contractV1, Capabilities: []Capability{packetV1},
		VPC: prodVPC, Prefixes: []netip.Prefix{netip.MustParsePrefix("fd00:5:0:1::/64")},
		ConfigGroup: "connect.galactic.datumapis.com", ConfigKind: "ConnectIPConfig",
	}
}

func TestAdmit(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
		want   Reason
	}{
		{"Admitted", func(*Request) {}, ""},
		{"UnknownProvider", func(r *Request) { r.Provider = "missing" }, UnknownProvider},
		{"UnapprovedProvider", func(r *Request) {
			r.Provider, r.ConfigGroup, r.ConfigKind = unapproved, "x.example.com", "XConfig"
		}, ProviderNotApproved},
		{"UnsupportedContractVersion", func(r *Request) { r.ContractVersion = "v2" }, UnsupportedContractVersion},
		{"UnsupportedCapabilityVersion", func(r *Request) {
			r.Capabilities = []Capability{{Name: packetAccess, Version: "v2"}}
		}, UnsupportedCapability},
		{"CapabilityTheProviderLacks", func(r *Request) {
			r.Capabilities = []Capability{{Name: "RouteExchange", Version: "v1"}}
		}, UnsupportedCapability},
		{"ForeignConfigurationKind", func(r *Request) { r.ConfigKind = "TailnetBinding" }, InvalidConfiguration},
		{"VPCNotGranted", func(r *Request) { r.VPC = "other" }, VPCNotGranted},
		{"PrefixOutsideGrant", func(r *Request) {
			r.Prefixes = []netip.Prefix{netip.MustParsePrefix("fd00:6::/64")}
		}, PrefixNotGranted},
		{"NoCapability", func(r *Request) { r.Capabilities = nil }, InvalidRequest},
		{"DuplicateCapability", func(r *Request) { r.Capabilities = []Capability{packetV1, packetV1} }, InvalidRequest},
		{"PrefixWithHostBits", func(r *Request) {
			r.Prefixes = []netip.Prefix{netip.MustParsePrefix("fd00:5::1/64")}
		}, InvalidRequest},
		{"PrefixWiderThanGrant", func(r *Request) {
			r.Prefixes = []netip.Prefix{netip.MustParsePrefix("fd00::/16")}
		}, PrefixNotGranted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := request()
			tt.mutate(&req)
			d := Admit(registry(), grants, req)
			if d.Admitted != (tt.want == "") || d.Reason != tt.want {
				t.Fatalf("Admit = %+v, want reason %q", d, tt.want)
			}
		})
	}
}

func TestGrantsForOneVPCAddUp(t *testing.T) {
	split := []Grant{
		{VPC: prodVPC, Capabilities: []string{"SocketAccess"}},
		{VPC: prodVPC, Capabilities: []string{packetAccess}},
		{VPC: prodVPC, Prefixes: []netip.Prefix{netip.MustParsePrefix("fd00:5::/48")}},
	}
	if d := Admit(registry(), split, request()); !d.Admitted {
		t.Fatalf("Admit with split grants = %+v, want admitted", d)
	}
}

func TestRegistryKeyMustMatchProviderName(t *testing.T) {
	providers := registry()
	p := providers[connectIP]
	p.Name = "other"
	providers[connectIP] = p
	if d := Admit(providers, grants, request()); d.Reason != UnknownProvider {
		t.Fatalf("Admit with a mismatched registry entry = %+v, want UnknownProvider", d)
	}
}

func TestCapabilityNotGranted(t *testing.T) {
	g := []Grant{{VPC: prodVPC, Capabilities: []string{"SocketAccess"}}}
	if d := Admit(registry(), g, request()); d.Reason != CapabilityNotGranted {
		t.Fatalf("Admit = %+v, want CapabilityNotGranted", d)
	}
}

func TestStatusAndClaimAuthority(t *testing.T) {
	core := Writer{Core: true}
	own := Writer{Provider: connectIP}
	other := Writer{Provider: "tailnet"}
	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{"CoreSetsProgrammed", MaySetCondition(core, connectIP, ConditionProgrammed), true},
		{"CoreSetsPublished", MaySetCondition(core, connectIP, ConditionPublished), true},
		{"CoreCannotForgeReadiness", MaySetCondition(core, connectIP, ConditionReady), false},
		{"ProviderSetsOwnReadiness", MaySetCondition(own, connectIP, ConditionReady), true},
		{"ProviderCannotSetProgrammed", MaySetCondition(own, connectIP, ConditionProgrammed), false},
		{"ProviderCannotSetPublished", MaySetCondition(own, connectIP, ConditionPublished), false},
		{"ProviderCannotSpoofAnothersReadiness", MaySetCondition(other, connectIP, ConditionReady), false},
		{"ProviderWritesOwnClaim", MayWriteClaim(own, connectIP), true},
		{"ProviderCannotWriteAnothersClaim", MayWriteClaim(other, connectIP), false},
		{"CoreDoesNotWriteClaims", MayWriteClaim(core, connectIP), false},
		{"AnonymousCannotWriteClaims", MayWriteClaim(Writer{}, ""), false},
		{"AnonymousCannotSetReadinessOnUnboundAttachment", MaySetCondition(Writer{}, "", ConditionReady), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %t, want %t", tt.got, tt.want)
			}
		})
	}
}
