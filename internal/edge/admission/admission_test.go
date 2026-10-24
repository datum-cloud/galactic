// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package admission

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
)

const (
	packetAccess = "PacketAccess"
	connectIP    = "connect-ip"
	contractV1   = "v1alpha1"
	unapproved   = "unapproved"
	prodVPC      = "vpc-uid-prod"
	grantUID     = "grant-uid-1"
	providerNS   = "edge-connect-ip"
	providerSA   = "connect-ip"
	podA         = "pod-uid-a"
	podB         = "pod-uid-b"
	maxSkew      = 2 * time.Second
	configGroup  = "connect.galactic.datumapis.com"
	configKind   = "ConnectIPConfig"
	socketAccess = "SocketAccess"
	otherName    = "other"
	// routeExchange is a capability the provider declares but core does
	// not implement.
	routeExchange = "RouteExchange"
)

var (
	packetV1 = Capability{Name: packetAccess, Version: "v1"}
	epoch    = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	callerA  = Identity{ServiceAccount: ServiceAccount{Namespace: providerNS, Name: providerSA}, PodUID: podA}
)

func registry() map[string]Provider {
	return map[string]Provider{
		connectIP: {
			Name: connectIP, Approved: true, ContractVersions: []string{contractV1},
			Capabilities:    []Capability{packetV1, {Name: routeExchange, Version: "v1"}},
			ServiceAccounts: []ServiceAccount{callerA.ServiceAccount},
			ConfigGroup:     configGroup, ConfigKind: configKind,
		},
		unapproved: {
			Name: unapproved, ContractVersions: []string{contractV1}, Capabilities: []Capability{packetV1},
			ServiceAccounts: []ServiceAccount{callerA.ServiceAccount},
			ConfigGroup:     "x.example.com", ConfigKind: "XConfig",
		},
	}
}

func grant() Grant {
	return Grant{
		UID: grantUID, Generation: 3, Provider: connectIP, VPC: prodVPC,
		Capabilities: []string{packetAccess},
		Prefixes:     []netip.Prefix{netip.MustParsePrefix("fd00:5::/48")},
		ValidUntil:   epoch.Add(time.Hour),
	}
}

func grants(gs ...Grant) map[string]Grant {
	m := map[string]Grant{}
	for _, g := range gs {
		m[g.UID] = g
	}
	return m
}

func request() Request {
	return Request{
		Identity: callerA, PodUID: podA,
		Provider: connectIP, ContractVersion: contractV1, Capabilities: []Capability{packetV1},
		Grant: GrantRef{UID: grantUID, Generation: 3},
		VPC:   prodVPC, Prefixes: []netip.Prefix{netip.MustParsePrefix("fd00:5:0:1::/64")},
		ConfigGroup: configGroup, ConfigKind: configKind,
	}
}

func TestAdmit(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request, *Grant)
		now    time.Time
		want   Reason
	}{
		{"Admitted", func(*Request, *Grant) {}, epoch, ""},
		{"NoIdentity", func(r *Request, _ *Grant) { r.Identity = Identity{} }, epoch, Unauthenticated},
		{"IdentityWithoutPod", func(r *Request, _ *Grant) { r.Identity.PodUID = "" }, epoch, Unauthenticated},
		{"AssertsAnotherPod", func(r *Request, _ *Grant) { r.PodUID = podB }, epoch, IdentityMismatch},
		{"NoAssertedPod", func(r *Request, _ *Grant) { r.PodUID = "" }, epoch, ""},
		{"ServiceAccountNotTheProviders", func(r *Request, _ *Grant) {
			r.Identity.ServiceAccount.Name = otherName
		}, epoch, IdentityNotAuthorized},
		{"ServiceAccountInAnotherNamespace", func(r *Request, _ *Grant) {
			r.Identity.ServiceAccount.Namespace = "tenant"
		}, epoch, IdentityNotAuthorized},
		{"UnknownProvider", func(r *Request, _ *Grant) { r.Provider = "missing" }, epoch, UnknownProvider},
		{"UnapprovedProvider", func(r *Request, _ *Grant) {
			r.Provider, r.ConfigGroup, r.ConfigKind = unapproved, "x.example.com", "XConfig"
		}, epoch, ProviderNotApproved},
		{"UnsupportedContractVersion", func(r *Request, _ *Grant) {
			r.ContractVersion = "v2"
		}, epoch, UnsupportedContractVersion},
		{"UnsupportedCapabilityVersion", func(r *Request, _ *Grant) {
			r.Capabilities = []Capability{{Name: packetAccess, Version: "v2"}}
		}, epoch, UnsupportedCapability},
		{"CapabilityTheProviderLacks", func(r *Request, g *Grant) {
			r.Capabilities = []Capability{{Name: socketAccess, Version: "v1"}}
			g.Capabilities = append(g.Capabilities, socketAccess)
		}, epoch, UnsupportedCapability},
		{"CapabilityCoreLacks", func(r *Request, g *Grant) {
			r.Capabilities = []Capability{{Name: routeExchange, Version: "v1"}}
			g.Capabilities = append(g.Capabilities, routeExchange)
		}, epoch, UnsupportedCapability},
		{"ForeignConfigurationKind", func(r *Request, _ *Grant) {
			r.ConfigKind = "TailnetBinding"
		}, epoch, InvalidConfiguration},
		{"NoGrantNamed", func(r *Request, _ *Grant) { r.Grant = GrantRef{} }, epoch, InvalidRequest},
		{"UnknownGrant", func(r *Request, _ *Grant) { r.Grant.UID = "missing" }, epoch, GrantRevoked},
		{"GrantBeingDeleted", func(_ *Request, g *Grant) { g.Revoked = true }, epoch, GrantRevoked},
		{"StaleGrantReplayed", func(_ *Request, g *Grant) { g.Generation = 4 }, epoch, StaleGrant},
		{"GrantAheadOfCache", func(r *Request, _ *Grant) { r.Grant.Generation = 4 }, epoch, StaleGrant},
		{"GrantExpired", func(*Request, *Grant) {}, epoch.Add(2 * time.Hour), GrantExpired},
		{"GrantInsideSkew", func(*Request, *Grant) {}, epoch.Add(time.Hour - maxSkew), GrantExpired},
		{"GrantJustOutsideSkew", func(*Request, *Grant) {}, epoch.Add(time.Hour - maxSkew - time.Nanosecond), ""},
		{"GrantWithoutExpiry", func(_ *Request, g *Grant) { g.ValidUntil = time.Time{} }, epoch.Add(1000 * time.Hour), ""},
		{"GrantForAnotherProvider", func(_ *Request, g *Grant) { g.Provider = "tailnet" }, epoch, ProviderNotGranted},
		{"VPCNotGranted", func(r *Request, _ *Grant) { r.VPC = otherName }, epoch, VPCNotGranted},
		{"CapabilityNotGranted", func(_ *Request, g *Grant) {
			g.Capabilities = []string{socketAccess}
		}, epoch, CapabilityNotGranted},
		{"PrefixOutsideGrant", func(r *Request, _ *Grant) {
			r.Prefixes = []netip.Prefix{netip.MustParsePrefix("fd00:6::/64")}
		}, epoch, PrefixNotGranted},
		{"PrefixWiderThanGrant", func(r *Request, _ *Grant) {
			r.Prefixes = []netip.Prefix{netip.MustParsePrefix("fd00::/16")}
		}, epoch, PrefixNotGranted},
		{"NoCapability", func(r *Request, _ *Grant) { r.Capabilities = nil }, epoch, InvalidRequest},
		{"DuplicateCapability", func(r *Request, _ *Grant) {
			r.Capabilities = []Capability{packetV1, packetV1}
		}, epoch, InvalidRequest},
		{"PrefixWithHostBits", func(r *Request, _ *Grant) {
			r.Prefixes = []netip.Prefix{netip.MustParsePrefix("fd00:5::1/64")}
		}, epoch, InvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, g := request(), grant()
			tt.mutate(&req, &g)
			d := Admit(registry(), grants(g), req, tt.now, maxSkew)
			if d.Admitted != (tt.want == "") || d.Reason != tt.want || (d.Authorization != nil) != d.Admitted {
				t.Fatalf("Admit = %+v, want reason %q", d, tt.want)
			}
		})
	}
}

func TestAdmitContractVersions(t *testing.T) {
	// A version the provider declares is still refused unless core
	// implements it, and every version core implements is admitted.
	providers := registry()
	p := providers[connectIP]
	p.ContractVersions = append(slices.Clone(supportedContractVersions), "v1alpha9")
	providers[connectIP] = p
	for _, v := range p.ContractVersions {
		req := request()
		req.ContractVersion = v
		d := Admit(providers, grants(grant()), req, epoch, maxSkew)
		if want := slices.Contains(supportedContractVersions, v); d.Admitted != want {
			t.Errorf("Admit(%q) = %+v, want admitted %v", v, d, want)
		}
		if !d.Admitted && d.Reason != UnsupportedContractVersion {
			t.Errorf("Admit(%q) reason = %q, want UnsupportedContractVersion", v, d.Reason)
		}
	}
}

func TestAdmitCapabilityVersions(t *testing.T) {
	// A capability version the provider declares is still refused unless
	// core implements it, and every version the provider contract lists as
	// implemented is admitted. The list is spelled out rather than read from
	// supportedCapabilities so that dropping a version from it fails here.
	implemented := []Capability{
		{Name: socketAccess, Version: "v1"},
		{Name: packetAccess, Version: "v1"},
		{Name: "PrefixReachability", Version: "v1"},
	}
	providers := registry()
	p := providers[connectIP]
	p.Capabilities = append(slices.Clone(implemented), Capability{Name: packetAccess, Version: "v9"})
	providers[connectIP] = p
	g := grant()
	g.Capabilities = nil
	for _, c := range p.Capabilities {
		if !slices.Contains(g.Capabilities, c.Name) {
			g.Capabilities = append(g.Capabilities, c.Name)
		}
	}
	for _, c := range p.Capabilities {
		req := request()
		req.Capabilities = []Capability{c}
		d := Admit(providers, grants(g), req, epoch, maxSkew)
		if want := slices.Contains(implemented, c); d.Admitted != want {
			t.Errorf("Admit(%v) = %+v, want admitted %v", c, d, want)
		}
		if !d.Admitted && d.Reason != UnsupportedCapability {
			t.Errorf("Admit(%v) reason = %q, want UnsupportedCapability", c, d.Reason)
		}
	}
}

func TestGrantNamedByAnotherGrantsUID(t *testing.T) {
	// A request cannot borrow another tenant's grant by naming it: the
	// grant's own provider, VPC and prefixes still bound it.
	other := grant()
	other.UID, other.VPC = "grant-uid-2", "vpc-uid-other"
	req := request()
	req.Grant.UID = other.UID
	if d := Admit(registry(), grants(grant(), other), req, epoch, maxSkew); d.Reason != VPCNotGranted {
		t.Fatalf("Admit = %+v, want VPCNotGranted", d)
	}
}

func TestRegistryKeyMustMatchProviderName(t *testing.T) {
	providers := registry()
	p := providers[connectIP]
	p.Name = otherName
	providers[connectIP] = p
	if d := Admit(providers, grants(grant()), request(), epoch, maxSkew); d.Reason != UnknownProvider {
		t.Fatalf("Admit with a mismatched registry entry = %+v, want UnknownProvider", d)
	}
}

func TestGrantMapKeyMustMatchUID(t *testing.T) {
	g := grant()
	g.UID = "forged"
	if d := Admit(registry(), map[string]Grant{grantUID: g}, request(), epoch, maxSkew); d.Reason != GrantRevoked {
		t.Fatalf("Admit with a mismatched grant entry = %+v, want GrantRevoked", d)
	}
}

func TestAuthorizationIsImmutable(t *testing.T) {
	req := request()
	d := Admit(registry(), grants(grant()), req, epoch, maxSkew)
	if !d.Admitted {
		t.Fatalf("Admit = %+v", d)
	}
	z := d.Authorization
	req.Prefixes[0] = netip.MustParsePrefix("fd00:6::/64")
	req.Capabilities[0].Name = socketAccess
	z.Prefixes()[0] = netip.MustParsePrefix("fd00:7::/64")
	z.Capabilities()[0].Name = socketAccess
	if got := z.Prefixes()[0]; got != netip.MustParsePrefix("fd00:5:0:1::/64") {
		t.Fatalf("Prefixes changed to %s", got)
	}
	if got := z.Capabilities()[0]; got != packetV1 {
		t.Fatalf("Capabilities changed to %+v", got)
	}
	if z.Identity() != callerA || z.Provider() != connectIP || z.VPC() != prodVPC ||
		z.Grant() != (GrantRef{UID: grantUID, Generation: 3}) {
		t.Fatalf("Authorization = %+v", z.req)
	}
	if want := epoch.Add(time.Hour); !z.Ceiling().Equal(want) {
		t.Fatalf("Ceiling = %s, want %s", z.Ceiling(), want)
	}
	if want := epoch.Add(time.Hour - maxSkew); !z.NotAfter().Equal(want) {
		t.Fatalf("NotAfter = %s, want %s", z.NotAfter(), want)
	}
}

func TestIdentityFromUserInfo(t *testing.T) {
	bound := authenticationv1.UserInfo{
		Username: "system:serviceaccount:" + providerNS + ":" + providerSA,
		Extra:    map[string]authenticationv1.ExtraValue{PodUIDExtra: {podA}},
	}
	id, err := IdentityFromUserInfo(bound)
	if err != nil || id != callerA {
		t.Fatalf("IdentityFromUserInfo = %+v, %v; want %+v", id, err, callerA)
	}
	tests := []struct {
		name string
		u    authenticationv1.UserInfo
	}{
		{"User", authenticationv1.UserInfo{Username: "alice@example.com",
			Extra: map[string]authenticationv1.ExtraValue{PodUIDExtra: {podA}}}},
		{"Node", authenticationv1.UserInfo{Username: "system:node:worker-1",
			Extra: map[string]authenticationv1.ExtraValue{PodUIDExtra: {podA}}}},
		{"UnboundToken", authenticationv1.UserInfo{Username: bound.Username}},
		{"EmptyPodUID", authenticationv1.UserInfo{Username: bound.Username,
			Extra: map[string]authenticationv1.ExtraValue{PodUIDExtra: {""}}}},
		{"TwoPodUIDs", authenticationv1.UserInfo{Username: bound.Username,
			Extra: map[string]authenticationv1.ExtraValue{PodUIDExtra: {podA, podB}}}},
		{"NoName", authenticationv1.UserInfo{Username: "system:serviceaccount:" + providerNS + ":",
			Extra: bound.Extra}},
		{"NoNamespace", authenticationv1.UserInfo{Username: "system:serviceaccount::" + providerSA,
			Extra: bound.Extra}},
		{"ExtraSegment", authenticationv1.UserInfo{Username: bound.Username + ":x", Extra: bound.Extra}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if id, err := IdentityFromUserInfo(tt.u); err == nil {
				t.Fatalf("IdentityFromUserInfo = %+v, want an error", id)
			}
		})
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
