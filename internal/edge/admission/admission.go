// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package admission decides whether a provider's request for a gateway
// service binding may be admitted, what it is then authorized to do and for
// how long, and which writer may set which part of its status.
//
// A provider's registration describes what it can do and which
// ServiceAccounts act for it: the contract versions and capability versions it
// implements and the kind of configuration it owns. It grants no tenant
// authority. Admission authenticates the caller from its bound token,
// intersects the registration with the operator's approval and the one tenant
// grant the request names, and fails before any host resource is allocated,
// with a reason a caller can put in a condition. A successful decision carries
// an Authorization, the immutable record of what was admitted, until when, and
// a signal that closes when it is revoked.
package admission

import (
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// Reason names why a request was refused or an authorization revoked. The
// values are condition reasons.
type Reason string

// Refusal and revocation reasons.
const (
	Unauthenticated            Reason = "Unauthenticated"
	IdentityMismatch           Reason = "IdentityMismatch"
	IdentityNotAuthorized      Reason = "IdentityNotAuthorized"
	UnknownProvider            Reason = "UnknownProvider"
	ProviderNotApproved        Reason = "ProviderNotApproved"
	UnsupportedContractVersion Reason = "UnsupportedContractVersion"
	UnsupportedCapability      Reason = "UnsupportedCapability"
	GrantRevoked               Reason = "GrantRevoked"
	StaleGrant                 Reason = "StaleGrant"
	GrantExpired               Reason = "GrantExpired"
	ProviderNotGranted         Reason = "ProviderNotGranted"
	CapabilityNotGranted       Reason = "CapabilityNotGranted"
	VPCNotGranted              Reason = "VPCNotGranted"
	PrefixNotGranted           Reason = "PrefixNotGranted"
	PrefixConflict             Reason = "PrefixConflict"
	InvalidConfiguration       Reason = "InvalidConfiguration"
	InvalidRequest             Reason = "InvalidRequest"
)

// supportedContractVersions are the provider contract versions this core
// implements: the current version and, once there is one, the version before
// it. Admission refuses any other version, whatever a provider declares.
var supportedContractVersions = []string{"v1alpha1"}

// supportedCapabilities are the capability versions this core implements.
// Admission refuses any other version, whatever a provider declares.
var supportedCapabilities = []Capability{
	{Name: "SocketAccess", Version: "v1"},
	{Name: "PacketAccess", Version: "v1"},
	{Name: "PrefixReachability", Version: "v1"},
}

// Capability is a typed capability at a version, such as PacketAccess v1.
type Capability struct {
	Name    string
	Version string
}

// ServiceAccount names one Kubernetes ServiceAccount.
type ServiceAccount struct {
	Namespace, Name string
}

// Provider is a registered gateway provider.
type Provider struct {
	Name string
	// Approved is set by the operator's approval, never by the provider.
	Approved bool
	// ContractVersions are the provider API versions the provider speaks.
	ContractVersions []string
	// Capabilities are the capability versions the provider implements.
	Capabilities []Capability
	// ServiceAccounts are the only identities that act for the provider.
	ServiceAccounts []ServiceAccount
	// ConfigGroup and ConfigKind name the provider-owned configuration
	// resource its services reference.
	ConfigGroup, ConfigKind string
}

// Grant is a tenant's authorization for one provider in one VPC, from one
// generation of one EdgeService.
type Grant struct {
	// UID and Generation identify the grant object and the version of it
	// this value was read from.
	UID        string
	Generation int64
	Provider   string
	// VPC is the granted VPC's UID.
	VPC          string
	Capabilities []string
	// Prefixes bound the site and client prefixes services may route.
	Prefixes []netip.Prefix
	// ValidUntil, when non-zero, is the wall-clock instant after which the
	// grant authorizes nothing.
	ValidUntil time.Time
	// Revoked is set once the grant is being deleted.
	Revoked bool
}

// GrantRef names the grant a request relies on, at the generation the
// requester read.
type GrantRef struct {
	UID        string
	Generation int64
}

// Request is a gateway service binding to admit.
type Request struct {
	// Identity is the authenticated caller, from IdentityFromUserInfo. It is
	// never taken from the object being written.
	Identity Identity
	// PodUID is the pod UID the written object asserts, if any. It must
	// match Identity.
	PodUID          string
	Provider        string
	ContractVersion string
	Capabilities    []Capability
	Grant           GrantRef
	// VPC is the VPC UID the request is for.
	VPC         string
	Prefixes    []netip.Prefix
	ConfigGroup string
	ConfigKind  string
}

// Decision is the outcome of Admit. Authorization is set exactly when
// Admitted is.
type Decision struct {
	Admitted      bool
	Reason        Reason
	Message       string
	Authorization *Authorization
}

func refuse(r Reason, format string, args ...any) Decision {
	return Decision{Reason: r, Message: fmt.Sprintf(format, args...)}
}

// Admit decides req at the wall-clock instant now against the registered
// providers and the grants, keyed by UID. Every check must pass; the first
// that fails names the reason. A grant expires maxSkew before its ValidUntil,
// so no node whose clock is within maxSkew still treats it as valid.
//
// The returned Authorization is not tracked: nothing closes its Done channel.
// Use Authority to have revocations and expiry delivered.
func Admit(providers map[string]Provider, grants map[string]Grant, req Request,
	now time.Time, maxSkew time.Duration) Decision {
	if d, ok := validate(req); !ok {
		return d
	}
	p, ok := providers[req.Provider]
	switch {
	case !ok || p.Name != req.Provider:
		return refuse(UnknownProvider, "provider %q is not registered", req.Provider)
	case !p.Approved:
		return refuse(ProviderNotApproved, "provider %q is not approved", req.Provider)
	case !slices.Contains(p.ServiceAccounts, req.Identity.ServiceAccount):
		return refuse(IdentityNotAuthorized, "%s does not act for provider %q",
			req.Identity.ServiceAccount, req.Provider)
	case !slices.Contains(supportedContractVersions, req.ContractVersion):
		return refuse(UnsupportedContractVersion, "core supports contract versions %v, not %q",
			supportedContractVersions, req.ContractVersion)
	case !slices.Contains(p.ContractVersions, req.ContractVersion):
		return refuse(UnsupportedContractVersion, "provider %q supports contract versions %v, not %q",
			req.Provider, p.ContractVersions, req.ContractVersion)
	case req.ConfigGroup != p.ConfigGroup || req.ConfigKind != p.ConfigKind:
		return refuse(InvalidConfiguration, "provider %q takes %s %s configuration, not %s %s",
			req.Provider, p.ConfigGroup, p.ConfigKind, req.ConfigGroup, req.ConfigKind)
	}
	for _, c := range req.Capabilities {
		if !slices.Contains(supportedCapabilities, c) {
			return refuse(UnsupportedCapability, "core does not implement %s %s", c.Name, c.Version)
		}
		if !slices.Contains(p.Capabilities, c) {
			return refuse(UnsupportedCapability, "provider %q does not implement %s %s", req.Provider, c.Name, c.Version)
		}
	}
	g, ok := grants[req.Grant.UID]
	if d, ok := checkGrant(g, ok, req, now, maxSkew); !ok {
		return d
	}
	return Decision{Admitted: true, Authorization: newAuthorization(req, g, maxSkew)}
}

// checkGrant refuses a request whose grant is gone, revoked, read at another
// generation, expired, or does not cover the provider, VPC, capabilities and
// prefixes requested.
func checkGrant(g Grant, found bool, req Request, now time.Time, maxSkew time.Duration) (Decision, bool) {
	switch {
	case !found || g.UID != req.Grant.UID || g.Revoked:
		return refuse(GrantRevoked, "grant %s no longer exists", req.Grant.UID), false
	case g.Generation != req.Grant.Generation:
		return refuse(StaleGrant, "grant %s is at generation %d, not %d",
			g.UID, g.Generation, req.Grant.Generation), false
	case !g.ValidUntil.IsZero() && !now.Before(g.ValidUntil.Add(-maxSkew)):
		return refuse(GrantExpired, "grant %s expired at %s", g.UID, g.ValidUntil.UTC().Format(time.RFC3339)), false
	case g.Provider != req.Provider:
		return refuse(ProviderNotGranted, "grant %s does not authorize provider %q", g.UID, req.Provider), false
	case g.VPC != req.VPC:
		return refuse(VPCNotGranted, "grant %s does not authorize VPC %q", g.UID, req.VPC), false
	}
	for _, c := range req.Capabilities {
		if !slices.Contains(g.Capabilities, c.Name) {
			return refuse(CapabilityNotGranted, "grant %s does not authorize %s", g.UID, c.Name), false
		}
	}
	for _, p := range req.Prefixes {
		if !covered(g.Prefixes, p) {
			return refuse(PrefixNotGranted, "prefix %s is outside grant %s", p, g.UID), false
		}
	}
	return Decision{}, true
}

// validate rejects a request without an authenticated identity, one whose
// asserted pod UID is not the caller's, one that names no grant or
// capability or names a capability twice, or one carrying a prefix that is
// invalid or has host bits set.
func validate(req Request) (Decision, bool) {
	if err := req.Identity.validate(); err != nil {
		return refuse(Unauthenticated, "%v", err), false
	}
	if req.PodUID != "" && req.PodUID != req.Identity.PodUID {
		return refuse(IdentityMismatch, "object names pod %s, but the caller is pod %s",
			req.PodUID, req.Identity.PodUID), false
	}
	if req.Grant.UID == "" {
		return refuse(InvalidRequest, "no grant named"), false
	}
	if len(req.Capabilities) == 0 {
		return refuse(InvalidRequest, "no capability requested"), false
	}
	seen := map[string]bool{}
	for _, c := range req.Capabilities {
		if seen[c.Name] {
			return refuse(InvalidRequest, "capability %s requested twice", c.Name), false
		}
		seen[c.Name] = true
	}
	for _, p := range req.Prefixes {
		if !p.IsValid() || p != p.Masked() {
			return refuse(InvalidRequest, "prefix %s is not a valid, masked prefix", p), false
		}
	}
	return Decision{}, true
}

func covered(grants []netip.Prefix, p netip.Prefix) bool {
	for _, g := range grants {
		if g.Bits() <= p.Bits() && g.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Writer identifies who is writing an attachment's status.
type Writer struct {
	// Core is set for galactic's own controllers and node authority.
	Core bool
	// Provider is the provider name a provider's identity resolves to.
	Provider string
}

// Condition types on an attachment. The core writes admission, allocation and
// programming; the provider writes only its own readiness; only the core
// combines them into publication.
const (
	ConditionAdmitted   = "Admitted"
	ConditionAllocated  = "Allocated"
	ConditionProgrammed = "Programmed"
	ConditionReady      = "Ready"
	ConditionPublished  = "Published"
)

// MaySetCondition reports whether w may set condition cond on an attachment
// bound to provider.
func MaySetCondition(w Writer, provider, cond string) bool {
	if w.Core {
		return cond != ConditionReady
	}
	return cond == ConditionReady && w.Provider != "" && w.Provider == provider
}

// MayWriteClaim reports whether w may write a claim or route candidate for an
// attachment bound to provider. The core never writes them on a provider's
// behalf, and a provider writes only its own.
func MayWriteClaim(w Writer, provider string) bool {
	return !w.Core && w.Provider != "" && w.Provider == provider
}
