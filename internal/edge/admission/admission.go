// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package admission decides whether a gateway service binding may be admitted
// and which writer may set which part of its status.
//
// A provider's registration describes what it can do: the contract versions
// and capability versions it implements and the kind of configuration it
// owns. It grants no tenant authority. Admission intersects that
// registration with the operator's approval and the tenant's grants, and
// fails before any host resource is allocated, with a reason a caller can
// put in a condition.
package admission

import (
	"fmt"
	"net/netip"
	"slices"
)

// Reason names why a request was refused. The values are condition reasons.
type Reason string

// Refusal reasons.
const (
	UnknownProvider            Reason = "UnknownProvider"
	ProviderNotApproved        Reason = "ProviderNotApproved"
	UnsupportedContractVersion Reason = "UnsupportedContractVersion"
	UnsupportedCapability      Reason = "UnsupportedCapability"
	CapabilityNotGranted       Reason = "CapabilityNotGranted"
	VPCNotGranted              Reason = "VPCNotGranted"
	PrefixNotGranted           Reason = "PrefixNotGranted"
	InvalidConfiguration       Reason = "InvalidConfiguration"
	InvalidRequest             Reason = "InvalidRequest"
)

// Capability is a typed capability at a version, such as PacketAccess v1.
type Capability struct {
	Name    string
	Version string
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
	// ConfigGroup and ConfigKind name the provider-owned configuration
	// resource its services reference.
	ConfigGroup, ConfigKind string
}

// Grant is what a tenant may use in one VPC.
type Grant struct {
	VPC          string
	Capabilities []string
	// Prefixes bound the site and client prefixes services may route.
	Prefixes []netip.Prefix
}

// Request is a gateway service binding to admit.
type Request struct {
	Provider        string
	ContractVersion string
	Capabilities    []Capability
	VPC             string
	Prefixes        []netip.Prefix
	ConfigGroup     string
	ConfigKind      string
}

// Decision is the outcome of Admit.
type Decision struct {
	Admitted bool
	Reason   Reason
	Message  string
}

func refuse(r Reason, format string, args ...any) Decision {
	return Decision{Reason: r, Message: fmt.Sprintf(format, args...)}
}

// Admit decides req against the registered providers and the tenant's
// grants. Every check must pass; the first that fails names the reason. A
// tenant may hold several grants for one VPC; they add up.
func Admit(providers map[string]Provider, grants []Grant, req Request) Decision {
	if d, ok := validate(req); !ok {
		return d
	}
	p, ok := providers[req.Provider]
	switch {
	case !ok || p.Name != req.Provider:
		return refuse(UnknownProvider, "provider %q is not registered", req.Provider)
	case !p.Approved:
		return refuse(ProviderNotApproved, "provider %q is not approved", req.Provider)
	case !slices.Contains(p.ContractVersions, req.ContractVersion):
		return refuse(UnsupportedContractVersion, "provider %q supports contract versions %v, not %q",
			req.Provider, p.ContractVersions, req.ContractVersion)
	case req.ConfigGroup != p.ConfigGroup || req.ConfigKind != p.ConfigKind:
		return refuse(InvalidConfiguration, "provider %q takes %s %s configuration, not %s %s",
			req.Provider, p.ConfigGroup, p.ConfigKind, req.ConfigGroup, req.ConfigKind)
	}
	for _, c := range req.Capabilities {
		if !slices.Contains(p.Capabilities, c) {
			return refuse(UnsupportedCapability, "provider %q does not implement %s %s", req.Provider, c.Name, c.Version)
		}
	}
	var capabilities []string
	var prefixes []netip.Prefix
	for _, g := range grants {
		if g.VPC == req.VPC {
			capabilities = append(capabilities, g.Capabilities...)
			prefixes = append(prefixes, g.Prefixes...)
		}
	}
	if capabilities == nil && prefixes == nil {
		return refuse(VPCNotGranted, "no grant for VPC %q", req.VPC)
	}
	for _, c := range req.Capabilities {
		if !slices.Contains(capabilities, c.Name) {
			return refuse(CapabilityNotGranted, "VPC %q does not grant %s", req.VPC, c.Name)
		}
	}
	for _, p := range req.Prefixes {
		if !covered(prefixes, p) {
			return refuse(PrefixNotGranted, "prefix %s is outside VPC %q's grants", p, req.VPC)
		}
	}
	return Decision{Admitted: true}
}

// validate rejects a request that names no capability, names one twice, or
// carries a prefix that is invalid or has host bits set.
func validate(req Request) (Decision, bool) {
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
