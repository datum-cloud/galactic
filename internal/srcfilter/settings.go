// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfilter

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"go.datum.net/galactic/internal/config"
)

const (
	modeNameOff       = "off"
	modeNameAudit     = "audit"
	modeNameEnforce   = "enforce"
	bindingNameStrict = "strict"
	bindingNameLoose  = "loose"
)

// Mode selects how the datapath acts on a source the filter rejects.
type Mode uint32

const (
	// ModeOff disables the filter.
	ModeOff Mode = iota
	// ModeAudit counts and records rejected sources but still delivers them.
	ModeAudit
	// ModeEnforce drops rejected sources.
	ModeEnforce
)

// String returns the mode's configuration name.
func (m Mode) String() string {
	switch m {
	case ModeOff:
		return modeNameOff
	case ModeAudit:
		return modeNameAudit
	case ModeEnforce:
		return modeNameEnforce
	default:
		return fmt.Sprintf("unknown(%d)", uint32(m))
	}
}

// ParseMode returns the Mode named by s, case-insensitively. Empty means
// ModeOff. Any other unknown name is an error.
func ParseMode(s string) (Mode, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ModeOff, nil
	}
	for _, m := range []Mode{ModeOff, ModeAudit, ModeEnforce} {
		if strings.EqualFold(s, m.String()) {
			return m, nil
		}
	}
	return ModeOff, fmt.Errorf("unknown source filter mode %q (want off, audit or enforce)", s)
}

// Binding selects whether a source is tied to the uplinks its route uses.
type Binding uint32

const (
	// BindingStrict accepts a source only on the uplinks this node's route to
	// it leaves through.
	BindingStrict Binding = iota
	// BindingLoose accepts a known source on any uplink.
	BindingLoose
)

// String returns the binding's configuration name.
func (b Binding) String() string {
	if b == BindingLoose {
		return bindingNameLoose
	}
	return bindingNameStrict
}

// ParseBinding returns the Binding named by s, case-insensitively. Empty means
// BindingStrict. Any other unknown name is an error.
func ParseBinding(s string) (Binding, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", bindingNameStrict:
		return BindingStrict, nil
	case bindingNameLoose:
		return BindingLoose, nil
	default:
		return BindingStrict, fmt.Errorf("unknown source binding %q (want strict or loose)", s)
	}
}

// DefaultMinPrefixLen is the shortest route a pass turns into an allow entry.
// A locator is a /64, so anything shorter is an aggregate that would also allow
// node IDs nobody holds.
const DefaultMinPrefixLen = 64

// Settings is the operator-facing source filter configuration.
type Settings struct {
	Mode           Mode
	DomainPrefixes []netip.Prefix
	Binding        Binding
	ExtraSources   []netip.Prefix
	// FabricNextHops, when set, are the only route gateways that count as a
	// fabric BGP peer. Empty skips the next-hop check.
	FabricNextHops []netip.Prefix
}

// LoadSettings reads Settings from the GALACTIC_CNI_SRV6_* variables through
// getenv. It returns an error for an unknown mode or binding, a malformed
// prefix, or audit or enforce mode with no SR domain prefixes. With mode off
// the other variables are not validated.
func LoadSettings(getenv func(string) string) (Settings, error) {
	mode, err := ParseMode(getenv(config.EnvCNISRv6SourceFilter))
	if err != nil {
		return Settings{}, fmt.Errorf("%s: %w", config.EnvCNISRv6SourceFilter, err)
	}
	if mode == ModeOff {
		return Settings{Mode: ModeOff}, nil
	}

	s := Settings{Mode: mode}
	var errs []error
	if s.Binding, err = ParseBinding(getenv(config.EnvCNISRv6SourceBinding)); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", config.EnvCNISRv6SourceBinding, err))
	}
	if s.DomainPrefixes, err = ParsePrefixList(getenv(config.EnvCNISRv6DomainPrefixes)); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", config.EnvCNISRv6DomainPrefixes, err))
	} else if len(s.DomainPrefixes) == 0 {
		errs = append(errs, fmt.Errorf("%s is required when %s is %s",
			config.EnvCNISRv6DomainPrefixes, config.EnvCNISRv6SourceFilter, mode))
	}
	if s.ExtraSources, err = ParsePrefixList(getenv(config.EnvCNISRv6SourceAllowExtra)); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", config.EnvCNISRv6SourceAllowExtra, err))
	}
	if s.FabricNextHops, err = ParsePrefixList(getenv(config.EnvCNISRv6FabricNextHops)); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", config.EnvCNISRv6FabricNextHops, err))
	}
	if len(errs) > 0 {
		return Settings{}, errors.Join(errs...)
	}
	return s, nil
}

// ParsePrefixList splits a comma-separated list of IPv6 prefixes, trimming
// whitespace and skipping blank entries, and returns each masked. An entry
// that is not an IPv6 prefix is an error.
func ParsePrefixList(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("parse prefix %q: %w", part, err)
		}
		if !p.Addr().Is6() || p.Addr().Is4In6() {
			return nil, fmt.Errorf("prefix %q is not IPv6", part)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
