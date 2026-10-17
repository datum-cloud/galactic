// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// Result is a compiled router configuration.
type Result struct {
	// Config is the complete frr.conf text.
	Config string
	// Digest is the hex SHA-256 of Config.
	Digest string
}

// Compile resolves in and renders the router's FRR configuration. It returns
// a RefusalError, and no Result, when anything the router depends on is missing,
// unsupported or contradictory: a partial configuration is never produced.
func Compile(in Input) (Result, error) {
	c := newCompiler(in)
	c.validate()
	if len(c.problems.list) > 0 {
		return Result{}, c.problems.sorted()
	}
	config := c.render()
	sum := sha256.Sum256([]byte(config))
	return Result{Config: config, Digest: hex.EncodeToString(sum[:])}, nil
}

// compiler holds one compile's resolved state.
type compiler struct {
	in       Input
	problems problems

	// Objects rendered, by metadata.name.
	profiles      map[string]*networkv1alpha1.BGPPeerProfile
	policies      map[string]*networkv1alpha1.BGPPolicy
	prefixLists   map[string]*networkv1alpha1.BGPPrefixList
	communitySets map[string]*networkv1alpha1.BGPCommunitySet

	// families is the router's address families, as afi/safi.
	families map[family]bool

	// peerAddresses maps each peer address to the peer that claimed it.
	peerAddresses map[netip.Addr]string

	// memberProfiles is the profiles at least one peer references.
	memberProfiles map[string]bool
}

type family struct {
	afi  networkv1alpha1.AFI
	safi networkv1alpha1.SAFI
}

func newCompiler(in Input) *compiler {
	return &compiler{
		in:             in,
		profiles:       map[string]*networkv1alpha1.BGPPeerProfile{},
		policies:       map[string]*networkv1alpha1.BGPPolicy{},
		prefixLists:    map[string]*networkv1alpha1.BGPPrefixList{},
		communitySets:  map[string]*networkv1alpha1.BGPCommunitySet{},
		families:       map[family]bool{},
		peerAddresses:  map[netip.Addr]string{},
		memberProfiles: map[string]bool{},
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func objectName(kind, name string) string { return kind + "/" + name }
