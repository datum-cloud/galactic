// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hash provides deterministic hashing of DesiredRouter values.
package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"go.datum.net/galactic/internal/model"
)

// sortableRouter is a copy of DesiredRouter with all slices sorted for
// deterministic serialization.
type sortableRouter struct {
	Namespace       string
	Name            string
	LocalASN        uint32
	RouterID        string
	AddressFamilies []model.AddressFamily
	Peers           []sortablePeer
	Advertisements  []sortableAdvertisement
	Policies        []sortablePolicy
}

type sortablePeer struct {
	Name            string
	PeerASN         uint32
	Address         string
	AddressFamilies []model.AddressFamily
	HoldTime        int64
	KeepaliveTime   int64
	AuthPassword    string
}

type sortableAdvertisement struct {
	Name            string
	AddressFamily   model.AddressFamily
	Prefixes        []string
	Communities     []string
	LocalPreference *uint32
	NextHop         string
}

type sortablePolicy struct {
	Name      string
	Direction model.BGPPolicyDirection
	Terms     []sortablePolicyTerm
}

type sortablePolicyTerm struct {
	Sequence int32
	Match    sortablePolicyMatch
	Action   model.BGPPolicyAction
	Set      *model.DesiredPolicySetActions
}

type sortablePolicyMatch struct {
	Any             bool
	AddressFamilies []model.AddressFamily
}

// DesiredRouter computes a deterministic hex-encoded SHA-256 hash of r.
// Slices are sorted before marshaling so field order does not affect the hash.
func DesiredRouter(r model.DesiredRouter) (string, error) {
	sr := toSortable(r)
	b, err := json.Marshal(sr)
	if err != nil {
		return "", fmt.Errorf("marshal desired router: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func toSortable(r model.DesiredRouter) sortableRouter {
	sr := sortableRouter{
		Namespace: r.Namespace,
		Name:      r.Name,
		LocalASN:  r.LocalASN,
		RouterID:  r.RouterID,
	}

	// Sort address families by AFI+SAFI string.
	sr.AddressFamilies = sortAFs(r.AddressFamilies)

	// Sort peers by Address.
	peers := make([]sortablePeer, len(r.Peers))
	for i, p := range r.Peers {
		peers[i] = sortablePeer{
			Name:            p.Name,
			PeerASN:         p.PeerASN,
			Address:         p.Address,
			AddressFamilies: sortAFs(p.AddressFamilies),
			HoldTime:        int64(p.HoldTime),
			KeepaliveTime:   int64(p.KeepaliveTime),
			AuthPassword:    p.AuthPassword,
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Address < peers[j].Address })
	sr.Peers = peers

	// Sort advertisements by Name.
	advs := make([]sortableAdvertisement, len(r.Advertisements))
	for i, a := range r.Advertisements {
		advs[i] = sortableAdvertisement{
			Name:            a.Name,
			AddressFamily:   a.AddressFamily,
			Prefixes:        sorted(a.Prefixes),
			Communities:     sorted(a.Communities),
			LocalPreference: a.LocalPreference,
			NextHop:         a.NextHop,
		}
	}
	sort.Slice(advs, func(i, j int) bool { return advs[i].Name < advs[j].Name })
	sr.Advertisements = advs

	// Sort policies by Direction+Name.
	policies := make([]sortablePolicy, len(r.Policies))
	for i, p := range r.Policies {
		terms := make([]sortablePolicyTerm, len(p.Terms))
		for j, t := range p.Terms {
			terms[j] = sortablePolicyTerm{
				Sequence: t.Sequence,
				Match: sortablePolicyMatch{
					Any:             t.Match.Any,
					AddressFamilies: sortAFs(t.Match.AddressFamilies),
				},
				Action: t.Action,
				Set:    t.Set,
			}
		}
		sort.Slice(terms, func(a, b int) bool { return terms[a].Sequence < terms[b].Sequence })
		policies[i] = sortablePolicy{
			Name:      p.Name,
			Direction: p.Direction,
			Terms:     terms,
		}
	}
	sort.Slice(policies, func(i, j int) bool {
		di := string(policies[i].Direction) + "/" + policies[i].Name
		dj := string(policies[j].Direction) + "/" + policies[j].Name
		return di < dj
	})
	sr.Policies = policies

	return sr
}

// sortAFs sorts address families by their AFI+SAFI string representation.
func sortAFs(afs []model.AddressFamily) []model.AddressFamily {
	if len(afs) == 0 {
		return afs
	}
	out := make([]model.AddressFamily, len(afs))
	copy(out, afs)
	sort.Slice(out, func(i, j int) bool {
		ki := string(out[i].AFI) + "/" + string(out[i].SAFI)
		kj := string(out[j].AFI) + "/" + string(out[j].SAFI)
		return ki < kj
	})
	return out
}

// sorted returns a sorted copy of s.
func sorted(s []string) []string {
	if len(s) == 0 {
		return s
	}
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}
