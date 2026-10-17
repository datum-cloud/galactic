// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package compile

import (
	"slices"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// FRR's keywords for the community attributes, in its order.
const (
	communityStandard = "standard"
	communityExtended = "extended"
	communityLarge    = "large"
)

// withheldCommunities is the community attributes a restriction to kind
// turns off, in FRR's keyword order.
func withheldCommunities(kind networkv1alpha1.SendCommunityType) []string {
	sent := map[networkv1alpha1.SendCommunityType][]string{
		networkv1alpha1.SendCommunityTypeStandard: {communityStandard},
		networkv1alpha1.SendCommunityTypeExtended: {communityExtended},
		networkv1alpha1.SendCommunityTypeLarge:    {communityLarge},
		networkv1alpha1.SendCommunityTypeBoth:     {communityStandard, communityExtended},
	}[kind]
	var out []string
	for _, k := range []string{communityStandard, communityExtended, communityLarge} {
		if !slices.Contains(sent, k) {
			out = append(out, k)
		}
	}
	return out
}
