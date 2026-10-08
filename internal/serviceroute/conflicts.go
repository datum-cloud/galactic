// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import "k8s.io/apimachinery/pkg/types"

// ConflictingPolicies returns all policies whose consumer attachment and
// frontend tuple overlap a translated policy. Ambiguity rejects every claimant.
func ConflictingPolicies(intents map[types.NamespacedName][]RouteIntent,
	translated map[types.NamespacedName]bool,
) map[types.NamespacedName]bool {
	type tuple struct {
		attachment        types.NamespacedName
		address, protocol string
		port              int32
	}
	owners := map[tuple][]types.NamespacedName{}
	for key, list := range intents {
		for _, in := range list {
			if in.Kind == RouteIntentRemoteProducer {
				continue
			}
			for _, p := range in.Ports {
				address := in.Service.String()
				if in.Frontend != nil {
					address = in.Frontend.String()
				}
				t := tuple{in.Attachment, address, string(p.Protocol), p.Port}
				owners[t] = append(owners[t], key)
			}
		}
	}
	conflicts := map[types.NamespacedName]bool{}
	for _, keys := range owners {
		distinct := map[types.NamespacedName]bool{}
		anyTranslated := false
		for _, k := range keys {
			distinct[k] = true
			anyTranslated = anyTranslated || translated[k]
		}
		if len(distinct) > 1 && anyTranslated {
			for k := range distinct {
				conflicts[k] = true
			}
		}
	}
	return conflicts
}
