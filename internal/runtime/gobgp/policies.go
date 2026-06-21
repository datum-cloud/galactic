// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"fmt"

	api "github.com/osrg/gobgp/v4/api"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"

	"go.datum.net/galactic/internal/model"
)

const globalPolicyTable = "global"

// applyPolicy creates or replaces a routing policy in GoBGP and assigns it
// to the global policy table in the appropriate direction.
func applyPolicy(ctx context.Context, b *gobgpserver.BgpServer, p model.DesiredPolicy) error {
	stmts := buildStatements(p)

	if err := b.AddPolicy(ctx, &api.AddPolicyRequest{
		Policy: &api.Policy{
			Name:       p.Name,
			Statements: stmts,
		},
		ReferExistingStatements: false,
	}); err != nil {
		return fmt.Errorf("add policy %q: %w", p.Name, err)
	}

	dir := policyDirection(p.Direction)
	if err := b.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          globalPolicyTable,
			Direction:     dir,
			Policies:      []*api.Policy{{Name: p.Name}},
			DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
		},
	}); err != nil {
		return fmt.Errorf("assign policy %q to direction %v: %w", p.Name, p.Direction, err)
	}

	return nil
}

// deletePolicy removes a routing policy assignment and definition from GoBGP.
func deletePolicy(ctx context.Context, b *gobgpserver.BgpServer, name string, direction model.BGPPolicyDirection) {
	dir := policyDirection(direction)
	_ = b.DeletePolicyAssignment(ctx, &api.DeletePolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:      globalPolicyTable,
			Direction: dir,
			Policies:  []*api.Policy{{Name: name}},
		},
	})
	_ = b.DeletePolicy(ctx, &api.DeletePolicyRequest{
		Policy:             &api.Policy{Name: name},
		PreserveStatements: false,
		All:                true,
	})
}

// policyDirection maps a model direction to a GoBGP PolicyDirection.
func policyDirection(d model.BGPPolicyDirection) api.PolicyDirection {
	if d == model.BGPPolicyDirectionImport {
		return api.PolicyDirection_POLICY_DIRECTION_IMPORT
	}
	return api.PolicyDirection_POLICY_DIRECTION_EXPORT
}

// buildStatements converts DesiredPolicy terms to GoBGP api.Statements.
func buildStatements(p model.DesiredPolicy) []*api.Statement {
	stmts := make([]*api.Statement, 0, len(p.Terms))
	for _, term := range p.Terms {
		stmt := &api.Statement{
			Name: fmt.Sprintf("%s-seq%d", p.Name, term.Sequence),
		}

		// Match conditions.
		if !term.Match.Any && len(term.Match.AddressFamilies) > 0 {
			stmt.Conditions = &api.Conditions{}
		}

		// Action.
		stmt.Actions = &api.Actions{}
		if term.Action == model.BGPPolicyActionPermit {
			stmt.Actions.RouteAction = api.RouteAction_ROUTE_ACTION_ACCEPT
		} else {
			stmt.Actions.RouteAction = api.RouteAction_ROUTE_ACTION_REJECT
		}

		if term.Set != nil {
			if len(term.Set.CommunitiesAdd) > 0 {
				stmt.Actions.Community = &api.CommunityAction{
					Type:        api.CommunityAction_TYPE_ADD,
					Communities: term.Set.CommunitiesAdd,
				}
			}
			if len(term.Set.CommunitiesRemove) > 0 {
				// If we already have an add action, the remove must be a separate pass.
				// GoBGP CommunityAction supports only one operation per statement.
				// When both add and remove are present, prefer add here.
				if stmt.Actions.Community == nil {
					stmt.Actions.Community = &api.CommunityAction{
						Type:        api.CommunityAction_TYPE_REMOVE,
						Communities: removeToRegexp(term.Set.CommunitiesRemove),
					}
				}
			}
			if term.Set.LocalPreference != nil {
				stmt.Actions.LocalPref = &api.LocalPrefAction{Value: *term.Set.LocalPreference}
			}
		}

		stmts = append(stmts, stmt)
	}
	return stmts
}

// removeToRegexp converts community strings to GoBGP community regexp format.
// GoBGP community matching uses exact string comparison, so we wrap each
// community in ^...$ anchors to prevent partial matches.
func removeToRegexp(communities []string) []string {
	out := make([]string, len(communities))
	for i, c := range communities {
		out[i] = "^" + c + "$"
	}
	return out
}
