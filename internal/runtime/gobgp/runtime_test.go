// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"testing"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"

	"go.datum.net/galactic/internal/model"
)

// newTestBgpServer starts a bare embedded GoBGP server suitable for exercising
// AddVrf/ListVrf in isolation, with no listening socket and no peers.
func newTestBgpServer(t *testing.T) *gobgpserver.BgpServer {
	t.Helper()
	b := gobgpserver.NewBgpServer()
	go b.Serve()
	t.Cleanup(b.Stop)

	if err := b.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65000,
			RouterId:   "1.2.3.4",
			ListenPort: -1,
		},
	}); err != nil {
		t.Fatalf("StartBgp() error = %v", err)
	}
	return b
}

// TestApplyVRFDerivesRouteDistinguisher verifies applyVRF derives the RFC 4364
// Type 1 route distinguisher as "routerID:vrfID" from the routerID parameter
// and vrf.VRFID, rather than reading a RouteDistinguisher field off the model
// (which no longer exists after the BGPVRFInstanceSpec.VRFID API change).
func TestApplyVRFDerivesRouteDistinguisher(t *testing.T) {
	tests := []struct {
		name     string
		routerID string
		vrf      model.DesiredVRFInstance
		wantRD   string
	}{
		{
			name:     "basic vrfID",
			routerID: "1.2.3.4",
			vrf: model.DesiredVRFInstance{
				Name:               "vrf-a",
				VRFID:              42,
				ImportRouteTargets: []string{"65000:100"},
				ExportRouteTargets: []string{"65000:100"},
			},
			wantRD: "1.2.3.4:42",
		},
		{
			name:     "different routerID and vrfID",
			routerID: "10.0.0.1",
			vrf: model.DesiredVRFInstance{
				Name:               "vrf-b",
				VRFID:              65535,
				ImportRouteTargets: []string{"65000:200"},
				ExportRouteTargets: []string{"65000:200"},
			},
			wantRD: "10.0.0.1:65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBgpServer(t)
			ctx := context.Background()

			vrf := tt.vrf
			if err := applyVRF(ctx, b, &vrf, tt.routerID); err != nil {
				t.Fatalf("applyVRF() error = %v", err)
			}

			var gotRD string
			if err := b.ListVrf(ctx, &api.ListVrfRequest{}, func(v *api.Vrf) {
				if v.Name != tt.vrf.Name {
					return
				}
				rd, err := apiutil.UnmarshalRD(v.Rd)
				if err != nil {
					t.Fatalf("UnmarshalRD() error = %v", err)
				}
				gotRD = rd.String()
			}); err != nil {
				t.Fatalf("ListVrf() error = %v", err)
			}

			if gotRD != tt.wantRD {
				t.Errorf("applyVRF() route distinguisher = %q, want %q", gotRD, tt.wantRD)
			}
		})
	}
}
