// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"log/slog"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"

	"go.datum.net/galactic/internal/plumbing/srv6"
)

// movedVRFTable is a VRF whose kernel table changed while it stayed desired:
// the table its routes were installed in, and the import route targets that
// selected them.
type movedVRFTable struct {
	name      string
	tableID   uint32
	importRTs []string
}

// vrfRouteDelIfSID removes a tenant route only while it still encapsulates
// toward the given SID; a package var so tests can drive it without a pinned
// egress_route_table.
var vrfRouteDelIfSID = srv6.RouteEgressDelIfSID

// withdrawMovedVRFRoutes removes the routes this runtime installed in m's old
// table: those of every remote best path carrying one of m's import route
// targets. Each is removed only while it still encapsulates toward that path's
// SID, so an entry another writer has since put in the table, such as another
// VPC given the same table ID, is kept. Retries pending for the old table are
// dropped.
func (r *GoBGPRuntime) withdrawMovedVRFRoutes(b *gobgpserver.BgpServer, m movedVRFTable) {
	if r.vrf != nil {
		r.vrf.forgetTable(m.tableID)
	}
	rts := make(map[string]struct{}, len(m.importRTs))
	for _, rt := range m.importRTs {
		rts[rt] = struct{}{}
	}
	var withdrawn int
	err := b.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    bgp.RF_EVPN,
	}, func(_ bgp.NLRI, paths []*apiutil.Path) {
		for _, path := range paths {
			if !path.Best || evpnMpReachNexthop(path.Attrs) == r.localAddress || !hasRouteTarget(path.Attrs, rts) {
				continue
			}
			evpnNLRI, ok := path.Nlri.(*bgp.EVPNNLRI)
			if !ok {
				continue
			}
			ipPrefix, ok := evpnNLRI.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
			if !ok {
				continue
			}
			prefix := addrToIPNet(ipPrefix.IPPrefix, int(ipPrefix.IPPrefixLength))
			if err := vrfRouteDelIfSID(prefix, m.tableID, evpnGateway(path.Attrs)); err != nil {
				slog.Error("withdrawMovedVRFRoutes: route delete failed",
					"vrf", m.name, "prefix", prefix, "table", m.tableID, "err", err)
				continue
			}
			withdrawn++
		}
	})
	if err != nil {
		slog.Error("withdrawMovedVRFRoutes: ListPath failed", "vrf", m.name, "err", err)
		return
	}
	slog.Info("withdrawMovedVRFRoutes: removed routes from the VRF's old table",
		"vrf", m.name, "table", m.tableID, "routes", withdrawn)
}

// hasRouteTarget reports whether attrs carry any route target in rts.
func hasRouteTarget(attrs []bgp.PathAttributeInterface, rts map[string]struct{}) bool {
	for _, attr := range attrs {
		ec, ok := attr.(*bgp.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, community := range ec.Value {
			if _, ok := rts[community.String()]; ok {
				return true
			}
		}
	}
	return false
}
