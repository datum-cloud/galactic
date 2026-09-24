// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"net"
	"slices"
	"sort"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"
	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
)

// These tests guard issue #599: GoBGP v4.9.0's TableManager.DeleteVrf calls
// deleteRTCPathsByVrf on the RTC table without checking it exists, and GoBGP
// only builds tables for the global family list. Starting GoBGP with an
// explicit list that omitted RTC therefore made every VRF deletion a nil
// dereference inside GoBGP's own goroutine, crashing galactic-router. That
// panic cannot be recovered, so a regression here aborts the test binary
// rather than failing a single test; either way the suite goes red.

const testLoopback = "127.0.0.1"

var (
	afIPv4Unicast = model.AddressFamily{AFI: afiIPv4, SAFI: safiUnicast}
	afIPv6Unicast = model.AddressFamily{AFI: afiIPv6, SAFI: safiUnicast}
	afL2VPNEVPN   = model.AddressFamily{AFI: afiL2VPN, SAFI: safiEVPN}

	// galacticFamilies is the explicit family set BGPRouter CRs carry.
	galacticFamilies = []model.AddressFamily{afIPv4Unicast, afIPv6Unicast, afL2VPNEVPN}
)

// TestGlobalFamilies verifies every explicit family list gains RTC, and an
// empty list stays empty so GoBGP falls back to enabling every family.
func TestGlobalFamilies(t *testing.T) {
	tests := []struct {
		name string
		afs  []model.AddressFamily
		want []uint32
	}{
		{name: "nil stays nil", afs: nil, want: nil},
		{name: "empty stays nil", afs: []model.AddressFamily{}, want: nil},
		{name: "galactic set gains RTC", afs: galacticFamilies, want: []uint32{0, 1, 9, globalFamilyRTC}},
		{name: "EVPN only gains RTC", afs: []model.AddressFamily{afL2VPNEVPN}, want: []uint32{9, globalFamilyRTC}},
		{name: "IPv6 only gains RTC", afs: []model.AddressFamily{afIPv6Unicast}, want: []uint32{1, globalFamilyRTC}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := globalFamilies(tt.afs); !slices.Equal(got, tt.want) {
				t.Errorf("globalFamilies() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGlobalFamilyIntsMatchGoBGP pins the hand-written family integers to
// GoBGP's own table, so a renumbering upstream can't silently turn the RTC
// guard into some other family and bring the #599 crash back.
func TestGlobalFamilyIntsMatchGoBGP(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want oc.AfiSafiType
	}{
		{name: "RTC", got: globalFamilyRTC, want: oc.AFI_SAFI_TYPE_RTC},
		{name: "IPv4 unicast", got: familyToGlobalInt(afIPv4Unicast), want: oc.AFI_SAFI_TYPE_IPV4_UNICAST},
		{name: "IPv6 unicast", got: familyToGlobalInt(afIPv6Unicast), want: oc.AFI_SAFI_TYPE_IPV6_UNICAST},
		{name: "L2VPN EVPN", got: familyToGlobalInt(afL2VPNEVPN), want: oc.AFI_SAFI_TYPE_L2VPN_EVPN},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := oc.IntToAfiSafiTypeMap[int(tt.got)]; got != tt.want {
				t.Errorf("GoBGP family %d = %q, want %q", tt.got, got, tt.want)
			}
		})
	}
}

func testVRF(name string, id int32, rts ...string) model.DesiredVRFInstance {
	return model.DesiredVRFInstance{
		Name:               name,
		VRFID:              id,
		ImportRouteTargets: rts,
		ExportRouteTargets: rts,
	}
}

// markKernelBacked records vrfs as applyVRFs does once it has resolved their
// kernel VRF tables. A test process has no kernel VRFs, so without this
// applyVRFs skips recording them and never reaches DeleteVrf on removal,
// which is exactly the call #599 crashes in.
// newTestRuntime builds a runtime through the production factory with an
// outbound-only listener.
func newTestRuntime(ctx context.Context, t *testing.T) *GoBGPRuntime {
	t.Helper()
	rt, err := NewRuntimeFactory(-1, false, "", nil)(types.NamespacedName{Namespace: "issue-599", Name: testRouterName})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Stop(ctx) })
	return rt.(*GoBGPRuntime)
}

func markKernelBacked(gr *GoBGPRuntime, vrfs []model.DesiredVRFInstance) {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	for _, v := range vrfs {
		gr.appliedVRFs[v.Name] = uint32(1000 + v.VRFID)
		gr.appliedVRFImportRTs[v.Name] = v.ImportRouteTargets
	}
}

func listVRFNames(ctx context.Context, t *testing.T, b *gobgpserver.BgpServer) []string {
	t.Helper()
	var names []string
	if err := b.ListVrf(ctx, &api.ListVrfRequest{}, func(v *api.Vrf) {
		names = append(names, v.Name)
	}); err != nil {
		t.Fatalf("ListVrf() error = %v", err)
	}
	sort.Strings(names)
	return names
}

// TestApplyRemovesVRFsWithoutCrashing drives VRF removal through the real
// Apply path (the one the BGPVRFInstance reconciler, CNI DEL and orphan GC all
// end up in) across each deletion shape GoBGP's RTC cleanup handles
// differently, and checks the server is still alive and holds exactly the
// desired VRFs after every step.
func TestApplyRemovesVRFsWithoutCrashing(t *testing.T) {
	vrfA := testVRF("vrf-a", 1, "65000:100")
	vrfB := testVRF("vrf-b", 2, "65000:200")
	vrfShared := testVRF("vrf-shared", 3, "65000:100")
	vrfMulti := testVRF("vrf-multi", 4, "65000:300", "65000:301")

	tests := []struct {
		name     string
		families []model.AddressFamily
		steps    [][]model.DesiredVRFInstance
	}{
		{
			name:     "last VRF removed",
			families: galacticFamilies,
			steps:    [][]model.DesiredVRFInstance{{vrfA}, nil},
		},
		{
			name:     "one of several VRFs removed",
			families: galacticFamilies,
			steps:    [][]model.DesiredVRFInstance{{vrfA, vrfB}, {vrfB}, nil},
		},
		{
			name:     "VRFs sharing an import RT removed one at a time",
			families: galacticFamilies,
			steps:    [][]model.DesiredVRFInstance{{vrfA, vrfShared}, {vrfShared}, nil},
		},
		{
			name:     "VRF with multiple import RTs removed",
			families: galacticFamilies,
			steps:    [][]model.DesiredVRFInstance{{vrfMulti}, nil},
		},
		{
			name:     "all VRFs removed at once",
			families: galacticFamilies,
			steps:    [][]model.DesiredVRFInstance{{vrfA, vrfB, vrfShared, vrfMulti}, nil},
		},
		{
			name:     "VRF re-added after removal then removed again",
			families: galacticFamilies,
			steps:    [][]model.DesiredVRFInstance{{vrfA}, nil, {vrfA}, nil},
		},
		{
			name:     "EVPN-only router",
			families: []model.AddressFamily{afL2VPNEVPN},
			steps:    [][]model.DesiredVRFInstance{{vrfA, vrfB}, nil},
		},
		{
			name:     "no explicit families",
			families: nil,
			steps:    [][]model.DesiredVRFInstance{{vrfA, vrfB}, nil},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			gr := newTestRuntime(ctx, t)

			for i, vrfs := range tt.steps {
				desired := model.DesiredRouter{
					LocalASN:        65000,
					RouterID:        testRouterID1,
					AddressFamilies: tt.families,
					VRFInstances:    vrfs,
				}
				if err := gr.Apply(ctx, desired); err != nil {
					t.Fatalf("step %d: Apply() error = %v", i, err)
				}
				markKernelBacked(gr, vrfs)

				b := gr.server.bgp.Load()
				if _, err := b.GetBgp(ctx, &api.GetBgpRequest{}); err != nil {
					t.Fatalf("step %d: GetBgp() after Apply error = %v", i, err)
				}
				want := make([]string, 0, len(vrfs))
				for _, v := range vrfs {
					want = append(want, v.Name)
				}
				sort.Strings(want)
				if got := listVRFNames(ctx, t, b); !slices.Equal(got, want) {
					t.Fatalf("step %d: VRFs = %v, want %v", i, got, want)
				}
			}
		})
	}
}

func freeTCPPort(t *testing.T) int32 {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort(testLoopback, "0"))
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer func() { _ = l.Close() }()
	return int32(l.Addr().(*net.TCPAddr).Port)
}

// remotePeer returns the fabric-side view of galactic's session, or nil.
func remotePeer(ctx context.Context, t *testing.T, b *gobgpserver.BgpServer) *api.Peer {
	t.Helper()
	var peer *api.Peer
	if err := b.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) { peer = p }); err != nil {
		t.Fatalf("ListPeer() error = %v", err)
	}
	return peer
}

func isEstablished(p *api.Peer) bool {
	return p != nil && p.State != nil && p.State.SessionState == api.PeerState_SESSION_STATE_ESTABLISHED
}

// TestVRFDeleteKeepsSessionUpAndRTCOffTheWire covers the issue's first
// acceptance criterion end to end: galactic-router peers with a remote
// speaker that would accept RTC, removes the node's last VRF, and the session
// must stay Established. It also checks the fix's no-wire-change claim: the
// extra RTC table is local only, so galactic must never offer RTC to a peer.
func TestVRFDeleteKeepsSessionUpAndRTCOffTheWire(t *testing.T) {
	ctx := context.Background()
	remotePort := freeTCPPort(t)

	remote := gobgpserver.NewBgpServer()
	go remote.Serve()
	t.Cleanup(remote.Stop)
	if err := remote.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn:             65000,
		RouterId:        testRouterID2,
		ListenPort:      remotePort,
		ListenAddresses: []string{testLoopback},
	}}); err != nil {
		t.Fatalf("remote StartBgp() error = %v", err)
	}
	evpn := &api.Family{Afi: api.Family_AFI_L2VPN, Safi: api.Family_SAFI_EVPN}
	rtc := &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_ROUTE_TARGET_CONSTRAINTS}
	if err := remote.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: testLoopback, PeerAsn: 65000},
		Transport: &api.Transport{PassiveMode: true},
		AfiSafis: []*api.AfiSafi{
			{Config: &api.AfiSafiConfig{Family: evpn, Enabled: true}},
			{Config: &api.AfiSafiConfig{Family: rtc, Enabled: true}},
		},
	}}); err != nil {
		t.Fatalf("remote AddPeer() error = %v", err)
	}

	gr := newTestRuntime(ctx, t)

	desired := model.DesiredRouter{
		LocalASN:        65000,
		RouterID:        testRouterID1,
		AddressFamilies: galacticFamilies,
		Peers: []model.DesiredPeer{{
			Name:            "fabric",
			PeerASN:         65000,
			Address:         testLoopback,
			RemotePort:      remotePort,
			AddressFamilies: []model.AddressFamily{afL2VPNEVPN},
		}},
		VRFInstances: []model.DesiredVRFInstance{testVRF("vrf-a", 1, "65000:100")},
	}
	if err := gr.Apply(ctx, desired); err != nil {
		t.Fatalf("Apply() with VRF error = %v", err)
	}
	markKernelBacked(gr, desired.VRFInstances)

	deadline := time.Now().Add(30 * time.Second)
	for !isEstablished(remotePeer(ctx, t, remote)) {
		if time.Now().After(deadline) {
			t.Fatalf("session never reached Established: %v", remotePeer(ctx, t, remote))
		}
		time.Sleep(100 * time.Millisecond)
	}
	upSince := remotePeer(ctx, t, remote).Timers.State.Uptime.AsTime()

	for _, c := range remotePeer(ctx, t, remote).State.RemoteCap {
		if mp := c.GetMultiProtocol(); mp != nil && mp.Family.Safi == api.Family_SAFI_ROUTE_TARGET_CONSTRAINTS {
			t.Fatalf("galactic offered RTC to its peer; the RTC table must stay local-only")
		}
	}

	desired.VRFInstances = nil
	if err := gr.Apply(ctx, desired); err != nil {
		t.Fatalf("Apply() removing VRF error = %v", err)
	}
	if got := listVRFNames(ctx, t, gr.server.bgp.Load()); len(got) != 0 {
		t.Fatalf("VRFs after removal = %v, want none", got)
	}

	// Give a crash or session reset time to surface before checking.
	time.Sleep(2 * time.Second)
	p := remotePeer(ctx, t, remote)
	if !isEstablished(p) {
		t.Fatalf("session dropped after VRF removal: %v", p)
	}
	if got := p.Timers.State.Uptime.AsTime(); !got.Equal(upSince) {
		t.Fatalf("session reset after VRF removal: up since %v, was %v", got, upSince)
	}
}
